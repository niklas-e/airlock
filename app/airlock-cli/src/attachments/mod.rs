//! Read-only imports for files dropped into sandbox terminals.

mod paste;
mod stdin;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
pub use stdin::wrap;

use crate::project::Project;
use crate::settings::FileDropLimits;
use crate::vm::mount::{MountType, ResolvedMount};

pub const GUEST_ROOT: &str = "/airlock/imports";

#[derive(Clone)]
pub struct Imports(Arc<Mutex<Store>>);

struct Store {
    session: Option<tempfile::TempDir>,
    share: PathBuf,
    rules: Rules,
    limits: FileDropLimits,
    bytes: u64,
    files: usize,
}

#[derive(Default)]
struct Rules {
    /// Host paths that the guest must not read.
    blocked: Vec<PathBuf>,
    /// Guest paths that masks hide.
    hidden: Vec<PathBuf>,
    /// Guest paths that cache overlays replace.
    shadowed: Vec<PathBuf>,
    mappings: Vec<Mapping>,
}

struct Mapping {
    source: PathBuf,
    target: PathBuf,
    dir: bool,
}

impl Mapping {
    fn guest_path(&self, host: &Path) -> Option<PathBuf> {
        if host == self.source {
            Some(self.target.clone())
        } else if self.dir {
            host.strip_prefix(&self.source)
                .ok()
                .map(|p| self.target.join(p))
        } else {
            None
        }
    }
}

impl Imports {
    /// Requires the project's exclusive lock and must run before VM startup.
    pub fn prepare(
        project: &Project,
        mounts: &mut Vec<ResolvedMount>,
        caches: &[crate::vm::disk::CacheEntry],
        limits: FileDropLimits,
    ) -> anyhow::Result<Self> {
        let key = hex::encode(Sha256::digest(project.sandbox_dir.as_os_str().as_bytes()));
        let parent = crate::cache::cache_dir()?.join("imports").join(key);
        let mut rules = Rules {
            blocked: vec![project.cache_dir.clone()],
            hidden: vec![project.guest_cwd.join(".airlock")],
            shadowed: caches
                .iter()
                .filter(|(_, enabled, _)| *enabled)
                .flat_map(|(_, _, paths)| paths.iter().map(PathBuf::from))
                .collect(),
            mappings: mounts
                .iter()
                .map(|m| Mapping {
                    source: m.source.clone(),
                    target: PathBuf::from(&m.target),
                    dir: matches!(m.mount_type, MountType::Dir { .. }),
                })
                .collect(),
        };
        for mask in project.config.mask.values().filter(|m| m.enabled) {
            rules
                .blocked
                .extend(mask.paths.iter().map(|p| project.host_cwd.join(p)));
            rules
                .hidden
                .extend(mask.paths.iter().map(|p| project.guest_cwd.join(p)));
        }
        let overlays: Vec<_> = rules
            .shadowed
            .iter()
            .chain(&rules.hidden)
            .cloned()
            .collect();
        validate_storage(&parent, mounts, &overlays)?;
        clean_bucket(&parent)?;
        let imports = Self::create(&parent, rules, limits)?;
        let share = imports.0.lock().share.clone();
        mounts.push(ResolvedMount {
            mount_type: MountType::Dir {
                key: "imports".into(),
            },
            source: share,
            target: GUEST_ROOT.into(),
            read_only: true,
        });
        Ok(imports)
    }

    fn create(parent: &Path, rules: Rules, limits: FileDropLimits) -> anyhow::Result<Self> {
        let session = tempfile::Builder::new().prefix("run-").tempdir_in(parent)?;
        let share = session.path().join("files");
        std::fs::create_dir(&share)?;
        // Non-root guest users need to traverse the share; its parent stays private.
        std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755))?;
        Ok(Self(Arc::new(Mutex::new(Store {
            session: Some(session),
            share,
            rules,
            limits,
            bytes: 0,
            files: 0,
        }))))
    }

    async fn rewrite(&self, bytes: Vec<u8>) -> Vec<u8> {
        let Some(paths) = paste::paths(&bytes) else {
            return bytes;
        };
        let imports = self.clone();
        match tokio::task::spawn_blocking(move || imports.0.lock().import(&paths)).await {
            Ok(Ok(rewritten)) => rewritten.into_bytes(),
            Ok(Err(err)) => {
                tracing::warn!("file attachment not imported; forwarding original paste: {err:#}");
                bytes
            }
            Err(err) => {
                tracing::warn!("file attachment task failed; forwarding original paste: {err}");
                bytes
            }
        }
    }

    /// Revoke imports even while RPC tasks retain clones.
    pub fn close(&self) {
        if let Some(session) = self.0.lock().session.take()
            && let Err(err) = session.close()
        {
            tracing::warn!("attachment cleanup failed (will retry at next sandbox start): {err}");
        }
    }
}

/// `overlays` are guest paths that masks and caches cover after guest init
/// mounts the directory shares.
fn validate_storage(
    parent: &Path,
    mounts: &[ResolvedMount],
    overlays: &[PathBuf],
) -> anyhow::Result<()> {
    for mount in mounts {
        // A second, writable alias defeats read-only VirtioFS enforcement.
        let directory = matches!(mount.mount_type, MountType::Dir { .. });
        if !mount.read_only && directory && parent.starts_with(&mount.source) {
            bail!(
                "attachment storage overlaps writable mount {}",
                mount.source.display()
            );
        }
        if Path::new(&mount.target).starts_with(GUEST_ROOT)
            || (!directory && Path::new(GUEST_ROOT).starts_with(&mount.target))
        {
            bail!(
                "mount target {} conflicts with attachment storage",
                mount.target
            );
        }
    }
    for target in overlays {
        if Path::new(GUEST_ROOT).starts_with(target) || target.starts_with(GUEST_ROOT) {
            bail!(
                "overlay target {} conflicts with attachment storage",
                target.display()
            );
        }
    }
    Ok(())
}

fn clean_bucket(parent: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(parent)?;
    // Reject redirected ancestors before removing data from an earlier run.
    let _parent_fd = open_path(parent, true)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    // The project's exclusive lock guarantees that these aren't live snapshots.
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

impl Store {
    fn import(&mut self, paths: &[String]) -> anyhow::Result<String> {
        let session = self
            .session
            .as_ref()
            .context("sandbox attachment storage is closed")?;
        let mut sources = Vec::new();
        let mut outputs = Vec::new();
        for text in paths {
            let path = Path::new(text);
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                bail!("parent traversal is not a dropped file path");
            }
            if self
                .rules
                .blocked
                .iter()
                .any(|blocked| path.starts_with(blocked))
            {
                bail!("path is masked from the sandbox");
            }
            let file =
                open_path(path, false).context("open dropped file without following symlinks")?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                bail!("only regular files can be attached");
            }

            let rules = &self.rules;
            let candidates: Vec<_> = rules
                .mappings
                .iter()
                .filter_map(|m| m.guest_path(path).map(|target| (m, target)))
                .collect();
            if candidates
                .iter()
                .any(|(_, target)| rules.hidden.iter().any(|h| target.starts_with(h)))
            {
                bail!("mapped path is masked from the sandbox");
            }
            // A cache overlay or a nested mount shows other content at the
            // mapped guest path, so such files need a copy.
            let mapped = candidates.into_iter().find_map(|(mapping, target)| {
                let shadowed = rules.shadowed.iter().any(|p| target.starts_with(p));
                let nested = rules.mappings.iter().any(|other| {
                    !std::ptr::eq(other, mapping)
                        && other.target.starts_with(&mapping.target)
                        && target.starts_with(&other.target)
                });
                (!shadowed && !nested).then_some(target)
            });
            if let Some(mapped) = mapped {
                outputs.push(Some(quote_path(&mapped.to_string_lossy())));
                sources.push(None);
            } else {
                if metadata.len() > self.limits.file_size.0 {
                    bail!(
                        "file exceeds the {} attachment limit",
                        self.limits.file_size
                    );
                }
                outputs.push(None);
                sources.push(Some((file, metadata, safe_name(path))));
            }
        }
        let count = sources.iter().filter(|f| f.is_some()).count();
        if self.files + count > self.limits.files {
            bail!("attachment file-count limit reached");
        }
        if count == 0 {
            return Ok(outputs.into_iter().flatten().collect::<Vec<_>>().join(" "));
        }

        // Keep incomplete batches outside the share until the final rename.
        let batch = tempfile::Builder::new()
            .prefix("batch-")
            .tempdir_in(session.path())?;
        let id = hex::encode(rand::random::<[u8; 16]>());
        let mut total = 0;
        for (index, source) in sources.into_iter().enumerate() {
            let Some((mut input, before, name)) = source else {
                continue;
            };
            let name = format!("{index}-{name}");
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(batch.path().join(&name))?;
            let allowance = (self.limits.file_size.0)
                .min(self.limits.total_size.0.saturating_sub(self.bytes + total));
            let copied = std::io::copy(&mut (&mut input).take(allowance + 1), &mut output)?;
            if copied > allowance {
                bail!("attachment size limit reached");
            }
            let after = input.metadata()?;
            if copied != before.len()
                || after.len() != before.len()
                || after.modified()? != before.modified()?
            {
                bail!("dropped file changed while copying; drop it again");
            }
            output.flush()?;
            output.set_permissions(std::fs::Permissions::from_mode(0o444))?;
            total += copied;
            outputs[index] = Some(format!("{GUEST_ROOT}/{id}/{name}"));
        }
        std::fs::set_permissions(batch.path(), std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(batch.path(), self.share.join(&id))?;
        self.bytes += total;
        self.files += count;
        Ok(outputs.into_iter().flatten().collect::<Vec<_>>().join(" "))
    }
}

fn safe_name(path: &Path) -> String {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.len() <= 160 {
        clean
    } else {
        // Keep the extension for the agent's file-type detection.
        clean[clean.len() - 160..].to_owned()
    }
}

fn quote_path(path: &str) -> String {
    if path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}

/// O_NOFOLLOW must cover ancestors too: the guest can replace writable directories.
fn open_path(path: &Path, directory: bool) -> std::io::Result<File> {
    if !path.is_absolute() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let mut file = File::open("/")?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(std::io::ErrorKind::InvalidInput.into());
        };
        let name = std::ffi::CString::new(name.as_bytes())?;
        let is_dir = directory || index + 1 < components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if is_dir { libc::O_DIRECTORY } else { 0 };
        // SAFETY: directory FD and NUL-terminated basename stay alive during openat.
        let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a new, owned descriptor.
        file = unsafe { File::from_raw_fd(fd) };
    }
    Ok(file)
}

#[cfg(test)]
mod tests;
