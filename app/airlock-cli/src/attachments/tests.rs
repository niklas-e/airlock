use std::os::unix::fs::{MetadataExt, symlink};

use smart_config::ByteSize;

use super::*;

pub(super) fn fixture() -> (tempfile::TempDir, Imports) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dev/tmp");
    std::fs::create_dir_all(&root).unwrap();
    // The default `.tmp` prefix would make every fixture path hidden.
    let dir = tempfile::Builder::new()
        .prefix("attachments-")
        .tempdir_in(root.canonicalize().unwrap())
        .unwrap();
    let limits = FileDropLimits {
        file_size: ByteSize(1 << 20),
        total_size: ByteSize(4 << 20),
        files: 16,
    };
    let imports = Imports::create(dir.path(), Rules::default(), limits).unwrap();
    (dir, imports)
}

pub(super) fn put(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}

pub(super) fn imported_path(imports: &Imports, guest: &str) -> PathBuf {
    imports.0.lock().share.join(
        guest
            .strip_prefix(GUEST_ROOT)
            .unwrap()
            .trim_start_matches('/'),
    )
}

#[test]
fn copies_are_independent_readable_and_cleaned_up() {
    let (dir, imports) = fixture();
    let source = put(dir.path(), "Screenshot 猫 2026.png", b"image contents");
    let guest = imports.import(std::slice::from_ref(&source)).unwrap();
    let copy = imported_path(&imports, &guest);
    assert_eq!(Path::new(&guest).extension().unwrap(), "png");
    assert!(!guest.contains(' '));
    assert_eq!(std::fs::read(&copy).unwrap(), b"image contents");
    assert_ne!(
        std::fs::metadata(&copy).unwrap().ino(),
        std::fs::metadata(&source).unwrap().ino()
    );
    assert_eq!(
        std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o444
    );
    std::fs::write(&source, b"changed").unwrap();
    assert_eq!(std::fs::read(&copy).unwrap(), b"image contents");
    let clone = imports.clone();
    imports.close();
    assert!(!copy.exists());
    assert!(clone.import(&[source]).is_err());
}

#[test]
fn refuses_symlinks_including_ancestor_redirection_and_special_files() {
    let (dir, imports) = fixture();
    let source = put(dir.path(), "secret.png", b"secret");
    let link = dir.path().join("link.png");
    symlink(&source, &link).unwrap();
    let ancestor = dir.path().join("redirect");
    symlink(dir.path(), &ancestor).unwrap();
    let fifo = dir.path().join("pipe.png");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for path in [
        link,
        ancestor.join("secret.png"),
        fifo,
        dir.path().to_path_buf(),
        PathBuf::from("/dev/null"),
    ] {
        assert!(
            imports
                .import(&[path.to_string_lossy().into_owned()])
                .is_err(),
            "{}",
            path.display()
        );
    }
    assert_eq!(
        std::fs::read_dir(&imports.0.lock().share).unwrap().count(),
        0
    );
}

#[test]
fn failed_batches_publish_nothing_and_do_not_consume_quota() {
    let (dir, imports) = fixture();
    let first = put(dir.path(), "first.png", b"ok");
    let large = put(dir.path(), "large.png", b"");
    File::options()
        .write(true)
        .open(&large)
        .unwrap()
        .set_len((1 << 20) + 1)
        .unwrap();
    let err = imports.import(&[first.clone(), large]).unwrap_err();
    assert!(err.to_string().contains("1 MiB"), "{err:#}");
    imports.0.lock().limits.total_size = ByteSize(8);
    let second = put(dir.path(), "second.png", b"too big");
    assert!(imports.import(&[first.clone(), second]).is_err());
    // procfs reports size 0 but has content, which fails the copy phase.
    #[cfg(target_os = "linux")]
    {
        let status = format!("/proc/{}/status", std::process::id());
        let err = imports.import(&[first, status]).unwrap_err();
        assert!(err.to_string().contains("changed while copying"), "{err:#}");
    }
    let store = imports.0.lock();
    assert_eq!((store.bytes, store.files), (0, 0));
    assert_eq!(std::fs::read_dir(&store.share).unwrap().count(), 0);
    assert_eq!(
        std::fs::read_dir(store.session.as_ref().unwrap().path())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn maps_shared_paths_but_respects_masks_and_overlapping_mounts() {
    let (dir, imports) = fixture();
    let source = put(dir.path(), "image.png", b"image");
    imports.0.lock().rules.mappings.push(Mapping {
        source: dir.path().to_owned(),
        target: "/workspace".into(),
        dir: true,
    });
    assert_eq!(
        imports.import(std::slice::from_ref(&source)).unwrap(),
        "/workspace/image.png"
    );
    assert_eq!(imports.0.lock().files, 0);
    imports.0.lock().rules.blocked.push(PathBuf::from(&source));
    assert!(imports.import(std::slice::from_ref(&source)).is_err());
    imports.0.lock().rules.blocked.clear();
    imports
        .0
        .lock()
        .rules
        .hidden
        .push("/workspace/image.png".into());
    assert!(imports.import(std::slice::from_ref(&source)).is_err());
    imports.0.lock().rules.hidden.clear();
    imports.0.lock().rules.shadowed.push("/workspace".into());
    assert!(imports.import(&[source]).unwrap().starts_with(GUEST_ROOT));
}

#[test]
fn nested_mounts_map_to_the_most_specific_target() {
    let (dir, imports) = fixture();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let outer = put(dir.path(), "outer.png", b"outer");
    let inner = put(&dir.path().join("sub"), "inner.png", b"inner");
    for (source, target) in [
        (dir.path().to_owned(), "/workspace"),
        (dir.path().join("sub"), "/workspace/sub"),
    ] {
        imports.0.lock().rules.mappings.push(Mapping {
            source,
            target: target.into(),
            dir: true,
        });
    }
    assert_eq!(imports.import(&[outer]).unwrap(), "/workspace/outer.png");
    assert_eq!(
        imports.import(&[inner]).unwrap(),
        "/workspace/sub/inner.png"
    );
    imports.0.lock().rules.mappings[1].source = dir.path().join("elsewhere");
    let shadowed = put(&dir.path().join("sub"), "shadowed.png", b"shadowed");
    assert!(imports.import(&[shadowed]).unwrap().starts_with(GUEST_ROOT));
}

#[test]
fn hidden_paths_are_mapped_but_never_copied() {
    let (dir, imports) = fixture();
    std::fs::create_dir(dir.path().join(".ssh")).unwrap();
    let key = put(&dir.path().join(".ssh"), "id_ed25519", b"secret");
    let dotfile = put(dir.path(), ".env", b"secret");
    for path in [&key, &dotfile] {
        assert!(
            imports.import(std::slice::from_ref(path)).is_err(),
            "{path}"
        );
    }
    assert_eq!(imports.0.lock().files, 0);
    imports.0.lock().rules.mappings.push(Mapping {
        source: dir.path().to_owned(),
        target: "/workspace".into(),
        dir: true,
    });
    assert_eq!(imports.import(&[dotfile]).unwrap(), "/workspace/.env");
}

#[test]
fn duplicate_names_and_repeated_drops_never_overwrite() {
    let (dir, imports) = fixture();
    let source = put(dir.path(), "image.png", b"first");
    let a = imports.import(&[source.clone(), source.clone()]).unwrap();
    let paths: Vec<_> = a.split(' ').collect();
    assert_ne!(paths[0], paths[1]);
    std::fs::write(&source, b"second").unwrap();
    let b = imports.import(&[source]).unwrap();
    assert_ne!(paths[0], b);
    assert_eq!(
        std::fs::read(imported_path(&imports, paths[0])).unwrap(),
        b"first"
    );
    assert_eq!(
        std::fs::read(imported_path(&imports, &b)).unwrap(),
        b"second"
    );
}

#[tokio::test]
async fn invalid_input_and_failed_imports_pass_through_unchanged() {
    let (_dir, imports) = fixture();
    for bytes in [
        b"Describe /etc/passwd".as_slice(),
        b"/does-not-exist.png",
        b"/does-not-exist.png is broken",
        b"/does-not-exist\\",
        b"\xff",
    ] {
        assert_eq!(imports.rewrite(bytes.to_vec()).await, bytes);
    }
}

#[tokio::test]
async fn concurrent_sessions_share_the_file_count_limit() {
    let (dir, imports) = fixture();
    let a = put(dir.path(), "a.png", b"a").into_bytes();
    let b = put(dir.path(), "b.png", b"b").into_bytes();
    imports.0.lock().files = 15;
    let (out_a, out_b) = tokio::join!(imports.rewrite(a.clone()), imports.rewrite(b.clone()));
    assert_ne!(out_a == a, out_b == b, "exactly one import must fit");
    assert_eq!(imports.0.lock().files, 16);
    assert_eq!(imports.0.lock().bytes, 1);
}

#[test]
fn parent_traversal_cannot_bypass_mask_checks() {
    let (dir, imports) = fixture();
    let secret = put(dir.path(), "secret.png", b"secret");
    imports.0.lock().rules.blocked.push(secret.into());
    let traversal = format!("{}/child/../secret.png", dir.path().display());
    assert!(imports.import(&[traversal]).is_err());
    assert_eq!(imports.0.lock().files, 0);
}

#[test]
fn storage_rejects_writable_aliases_and_overlays_before_boot() {
    let (dir, _imports) = fixture();
    let parent = dir.path().join("cache/imports");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::create_dir(dir.path().join("project")).unwrap();
    symlink(dir.path().join("cache"), dir.path().join("alias")).unwrap();
    let mut mount = ResolvedMount {
        mount_type: MountType::Dir {
            key: "project".into(),
        },
        source: dir.path().join("project"),
        target: "/workspace".into(),
        read_only: false,
    };
    assert!(validate_storage(&parent, std::slice::from_ref(&mount), &[]).is_ok());
    for source in [dir.path().to_owned(), dir.path().join("alias")] {
        mount.source = source;
        assert!(validate_storage(&parent, std::slice::from_ref(&mount), &[]).is_err());
    }
    mount.read_only = true;
    assert!(validate_storage(&parent, std::slice::from_ref(&mount), &[]).is_ok());
    mount.target = GUEST_ROOT.into();
    assert!(validate_storage(&parent, std::slice::from_ref(&mount), &[]).is_err());
    mount.target = "/airlock".into();
    mount.mount_type = MountType::File {
        mount_key: "file".into(),
    };
    assert!(validate_storage(&parent, &[mount], &[]).is_err());
    for target in ["/airlock", GUEST_ROOT, "/airlock/imports/child"] {
        assert!(validate_storage(&parent, &[], &[target.into()]).is_err());
    }
}

#[test]
fn masks_match_by_identity_not_by_spelling() {
    let (dir, imports) = fixture();
    std::fs::create_dir(dir.path().join("masked")).unwrap();
    let secret = put(&dir.path().join("masked"), "secret.png", b"secret");
    symlink(dir.path().join("masked"), dir.path().join("alias")).unwrap();
    imports
        .0
        .lock()
        .rules
        .blocked
        .push(dir.path().join("alias"));
    assert!(imports.import(&[secret]).is_err());
    assert_eq!(imports.0.lock().files, 0);
}

#[test]
fn crash_cleanup_does_not_follow_stale_symlinks() {
    let (dir, _imports) = fixture();
    let victim = dir.path().join("outside");
    std::fs::create_dir(&victim).unwrap();
    let secret = put(&victim, "keep", b"untouched");
    let bucket = dir.path().join("bucket");
    std::fs::create_dir_all(bucket.join("old-run")).unwrap();
    put(&bucket.join("old-run"), "snapshot", b"stale");
    symlink(&victim, bucket.join("stale-link")).unwrap();
    clean_bucket(&bucket).unwrap();
    assert_eq!(std::fs::read_dir(&bucket).unwrap().count(), 0);
    assert_eq!(std::fs::read(&secret).unwrap(), b"untouched");
    let redirected = dir.path().join("redirected-bucket");
    symlink(&victim, &redirected).unwrap();
    assert!(clean_bucket(&redirected).is_err());
    assert_eq!(std::fs::read(&secret).unwrap(), b"untouched");
}
