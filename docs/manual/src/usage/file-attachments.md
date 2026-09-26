# File attachments

Drop a file into a sandbox terminal to give the agent a path that it can read.
Airlock does not process images in a special way. Agents that detect image
paths, such as Claude Code, attach dropped images as usual.

File drops work with `airlock start`, `--monitor`, and interactive `airlock exec`
sessions. The terminal must send bracketed pastes, which mark the start and end
of pasted text. Pasting absolute file paths has the same effect as dropping files.
This includes files that you copy in a file manager, which pastes one path per
line. Text mixed with paths passes through unchanged.

Airlock copies external files into a read-only share. Files already available
through an existing mount use that mount when possible. Copied files remain
available until the sandbox stops. They do not persist for resumed conversations.

> **Warning:** A pasted absolute host path gives the sandbox a copy of that file.
> Airlock cannot tell a paste from a drop. Do not paste host paths of files that
> the sandbox must not read. An absolute path that exists both in the sandbox and
> on the host also changes to the path of the host copy.

## Limits

You cannot change these limits:

- Up to 16 files per paste.
- Up to 64 KiB of pasted text.

These limits apply to copied files. All sessions of a sandbox run share them:

| Setting      | Default     | Limit                                 |
|--------------|-------------|---------------------------------------|
| `file_size`  | `"32 MiB"`  | Maximum size of one copied file.      |
| `total_size` | `"256 MiB"` | Maximum total size of copies per run. |
| `files`      | `256`       | Maximum number of copies per run.     |

To change them, add a `[terminal.file_drop_limits]` table to
`~/.airlock/settings.toml` on the host:

```toml
[terminal.file_drop_limits]
file_size = "100 MiB"
total_size = "1 GiB"
files = 500
```

Project configuration cannot change these limits. Files that an existing
mount shares do not count against them.

Airlock does not import directories, symlinks, masked files, relative paths,
or `file://` URLs. A symlink in any parent directory also prevents importing.
If an import fails, Airlock forwards the original paste and logs the reason.

Some terminals send a dropped file as typed text, not as a bracketed paste.
Airlock does not import typed text. In these terminals, copy the file in a
file manager and paste it instead.

On WSL, some Windows apps send Windows paths, for example
`'C:\Users\me\shot.png'`. Airlock does not import Windows paths. Use a
terminal that sends WSL paths, such as `/mnt/c/Users/me/shot.png`.

Clipboard image data requires a separate step: save the image to a file,
then drop that file into the terminal.

## Disable file imports

Add this to `~/.airlock/settings.toml` on the host:

```toml
[terminal]
file_drop = false
```

Restart the sandbox to apply the setting. Project configuration cannot enable
file imports when this setting disables them.
