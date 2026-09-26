# Terminal file attachments

Issue: https://github.com/milankinen/airlock/issues/16

## Problem

Terminal file drops insert host paths that the sandbox cannot read. Copy
external files into a read-only VirtioFS share and replace those paths before
forwarding the paste. The agent sees an ordinary path and detects images
itself.

## Implementation

The stdin filter handles raw, monitor, and exec sessions. It buffers complete
bracketed pastes up to 64 KiB and parses lists of up to 16 absolute paths.
Other input passes through unchanged. Partial markers and incomplete pastes
time out. The timeout keeps the source read pending, because cancelling it
could lose input that the source already consumed.

Each sandbox has a private directory under `~/.cache/airlock/imports`.
Copies are staged outside the exported subtree, then a rename publishes the
batch at `/airlock/imports`. All sessions share the store and its quotas.

The copy limits bound host disk use: copies stay in the cache until the
sandbox stops. The defaults are 32 MiB per file, 256 MiB per run, and 256
copied files. `[terminal.file_drop_limits]` in `~/.airlock/settings.toml`
changes them. Project configuration cannot, because a project must not raise
what the guest can pull from the host. The 64 KiB paste buffer and the
16-path cap stay fixed. They bound memory and the time that input waits for
path checks, and users have no reason to change them.

Source paths are opened component by component with `O_NOFOLLOW` to reject
symlink redirection through guest-writable directories. `O_NONBLOCK` prevents
FIFOs from blocking before the regular-file check. The open descriptor is
used for the copy. Size and modification time checks detect concurrent edits.

Existing mounts supply guest paths when no mask, cache, or other mount hides
them. Conflicts with the import share or writable aliases to its storage
disable imports. The user can also disable them with `[terminal] file_drop =
false` in `~/.airlock/settings.toml`; project configuration cannot override it.

Shutdown closes the store even when RPC tasks retain clones. After a crash,
the next start removes stale copies while holding the project's lock.

## Hidden paths

A paste of a host path imports the file, and the guest can put text on the
host clipboard with OSC 52 or ask the user for a path. Copies therefore skip
any path with a dot-prefixed component. This covers `~/.ssh`, `~/.aws`,
`~/.airlock` (including a plain-text file vault), `~/.cache/airlock`, and the
`.airlock` directories of other projects. Mapped paths keep working, because
the guest can already read them through the mount.

## File identity checks

Text comparison of paths misses aliases. On a case-insensitive macOS volume,
`proj/Secrets` is the masked `proj/secrets`, and a symlinked mask path names
another directory. The component-wise open records the device and inode of every
directory on the way. A mask or a writable mount source blocks the path when
its identity is among them. The text comparison stays for masked paths that do
not exist yet.

## Terminal replies

The guest writes to the terminal, and the terminal answers some queries on
stdin. Some terminals echo guest-controlled text in these answers, for example
in a window title report. Before file drops, such an echo only reached the
guest itself. Now a paste marker inside it could import a host file. The
decoder therefore tracks OSC, DCS, APC, PM, and SOS strings and ignores paste
markers inside them. A string ends at BEL, ST, CAN, or SUB. A key such as
Alt+] also starts a string, so the idle timeout ends an unterminated string.

## Locking

The store lock covers path checks, quota reservation, and the final rename,
but not the copy. A copy can take up to 256 MiB of I/O, and shutdown closes
the store from the async runtime, so it must not wait for a copy. The
reservation uses the file sizes from before the copy. The copy must match
them exactly, so the reservation is also the final use. A failed copy
releases the reservation. A copy that ends after shutdown finds the store
closed and publishes nothing.

## Known limitations

Terminals send drops and pastes the same way. A pasted absolute host path
therefore imports that file, and a path that exists both in the guest and on
the host changes to the path of the host copy. A lone Esc key waits up to
50 ms before it reaches the guest, because it can start a paste marker.

File managers copy unquoted paths, one per line, and terminals send the line
breaks of a paste as CR. The parser therefore falls back to one literal path
per line (CR, LF, or CRLF) when the shell-style parse fails. A pasted
sentence that starts with `/` then becomes a candidate file name, fails to
open, and passes through unchanged.

The VS Code terminal sends drops without bracketed-paste markers, even when
the guest enabled them. The raw terminal receives the quoted path as one
chunk, and the monitor receives one key event per character. A heuristic that
treats a large chunk as a paste would cover only raw mode and could misfire,
so the manual documents the limitation instead. Pasting a copied file works
in VS Code.

VS Code's own source confirms this: its drop handler calls `sendPath` without
forcing bracketed paste, so the behavior is by design on every platform.

On WSL, the VS Code terminal drops Windows paths such as
`'C:\Users\me\shot.png'`, and Airlock forwards them unchanged. Other
terminals, for example Orca, drop WSL paths, and those imports work. A
`wslpath` conversion was prototyped and dropped: no other Airlock feature has
WSL-specific code, and the behavior comes from the editor.

## Tests

Unit tests cover paste framing, shell quoting, passthrough, symlinks, masks,
mount mapping, quotas, batch rollback, cleanup, and stdin RPC ordering. VM
tests drop a file through raw, monitor, and exec terminals. Manual testing
covered image drops on WSL, including Orca, and drops and file pastes in the
Linux Mint terminal and VS Code, in raw and monitor mode. macOS is untested.
