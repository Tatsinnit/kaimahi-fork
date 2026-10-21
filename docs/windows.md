# Windows

::: warning Unreleased
Native Windows work is tracked in [#578](https://github.com/kaimahi-agents/kaimahi/issues/578).
It is a day-0 prerequisite for [#594](https://github.com/kaimahi-agents/kaimahi/issues/594),
not a claim that the plugin, in-process preview runner or local Test/Publish loop
has shipped. The current stable v0.8.1 release does not include a native Windows
binary. Do not expect `@latest` or an older release to contain this work.
:::

## Native execution

The native build is a Windows `.exe`; it does not invoke WSL or require a Unix
shell. Offline authoring and local artifact operations do not require Docker or
a Kubernetes cluster. Operations that explicitly target Kubernetes still require
their documented runtime and access; native Windows does not make those
prerequisites disappear. Legacy AKS script execution remains unavailable on
Windows rather than silently invoking a shell or WSL.

Windows amd64 filesystem and publication tests execute on local NTFS. Windows
arm64 is cross-built and vetted; that is not native arm64 execution evidence.
Pinned kubectl and Helm have Windows assets. The pinned kind release has a
Windows amd64 asset only; Windows arm64 requires an operator-provided kind on
PATH for those later local-cluster workflows. A tool already on PATH wins over
a managed download.

Release asset verification and the distinction between stable and unreleased
builds are documented in [releases](releases.md). The Unix `install.sh` and
Homebrew instructions are not PowerShell installers. Shell-completion generation
currently supports bash, zsh and fish, not PowerShell.

## State and permissions

Native Windows defaults to `%LOCALAPPDATA%\kmx`, not the roaming AppData folder,
HOME, or a WSL home directory. `KMX_HOME` is an explicit override. Choose a new
local path when isolating a run: kmx creates its private root with the current
user as owner and a protected, user-only DACL before writing data. An existing
unsafe root or private file is refused, not repaired, relabeled or adopted.
SYSTEM or Administrators grants do not count as user-only private access.

Use an ordinary, non-elevated session. If a process token defaults new objects
to an Administrators-group owner, third-party private store creation is refused
before it writes anything. kmx does not change the token, enable privileges,
change machine policy or create another account. CI's isolated test-child token
launcher is test infrastructure, not product behavior.

Private state includes tool caches, workspace preparation, passing evidence,
release observations and saved preferences. Exported files created by the native
build may also have user-only ACLs even when their contents are public; copy them
through an explicitly reviewed sharing mechanism if another user needs access.
Unix file modes and Unix locking retain their existing behavior.

## Filesystem boundaries

A loose AgentSuite directory passed directly to `suite validate`, `suite push`
or `suite build` must have a protected, user-only root DACL under the upstream
AgentSuite policy; an ordinary inherited-ACL folder can be refused. kmx does not
repair it. Native workspace preparation uses its own protected staging roots,
so this does not require relabeling a read-only authored workspace.

The native private-storage path is local NTFS. UNC shares, device namespaces,
non-NTFS volumes, alternate data streams, drive-relative paths, reserved device
names and trailing-dot/space names are refused. Reparse points, including
junctions and symlinks, are not followed. OneDrive and other reparse-backed paths
can therefore be refused: keep private state and output in a plain local NTFS
location. An ordinary user's inability to create a symbolic link is not a reason
to enable Developer Mode or grant a privilege merely to run kmx.

Different case, extended-length spellings and available 8.3 aliases refer to the
same physical workspace identity and lock. Windows layout publishers serialize
by their physical parent directory. A stale layout sentinel after a crash still
requires operator inspection; do not remove one while a publisher may be active.
This is not a recovery or adoption protocol.

Private receipt publication writes and flushes a complete file before an
exclusive link, then flushes the directory. Open or flush failures are fatal.
An error after the link can leave a complete visible file and must not be
interpreted as acknowledged durable success. Successful flush API tests are not
power-loss certification or a general backup guarantee.

## Native Windows and WSL must not share writable state

Concurrent native and WSL writes to one physical kmx home, cache or output
layout are unsupported. Windows byte-range locks and Linux `flock` do not form
a cross-kernel exclusion protocol. Use separate physical locations, not two
spellings of the same directory.

On Linux, kmx refuses Windows-drive `drvfs` and recognized Windows-drive `9p`
mounts for state, caches and outputs. The error names the requested path and
recommends a Linux path or native Windows kmx. The check resolves existing
ancestors and recognizes aliases and mounts; it is not a blanket ban on every
`9p` filesystem. Unobserved Windows-drive `virtiofs` mounts are not detected.
Read-only Windows source inputs and tools, such as the documented Azure WSL
`kubelogin.exe`, remain usable. Do not move shared state to a Windows drive to
work around a refusal.

## Qualification limits

Native tests cover ordinary-user NTFS handles, actual ACL refusals, physical
aliases, process lock lifetime and publication ordering/failure behavior. CI
adds a `windows-latest` job for those contracts without WSL, Docker, a cluster
or a model download. Cross-compilation alone is not runtime qualification.
Unix-specific signal, FIFO and permission fixtures are not Windows evidence;
Windows tests exercise the corresponding native boundaries explicitly.

Current-user or administrator tampering with private paths, remapping drive
letters, and host-wide compromise are outside the unprivileged filesystem
threat model. Windows cannot replace an executable image while it is running:
an identical verified managed alias is reused; replacing a different running
pin fails rather than executing unchecked bytes. A failed temporary patch-input
cleanup can report an uncertain result after the Kubernetes API call; it never
automatically resends the write.
