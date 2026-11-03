# Windows WFP integration

Run only in an elevated, disposable GitHub-hosted Windows job with no user
secrets or persisted checkout credentials. Use a complete x64 application build
from the revision under test and initialize the x64 MSVC developer environment.
The job must own its VM and use a bounded timeout. The environment checks are
guardrails, not proof that a VM is disposable or free of secrets.

```powershell
pwsh -NoProfile -File tests/windows_integration/run.ps1 -SimplewallExe path\to\simplewall.exe
```

The executable is copied to a new directory under `RUNNER_TEMP`, next to a new
`simplewall.ini` and synthetic `profile.xml`; no user's profile is read. The
profile uses `root type="3" version="6"` and app paths containing a temporary
`%SIMPLEWALL_INTEGRATION_ROOT%` variable. The runner creates the fixture files
and the variable. Names, directories and rule names are synthetic.

The script starts the complete application executable in its command-line
`-install -temp -silent -portable` mode, then enumerates its actual WFP provider,
sublayer, callouts and filters. It checks that a name-and-directory rule has
only permit filters containing the expected app ID, that a name-only rule does
likewise, and that wrong-directory and missing-name rules have no filters. It
rewrites the profile and invokes the application again to check disabling,
reenabling and deleting the first rule. A positive assertion also proves that
the version-6 profile and expanded application path were loaded sufficiently
to produce the expected app ID. The test does not exercise the graphical editor
or a live rule toggle: these are profile reload and full-filter rebuild checks.

For traffic checks, a local listener binds an exclusive random IPv4 loopback
port. Copies of a small TCP fixture supply distinct executable identities. The
test first confirms each can connect without the test block. A separate helper
then opens a dynamic WFP session and adds a block in simplewall's sublayer at
`ALE_AUTH_CONNECT_V4`. It matches local and remote `127.0.0.1`, TCP, and the
listener's remote port. It has weight range `0x0a`, between the application's
user-rule permit `0x0b` and default permit `0x08`. It has no provider and no
persistent or boot-time flag. The script independently checks the filter's
actual conditions and weight, then checks the matching client can connect,
the wrong-directory and unmatched clients get `WSAEACCES`, and the matching
client is blocked after disabling or deleting the rule. Reenabling restores its
connection. After closing the dynamic session, the script checks the filter key
is absent and confirms all clients connect again. Fresh sockets are used for
every attempt; a refusal, timeout, unexpected error, or missing listener accept
fails rather than counting as a block.

The app's secure ACL explicitly denies `FWPM_ACTRL_WRITE`, `DELETE`,
`WRITE_DAC`, and `WRITE_OWNER`, but not `FWPM_ACTRL_ADD_LINK`. That does not
establish effective access: the helper reports the actual `FwpmFilterAdd0`
error and fails if the VM policy or inherited grants prevent the operation.
The ordering follows Microsoft's [filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
and [weight assignment](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment)
documentation; [filter creation](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0)
requires access to the filter container, layer and sublayer.

Before starting the application, the test rejects an existing simplewall process
or WFP provider, sublayer, callout or provider filter. It configures default
inbound and outbound policy to permit, disables stealth and boot-time filtering,
disables bundled rules and checks anonymous HTTPS access to github.com before
and after each rebuild. Its post-install inventory rejects non-permit filters,
callouts, and persistent or boot-time objects. This is a detection mechanism,
not an atomic safety barrier: a broken build or configuration parser could
affect connectivity before enumeration. A successful GitHub request also does
not establish connectivity to every Actions service. Only run the tested build
on a fresh disposable VM, without secrets.

Cleanup uses the application's `-uninstall -silent -portable` command and
requires a zero exit code. It independently inventories the provider, sublayer,
callouts and filters, and fails if removal cannot be established.
Cleanup is attempted in `finally` after a timeout or assertion failure too.
If the runner or job is forcibly terminated, `finally` may not execute; `-temp`
objects are static rather than tied to a dynamic WFP session, so they can remain
until removed or the VM is discarded. The application can also touch WFP engine
security or net-event options; this test does not snapshot or restore them.
Cleanup failures must be inspected in the job log.

Publisher matching, first-block discovery, graphical editing, runtime exclusion,
and the behavior of an abruptly terminated runner are not covered. The dynamic
block is removed by BFE when the helper session closes, including helper death;
the script additionally checks its specific filter key before app uninstall.

Consult the corresponding GitHub Actions run for the tested revision and result.
