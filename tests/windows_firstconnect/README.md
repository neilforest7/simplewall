# First-block automatic discovery

Run only in an elevated, disposable GitHub-hosted Windows Actions VM with an
interactive desktop, an x64 MSVC environment and a complete application build.
The workflow uses a bounded job and step timeout and does not persist checkout
credentials. Environment-variable checks are guardrails, not proof that a host
is disposable or free of credentials.

The test creates a portable application directory and an isolated XML profile
under `RUNNER_TEMP`. It temporarily enables Simplewall's real default outbound
block, disables the loopback exemption and boot-time filters, and keeps the
internal profile enabled. The profile allows the Actions worker and current
shell to preserve job connectivity; this is not a guarantee that every Actions
service remains reachable. All network probes use a local IPv4 TCP listener.

The initial profile contains one enabled filename-and-directory automatic rule
for an executable that has not run and is absent from the application list.
Before the probe, the WFP inventory must find no filter for that application.
After a temporary CLI install, the actual GUI reloads the profile and rebuilds
the filters. A changed default-filter ID proves the new inventory came from
that GUI rebuild. An enabled `System rule\DNS` permit for `svchost.exe`, UDP
and destination port 53 confirms that the embedded internal profile was loaded
and produced a rule; missing or invalid resources fail the test. No external
`profile_internal.xml` is copied into the portable profile directory.

A separate read-only WFP subscription starts before the client. The first
connection must return `WSAEACCES`, and its classify-drop event must identify
Simplewall's default outbound-block filter. The test waits for the running GUI
to create the automatic rule, then checks every filter with the rule's name. It
must be a nonpersistent outbound IPv4 TCP permit scoped to the exact application
ID and listener port. A new connection must reach the loopback listener;
an executable with the same name in another directory must remain blocked.
Timeouts, an unavailable desktop, missing events, wrong filters and unexpected
socket errors fail the test.

The script closes the GUI, invokes silent uninstall and independently verifies
that Simplewall's provider, sublayer, callouts and filters are gone, including
when an assertion fails. A separate watchdog attempts the same cleanup if the
test process exits unexpectedly or exceeds four minutes. Cleanup failure keeps
the temporary directory and fails the step. Forced job or VM termination can
prevent either cleanup path; the runner must be discarded. As with the existing
integration test, Simplewall may change WFP engine security and net-event
options, which are not snapshot/restored. Consult the GitHub Actions run for
the result of the exact revision under test.
