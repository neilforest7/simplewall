# Windows GUI smoke test

Run only in an elevated, disposable GitHub-hosted Windows VM with no user secrets
or persisted checkout credentials. Build the full application for x64 and set up
the x64 MSVC developer environment first. Give the job a bounded timeout and an
interactive desktop. Environment variables are guardrails, not proof that the
host is disposable or secret-free.

From the repository root, after the build:

```powershell
pwsh -NoProfile -File tests/windows_gui/run.ps1 -SimplewallExe bin/64/simplewall.exe
```

The script copies the executable and built language file into a fresh directory under RUNNER_TEMP,
creates a portable English configuration, and starts the GUI with `-portable`.
It checks that the process and the simplewall WFP provider, sublayer, provider
callouts, and provider/sublayer filters are absent before startup. It opens the
actual new-rule editor, reads and clicks the native Auto match tab, checks the
publisher-without-filename warning, and saves two enabled allow rules: one with
both filename and publisher, and one with filename only. After a clean exit it
reads the portable profile and checks both records under `rules_auto`.

The read-only WFP inventory runs before startup, during the test, after clean
exit, and in cleanup. Inventory failure or a missing/unusable desktop is a test
failure, never a pass. The checks are snapshots; they cannot establish that no
object existed briefly between checks, nor identify unrelated WFP objects with
other keys. The test does not enable filtering or exercise actual publisher
signature matching. Environment checks cannot guarantee the absence of secrets.
If a failure leaves the GUI running, cleanup terminates that process and checks
the inventory again; it never invokes the uninstall or install commands. Forced
job termination can bypass cleanup, so discard the VM after the job.

A syntax check alone does not validate this test. Consult the corresponding
GitHub Actions run for the tested revision and result; an unavailable desktop
or inaccessible required dialog causes the test to fail.
