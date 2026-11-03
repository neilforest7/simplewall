# Automatic application allow rules

[简体中文](automatic-app-rules.zh-CN.md)

This branch adds an **Auto match** tab to the custom rule editor. It matches a
desktop executable by filename and can additionally require an installation
directory and a verified signature publisher. The UI includes English and
Simplified Chinese strings.

## Build and verification status

The implementation is based on upstream commit
`24bbd2ceb7daee9ef308e0b406be5eb039cb30a1`. It has not been built or exercised as a
complete Windows firewall application. Do not treat this branch as a tested
release.

Upstream's current application source requires a newer `routine` SDK than the
public repository contains. The public SDK's list, configuration, file and UI
APIs differ from those used by the unmodified application. The SDK maintainer
documents the end of public SDK updates in the
[routine README](https://github.com/henrypp/routine), and the build issue is
tracked in
[simplewall issue 2027](https://github.com/henrypp/simplewall/issues/2027).
Cloning the two current repositories is therefore insufficient to build this
branch. The known older build pairing described in that issue is Simplewall
3.8.5 and routine commit `9e1357364e0e23e56adeed443ae7419c9659d43f`; this feature
has not been backported to that pairing.

The included workflow deliberately tests the independent matcher and rule
scope/XML guards. It does **not** build the full application or prove WFP
integration. A compatible SDK and Windows integration testing remain release
requirements.

Verification performed during implementation:

- The three portable production-function regression tests (scope, XML and
  revocation failures) passed on Linux.
- The standalone matcher and its Windows test compiled and linked for Windows
  x64 with LLVM-MinGW 20261020 (`-Wall -Wextra -Werror`, ignoring MSVC-only
  library pragmas and linking those libraries explicitly).
- That Windows executable has not been run here. Authenticode, filesystem and
  WFP behavior still require Windows execution; the workflow is prepared for
  the independent matcher tests.

## Create a rule

1. Open the custom rules editor and create an **Allow** rule.
2. Set direction, protocol, addresses and ports as needed. For normal outbound
   internet access, use an outbound rule; an inbound permit is a separate choice.
3. Open **Auto match / 自动匹配** and enter the executable filename, including
   `.exe`, such as `example.exe`.
4. Optionally enter a local directory, such as `C:\Program Files\Example`, and
   the exact signing certificate's publisher common name.
5. Enable and save the rule.

Example selector (the publisher is a placeholder, not a claim about a real
certificate):

| Field | Value | Meaning |
| --- | --- | --- |
| Executable name | `example.exe` | Exact filename, case insensitive |
| Installation directory | `C:\Program Files\Example` | This directory and its descendants |
| Verified publisher | `Example Software Ltd.` | Exact common name from a successfully verified signing certificate |

All filled automatic conditions must match. Leaving the directory or publisher
empty removes that particular restriction. A filename is required when either
optional field is filled. Paths and wildcards are not accepted in the filename;
publisher wildcards are also rejected. The name is the executable filename,
not an installed product's display name or its file-description metadata.

Directory matching resolves file and directory handles before comparing them.
It checks the directory boundary, so `C:\Apps2` does not satisfy `C:\Apps`.
A junction or symbolic link that resolves outside the selected directory does
not satisfy that directory condition. The resolved executable's basename must
also match. Use an absolute drive-letter directory; UNC paths, device paths,
relative paths and environment-variable expressions are not supported.

## When automatic matches take effect

Saving, enabling or rebuilding a rule evaluates the programs already known to
Simplewall. While Simplewall is running, a new ordinary desktop executable
blocked by Simplewall's default policy is evaluated against automatic rules.
The program may need to retry its first connection after its path is permitted.
Traffic blocked by a specific custom, system or blocklist rule does not trigger
this discovery path.

There is no full-disk or installed-program scan. Services, packaged apps, WSL
process identities and network/device paths are not automatically selected by
this feature. Existing app and rule controls remain available for those cases.

The **Apps** tab continues to contain manual selections. Its selections and
automatic matches are combined. Thus a manually selected program can be covered
even when it does not satisfy the automatic selector. Leave the manual list
empty when only automatic matches should receive the rule.

A name selector with zero matches remains scoped to zero automatic targets. It
never becomes an unrestricted global permit. Clearing an existing automatic
selector with no manual app selections disables the rule and displays an
explanation. Deleting or disabling an automatic rule removes the filters owned
by that rule; separate manual permissions remain independent.

## Explicit exclusions

An app's properties include **Exclude from automatic allow rules**. A manual
block action also sets that exclusion, so the next blocked connection cannot
immediately allow it again through name matching. Clear the exclusion to make
the application eligible again. An explicit allow action clears the exclusion.

An exclusion controls automatic membership only. A separate manual allow rule
or an individually allowed application is an independent permission. Existing
custom block rules retain their usual priority.

## What the publisher condition verifies

The matcher calls Windows `WinVerifyTrust` for the file's embedded Authenticode
signature and accepts only `ERROR_SUCCESS`. It extracts the leaf signer's
certificate common name from that verified trust result. File version metadata,
such as `CompanyName`, is not used as proof of publisher identity.

Certificate-chain revocation checks are required, excluding the root. Production
checks use cached certificate/revocation information so a blocked app does not
cause an unbounded online trust lookup. An unavailable, unknown, offline or
revoked non-root status fails the match. As a result, a correctly signed program
can remain blocked until Windows has usable trust and revocation data in its
cache. Catalog-only signatures are not supported by this matcher.

These conditions are evaluated when a path is enrolled or its rule is rebuilt.
The resulting WFP filters still authorize an application path. They do not bind
every future connection to a certificate or file hash, and a replacement at an
already allowed path is not continuously reverified by this feature. The
existing changed-file monitoring option is separate. This is particularly
relevant when an installation directory is writable by an untrusted account.

## Profile format

Automatic rules are saved under a separate `rules_auto` section, with
`auto_filename`, `auto_directory` and `auto_publisher` attributes. Explicit
per-app exclusions are saved with the application entry. Derived automatic
memberships are rebuilt and are never saved as manual app selections.

The separate section prevents older Simplewall versions, which do not understand
automatic selectors, from loading a zero-manual-target automatic rule as a
global rule. An older version does not support these rules and may discard them
when saving a profile. Keep a backup before switching application versions.

## Run the independent tests

On Linux or another environment with Python 3 and a C11 compiler:

```sh
python3 tests/autoallow_scope_test.py
python3 tests/autoallow_xml_presence_test.py
python3 tests/autoallow_revoke_test.py
```

These compile selected production functions with small API stubs. They cover
scope preservation, invalid/empty selectors, manual and automatic membership,
excluded app types, serialization boundaries and XML absent-versus-empty
attribute behavior. They do not simulate the Windows trust service, UI or WFP.
The revocation test injects transaction begin, delete and commit failures into
the production deletion helper to check that failed revocation retains filter
identifiers and restores protection.

From an x64 Visual Studio developer command prompt on Windows:

```bat
cl /nologo /W4 /WX /DUNICODE /D_UNICODE /Fe:autoallow_match_test.exe tests\autoallow_match_test.c src\autoallow_match.c
autoallow_match_test.exe "C:\Program Files\PowerShell\7\pwsh.exe"
```

Pass the absolute path to a trusted, embedded-signed executable. The test warms
its certificate/revocation cache through an online verification, then exercises
the production cache-only matcher. It checks exact names, path validation,
directory boundaries, unsigned and tampered files, a valid signer and a wrong
signer. The directory-symlink case prints `SKIP` if Windows does not grant the
necessary link-creation capability. A failed trust fixture is a test failure,
not a skipped positive verification.

Before releasing an application build, also verify on Windows that rule
save/enable/disable/delete, restart/profile reload, first blocked connections,
manual exclusions, changed-file blocking and transaction failures produce the
expected WFP filters and traffic behavior. The independent tests above do not
replace those checks.
