// simplewall
// Automatic allow matching. These functions are synchronous; call outside app locks.
#pragma once

#include <windows.h>

// A single unambiguous Windows executable basename, including .exe.
BOOL sw_autoallow_valid_filename (PCWSTR filename);

// An absolute, local drive-letter path in ordinary Win32 syntax. Existence is
// checked when matching, not here. UNC, device paths and dot components fail.
BOOL sw_autoallow_valid_directory (PCWSTR directory);

// All supplied conditions must match. Directory means the directory itself or
// any descendant. Publisher means the exact, case-insensitive signer common name
// from a successfully verified embedded Authenticode signature. Revocation is
// checked using cached data only; unavailable or unknown status fails closed.
// File and directory are opened and normalized at match time. This is not a
// durable file identity: a path-based firewall rule can later refer to a
// replacement file, so callers must re-evaluate on relevant file changes.
BOOL sw_autoallow_match (PCWSTR file_path, PCWSTR filename, PCWSTR directory, PCWSTR publisher);

// Retrieves the verified embedded signer common name, or returns FALSE and
// clears output. No file metadata or unverified certificate fallback is used.
BOOL sw_autoallow_get_publisher (PCWSTR file_path, PWSTR output, DWORD capacity);
