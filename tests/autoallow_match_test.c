// Build from a Visual Studio developer prompt, then pass an absolute path to a
// trusted, embedded-signed executable, for example: autoallow_match_test.exe C:\path\pwsh.exe
// cl /W4 /WX /DUNICODE /D_UNICODE tests\autoallow_match_test.c src\autoallow_match.c
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <wchar.h>
#include "../src/autoallow_match.h"

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

#define CHECK(x) do { if (!(x)) { fwprintf (stderr, L"FAIL line %d: %hs\n", __LINE__, #x); failures++; } } while (0)

// Warm the Windows certificate and revocation caches through an online trust
// check. The production matcher stays cache-only and rejects unknown status.
static BOOL prewarm_trust (PCWSTR path)
{
	WINTRUST_FILE_INFO file_info = {0};
	WINTRUST_DATA trust = {0};
	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG status;

	file_info.cbStruct = sizeof (file_info);
	file_info.pcwszFilePath = path;
	trust.cbStruct = sizeof (trust);
	trust.dwUIChoice = WTD_UI_NONE;
	trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	trust.dwUnionChoice = WTD_CHOICE_FILE;
	trust.pFile = &file_info;
	trust.dwStateAction = WTD_STATEACTION_VERIFY;
	trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
	status = WinVerifyTrust (INVALID_HANDLE_VALUE, &action, &trust);
	trust.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust (INVALID_HANDLE_VALUE, &action, &trust);
	if (status != ERROR_SUCCESS)
		fwprintf (stderr, L"Online fixture verification failed: 0x%08lX\n", (unsigned long)status);
	return status == ERROR_SUCCESS;
}

// Flip a byte in the PE's DOS stub, which is covered by its signature.
static BOOL tamper_file (PCWSTR path)
{
	HANDLE file;
	BYTE byte;
	DWORD count;
	BOOL result = FALSE;
	LARGE_INTEGER offset;

	file = CreateFileW (path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return FALSE;
	offset.QuadPart = 0x40;
	if (SetFilePointerEx (file, offset, NULL, FILE_BEGIN) && ReadFile (file, &byte, 1, &count, NULL) && count == 1 &&
		SetFilePointerEx (file, offset, NULL, FILE_BEGIN))
	{
		byte = (BYTE)(byte ^ 1);
		result = WriteFile (file, &byte, 1, &count, NULL) && count == 1;
	}
	CloseHandle (file);
	return result;
}

int wmain (int argc, WCHAR **argv)
{
	WCHAR temp[MAX_PATH], base[MAX_PATH], apps[MAX_PATH], apps2[MAX_PATH], nested[MAX_PATH];
	WCHAR exe[MAX_PATH], nested_exe[MAX_PATH], signed_exe[MAX_PATH], tampered_exe[MAX_PATH];
	WCHAR link_path[MAX_PATH], link_exe[MAX_PATH], self[MAX_PATH], signer[1024], wrong_signer[1024], output[1024];
	DWORD length;
	int failures = 0;
	BOOL linked = FALSE;

	if (argc != 2)
	{
		fwprintf (stderr, L"Usage: autoallow_match_test.exe <absolute path to a trusted signed executable>\n");
		return 2;
	}

	CHECK (sw_autoallow_valid_filename (L"App.EXE"));
	CHECK (!sw_autoallow_valid_filename (NULL));
	CHECK (!sw_autoallow_valid_filename (L""));
	CHECK (!sw_autoallow_valid_filename (L"../app.exe"));
	CHECK (!sw_autoallow_valid_filename (L"app.exe:stream"));
	CHECK (!sw_autoallow_valid_filename (L"app*.exe"));
	CHECK (!sw_autoallow_valid_filename (L"CON.exe"));
	CHECK (!sw_autoallow_valid_filename (L"LPT\x00b9.exe"));
	CHECK (!sw_autoallow_valid_filename (L"app.exe."));
	CHECK (!sw_autoallow_valid_filename (L"app\x0085.exe"));
	CHECK (sw_autoallow_valid_directory (L"C:\\Apps\\"));
	CHECK (!sw_autoallow_valid_directory (L"C:Apps"));
	CHECK (!sw_autoallow_valid_directory (L"C:\\Apps\\..\\Other"));
	CHECK (!sw_autoallow_valid_directory (L"\\\\server\\share"));
	CHECK (!sw_autoallow_valid_directory (L"C:\\Apps:stream"));
	CHECK (!sw_autoallow_match (NULL, L"app.exe", NULL, NULL));
	CHECK (!sw_autoallow_match (L"", L"app.exe", NULL, NULL));

	length = GetTempPathW (MAX_PATH, temp);
	if (!length || length >= MAX_PATH || !GetTempFileNameW (temp, L"swa", 0, base))
		return 2;
	if (!DeleteFileW (base) || !CreateDirectoryW (base, NULL))
		return 2;
	if (swprintf_s (apps, MAX_PATH, L"%s\\Apps", base) < 0 ||
		swprintf_s (apps2, MAX_PATH, L"%s\\Apps2", base) < 0 ||
		swprintf_s (nested, MAX_PATH, L"%s\\Nested", apps2) < 0 ||
		swprintf_s (exe, MAX_PATH, L"%s\\app.exe", apps2) < 0 ||
		swprintf_s (nested_exe, MAX_PATH, L"%s\\app.exe", nested) < 0 ||
		swprintf_s (signed_exe, MAX_PATH, L"%s\\signed.exe", apps2) < 0 ||
		swprintf_s (tampered_exe, MAX_PATH, L"%s\\tampered.exe", apps2) < 0 ||
		swprintf_s (link_path, MAX_PATH, L"%s\\Link", apps) < 0 ||
		swprintf_s (link_exe, MAX_PATH, L"%s\\app.exe", link_path) < 0)
		return 2;
	length = GetModuleFileNameW (NULL, self, MAX_PATH);
	if (!length || length >= MAX_PATH || !CreateDirectoryW (apps, NULL) || !CreateDirectoryW (apps2, NULL) ||
		!CreateDirectoryW (nested, NULL) || !CopyFileW (self, exe, TRUE) || !CopyFileW (self, nested_exe, TRUE) ||
		!CopyFileW (argv[1], signed_exe, TRUE) || !CopyFileW (argv[1], tampered_exe, TRUE))
	{
		fwprintf (stderr, L"Could not prepare test files: %lu\n", GetLastError ());
		return 2;
	}

	CHECK (sw_autoallow_match (exe, L"APP.EXE", NULL, NULL));
	CHECK (sw_autoallow_match (exe, L"app.exe", apps2, NULL));
	CHECK (sw_autoallow_match (nested_exe, L"app.exe", apps2, NULL));
	CHECK (!sw_autoallow_match (exe, L"other.exe", apps2, NULL));
	CHECK (!sw_autoallow_match (exe, L"app.exe", apps, NULL));
	CHECK (!sw_autoallow_get_publisher (exe, output, ARRAYSIZE (output)));
	CHECK (!sw_autoallow_match (exe, L"app.exe", apps2, L"Unrelated publisher"));

	linked = CreateSymbolicLinkW (link_path, apps2, SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
	if (linked)
	{
		CHECK (sw_autoallow_match (link_exe, L"app.exe", apps2, NULL));
		CHECK (!sw_autoallow_match (link_exe, L"app.exe", apps, NULL));
	}
	else
		fwprintf (stderr, L"SKIP directory symlink escape test (Windows error %lu)\n", GetLastError ());

	if (prewarm_trust (signed_exe) && sw_autoallow_get_publisher (signed_exe, signer, ARRAYSIZE (signer)))
	{
		CHECK (signer[0] != L'\0');
		CHECK (sw_autoallow_match (signed_exe, L"signed.exe", apps2, signer));
		CHECK (wcscpy_s (wrong_signer, ARRAYSIZE (wrong_signer), signer) == 0);
		wrong_signer[0] = signer[0] == L'A' ? L'B' : L'A';
		CHECK (!sw_autoallow_match (signed_exe, L"signed.exe", apps2, wrong_signer));
		CHECK (tamper_file (tampered_exe));
		CHECK (!sw_autoallow_get_publisher (tampered_exe, output, ARRAYSIZE (output)));
		CHECK (!sw_autoallow_match (tampered_exe, L"tampered.exe", apps2, signer));
	}
	else
	{
		fwprintf (stderr, L"FAIL trusted fixture or cached revocation data unavailable\n");
		failures++;
	}

	if (linked)
		RemoveDirectoryW (link_path);
	DeleteFileW (tampered_exe);
	DeleteFileW (signed_exe);
	DeleteFileW (nested_exe);
	DeleteFileW (exe);
	RemoveDirectoryW (nested);
	RemoveDirectoryW (apps2);
	RemoveDirectoryW (apps);
	RemoveDirectoryW (base);
	return failures ? 1 : 0;
}
