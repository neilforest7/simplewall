// simplewall
// Copyright (c) 2016-2026 Henry++

#include "autoallow_match.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <wchar.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#define SW_PATH_LIMIT 32768

static BOOL sw_equal (PCWSTR left, int left_length, PCWSTR right, int right_length)
{
	return CompareStringOrdinal (left, left_length, right, right_length, TRUE) == CSTR_EQUAL;
}

// Reject DOS device aliases even with an extension (e.g. CON.exe).
static BOOL sw_valid_component (PCWSTR name, size_t length)
{
	size_t i, stem = length;
	WCHAR digit;

	if (!length || length > 255 || name[length - 1] == L' ' || name[length - 1] == L'.')
		return FALSE;

	for (i = 0; i < length; i++)
	{
		if (name[i] < 32 || (name[i] >= 127 && name[i] <= 159) || wcschr (L"<>:\"/\\|?*", name[i]))
			return FALSE;
		if (name[i] == L'.' && stem == length)
			stem = i;
	}

	if (stem && name[stem - 1] == L' ')
		return FALSE;

	if ((stem == 3 && (sw_equal (name, 3, L"CON", 3) || sw_equal (name, 3, L"PRN", 3) ||
		sw_equal (name, 3, L"AUX", 3) || sw_equal (name, 3, L"NUL", 3))) ||
		(stem == 6 && sw_equal (name, 6, L"CONIN$", 6)) ||
		(stem == 7 && sw_equal (name, 7, L"CONOUT$", 7)))
		return FALSE;

	if (stem == 4 && (sw_equal (name, 3, L"COM", 3) || sw_equal (name, 3, L"LPT", 3)))
	{
		digit = name[3];
		if ((digit >= L'1' && digit <= L'9') || digit == 0x00b9 || digit == 0x00b2 || digit == 0x00b3)
			return FALSE;
	}

	return TRUE;
}

BOOL sw_autoallow_valid_filename (PCWSTR filename)
{
	size_t length;

	if (!filename)
		return FALSE;

	length = wcslen (filename);
	return length > 4 && sw_valid_component (filename, length) &&
		sw_equal (filename + length - 4, 4, L".exe", 4);
}

static BOOL sw_valid_local_path (PCWSTR path, BOOL allow_trailing_slash)
{
	PCWSTR component, cursor;
	size_t length;

	if (!path)
		return FALSE;

	length = wcslen (path);
	if (length < 3 || length >= SW_PATH_LIMIT ||
		!((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
		path[1] != L':' || path[2] != L'\\')
		return FALSE;

	component = path + 3;
	cursor = component;
	while (*cursor)
	{
		if (*cursor == L'\\')
		{
			if (!sw_valid_component (component, (size_t)(cursor - component)))
				return FALSE;
			component = cursor + 1;
		}
		cursor++;
	}

	if (cursor == component)
		return (cursor == path + 3) || allow_trailing_slash;

	return sw_valid_component (component, (size_t)(cursor - component));
}

BOOL sw_autoallow_valid_directory (PCWSTR directory)
{
	return sw_valid_local_path (directory, TRUE);
}

static HANDLE sw_open_local (PCWSTR path, BOOL is_directory)
{
	WCHAR root[] = L"C:\\";
	HANDLE file;
	BY_HANDLE_FILE_INFORMATION info;
	UINT drive_type;

	if (!sw_valid_local_path (path, is_directory))
		return INVALID_HANDLE_VALUE;

	root[0] = path[0];
	drive_type = GetDriveTypeW (root);
	if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE && drive_type != DRIVE_CDROM && drive_type != DRIVE_RAMDISK)
		return INVALID_HANDLE_VALUE;

	file = CreateFileW (path, is_directory ? FILE_READ_ATTRIBUTES : GENERIC_READ,
		is_directory ? FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE : FILE_SHARE_READ,
		NULL, OPEN_EXISTING, is_directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE)
		return file;

	if (GetFileType (file) != FILE_TYPE_DISK || !GetFileInformationByHandle (file, &info) ||
		(((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != is_directory))
	{
		CloseHandle (file);
		return INVALID_HANDLE_VALUE;
	}

	return file;
}

static PWSTR sw_final_path (HANDLE file)
{
	DWORD length, written;
	PWSTR path;

	length = GetFinalPathNameByHandleW (file, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
	if (!length || length > SW_PATH_LIMIT)
		return NULL;

	path = (PWSTR)HeapAlloc (GetProcessHeap (), 0, (SIZE_T)length * sizeof (WCHAR));
	if (!path)
		return NULL;

	written = GetFinalPathNameByHandleW (file, path, length, FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
	if (!written || written >= length)
	{
		HeapFree (GetProcessHeap (), 0, path);
		return NULL;
	}

	return path;
}

static BOOL sw_verified_publisher (HANDLE file, PCWSTR path, PWSTR output, DWORD capacity)
{
	WINTRUST_FILE_INFO file_info = {0};
	WINTRUST_DATA trust = {0};
	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	PCRYPT_PROVIDER_DATA provider;
	PCRYPT_PROVIDER_SGNR signer;
	PCRYPT_PROVIDER_CERT cert;
	PCCERT_CHAIN_CONTEXT chain;
	DWORD i, j, needed;
	BOOL result = FALSE;
	LONG status;

	if (!output || !capacity)
		return FALSE;
	output[0] = L'\0';
	file_info.cbStruct = sizeof (file_info);
	file_info.pcwszFilePath = path;
	file_info.hFile = file;
	trust.cbStruct = sizeof (trust);
	trust.dwUIChoice = WTD_UI_NONE;
	trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	trust.dwUnionChoice = WTD_CHOICE_FILE;
	trust.pFile = &file_info;
	trust.dwStateAction = WTD_STATEACTION_VERIFY;
	trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;

	status = WinVerifyTrust (INVALID_HANDLE_VALUE, &action, &trust);
	if (status == ERROR_SUCCESS && trust.hWVTStateData)
	{
		provider = WTHelperProvDataFromStateData (trust.hWVTStateData);
		signer = provider ? WTHelperGetProvSignerFromChain (provider, 0, FALSE, 0) : NULL;
		cert = signer ? WTHelperGetProvCertFromChain (signer, 0) : NULL;
		chain = signer ? signer->pChainContext : NULL;

		if (cert && cert->pCert && chain && chain->cChain)
		{
			result = TRUE;
			for (i = 0; i < chain->cChain && result; i++)
			{
				PCCERT_SIMPLE_CHAIN simple = chain->rgpChain[i];
				if (!simple || simple->cElement < 2)
				{
					result = FALSE;
					break;
				}
				// Root revocation is not checked; require a known, non-revoked status for every other certificate.
				for (j = 0; j + 1 < simple->cElement; j++)
				{
					if (!simple->rgpElement[j] || (simple->rgpElement[j]->TrustStatus.dwErrorStatus &
						(CERT_TRUST_IS_REVOKED | CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION)))
					{
						result = FALSE;
						break;
					}
				}
			}
			if (result)
			{
				needed = CertGetNameStringW (cert->pCert, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_COMMON_NAME, NULL, 0);
				result = needed > 1 && needed <= capacity &&
					CertGetNameStringW (cert->pCert, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_COMMON_NAME, output, capacity) == needed;
			}
		}
	}

	trust.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust (INVALID_HANDLE_VALUE, &action, &trust);
	if (!result)
		output[0] = L'\0';
	return result;
}

BOOL sw_autoallow_get_publisher (PCWSTR file_path, PWSTR output, DWORD capacity)
{
	HANDLE file;
	BOOL result;

	if (!output || !capacity)
		return FALSE;
	output[0] = L'\0';
	file = sw_open_local (file_path, FALSE);
	if (file == INVALID_HANDLE_VALUE)
		return FALSE;
	result = sw_verified_publisher (file, file_path, output, capacity);
	CloseHandle (file);
	return result;
}

BOOL sw_autoallow_match (PCWSTR file_path, PCWSTR filename, PCWSTR directory, PCWSTR publisher)
{
	HANDLE file = INVALID_HANDLE_VALUE, folder = INVALID_HANDLE_VALUE;
	PWSTR file_final = NULL, folder_final = NULL;
	PCWSTR basename;
	size_t folder_length, file_length;
	WCHAR signer[1024];
	BOOL result = FALSE;

	if (!sw_autoallow_valid_filename (filename) || !file_path || !*file_path ||
		(directory && *directory && !sw_autoallow_valid_directory (directory)))
		return FALSE;

	// Reject obvious nonmatches before opening the file, then check the final
	// resolved basename too so a link cannot substitute a different target.
	basename = wcsrchr (file_path, L'\\');
	if (!basename || !sw_equal (basename + 1, -1, filename, -1))
		return FALSE;

	file = sw_open_local (file_path, FALSE);
	if (file == INVALID_HANDLE_VALUE)
		goto cleanup;
	file_final = sw_final_path (file);
	if (!file_final)
		goto cleanup;
	basename = wcsrchr (file_final, L'\\');
	if (!basename || !sw_autoallow_valid_filename (basename + 1) || !sw_equal (basename + 1, -1, filename, -1))
		goto cleanup;

	if (directory && *directory)
	{
		folder = sw_open_local (directory, TRUE);
		if (folder == INVALID_HANDLE_VALUE)
			goto cleanup;
		folder_final = sw_final_path (folder);
		if (!folder_final)
			goto cleanup;
		folder_length = wcslen (folder_final);
		file_length = wcslen (file_final);
		while (folder_length && folder_final[folder_length - 1] == L'\\')
			folder_length--;
		if (!folder_length || file_length <= folder_length || file_final[folder_length] != L'\\' ||
			!sw_equal (folder_final, (int)folder_length, file_final, (int)folder_length))
			goto cleanup;
	}

	if (publisher && *publisher && (!sw_verified_publisher (file, file_path, signer, ARRAYSIZE (signer)) ||
		!sw_equal (signer, -1, publisher, -1)))
		goto cleanup;

	result = TRUE;
cleanup:
	if (folder_final)
		HeapFree (GetProcessHeap (), 0, folder_final);
	if (file_final)
		HeapFree (GetProcessHeap (), 0, file_final);
	if (folder != INVALID_HANDLE_VALUE)
		CloseHandle (folder);
	if (file != INVALID_HANDLE_VALUE)
		CloseHandle (file);
	return result;
}
