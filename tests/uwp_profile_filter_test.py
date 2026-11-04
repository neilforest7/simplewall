#!/usr/bin/env python3
"""Exercise the real UWP filter builder with synthetic SIDs and no WFP calls.

Run on Windows from a Visual Studio developer prompt with CC set to clang.
The real routine SID converter and Windows SID APIs are used. Filter creation
is intercepted to inspect the conditions without changing the host firewall.
"""

import os
from pathlib import Path
import subprocess
import tempfile

if os.name != 'nt':
    raise SystemExit('This test requires Windows SID APIs and the Windows SDK')

root = Path(__file__).resolve().parents[1]
wfp = (root / 'src' / 'wfp.c').read_text()
routine = (root.parent / 'routine' / 'src' / 'routine.c').read_text()


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


stubs = r'''
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <sddl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xc000003aL)
#define RtlLengthSid GetLengthSid
#define RtlLengthSecurityDescriptor GetSecurityDescriptorLength
#define RTL_NUMBER_OF(a) (sizeof(a) / sizeof((a)[0]))
#define DATA_APP_SERVICE 1
#define DATA_APP_UWP 2
#define DATA_APP_REGULAR 3
#define DATA_TYPE_PORT 4
#define DATA_TYPE_IP 5
#define NET_ADDRESS_IPV4 1
#define NET_ADDRESS_IPV6 2
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_ERROR 2
#define PR_ULONG_PTR "zu"
#define _r_log(...) ((void)0)
#define _r_log_v(...) ((void)0)
#define _r_obj_getstring(s) ((s) ? (s)->buffer : L"")
#define _r_obj_isstringempty(s) (!(s) || !(s)->length || !(s)->buffer || !(s)->buffer[0])

typedef LONG NTSTATUS;
typedef int ENUM_TYPE_DATA;
typedef struct { ULONG_PTR length; LPWSTR buffer; } R_STRING, *PR_STRING, *PR_STRINGREF;
typedef struct { ULONG_PTR length; LPSTR buffer; } R_BYTE, *PR_BYTE;
typedef struct { PR_STRING original_path; PR_BYTE bytes; ENUM_TYPE_DATA type; } ITEM_APP, *PITEM_APP;
typedef struct { FWP_DIRECTION direction; UINT8 protocol; ADDRESS_FAMILY af; } ITEM_FILTER_CONFIG, *PITEM_FILTER_CONFIG;
typedef struct {
    FWP_V4_ADDR_AND_MASK addr4;
    FWP_V6_ADDR_AND_MASK addr6;
    FWP_RANGE0 range;
    UINT16 port;
    int type, format, is_range;
} ITEM_ADDRESS;
typedef void *PR_ARRAY;

static ITEM_APP app;
static PR_BYTE outstanding;
static PSID expected;
static unsigned filter_calls, app_releases, byte_releases, fail_at;
static int expected_type;
static FWP_ACTION_TYPE expected_action = FWP_ACTION_PERMIT;

static PR_BYTE _r_obj_createbyte_ex(const void *source, ULONG length) {
    PR_BYTE bytes = malloc(sizeof(*bytes) + length);
    assert(bytes && !outstanding);
    bytes->length = length;
    bytes->buffer = (LPSTR)(bytes + 1);
    if (source) memcpy(bytes->buffer, source, length);
    outstanding = bytes;
    return bytes;
}
static void _r_obj_dereference(void *object) {
    if (object == &app) { ++app_releases; return; }
    assert(object == outstanding);
    free(outstanding);
    outstanding = NULL;
    ++byte_releases;
}
static PITEM_APP _app_getappitem(ULONG_PTR hash) { return hash == 1 ? &app : NULL; }
static void ByteBlobAlloc(const void *data, ULONG_PTR length, FWP_BYTE_BLOB **out) {
    (void)data; (void)length; (void)out; assert(0);
}
static void ByteBlobFree(FWP_BYTE_BLOB **blob) { (void)blob; assert(0); }
static NTSTATUS _FwpmGetAppIdFromFileName1(PR_STRING path, int type, FWP_BYTE_BLOB **blob) {
    (void)path; (void)type; (void)blob; return STATUS_OBJECT_NAME_NOT_FOUND;
}
static BOOLEAN _app_parserulestring(PR_STRINGREF rule, ITEM_ADDRESS *address) {
    (void)rule; (void)address; return FALSE;
}
static ULONG _wfp_createfilter(HANDLE engine, int type, LPCWSTR name,
    FWPM_FILTER_CONDITION0 *conditions, UINT32 count, const GUID *layer,
    const GUID *callout, UINT8 weight, FWP_ACTION_TYPE action, UINT32 flags, PR_ARRAY guids) {
    const GUID *layers[] = { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 };
    (void)engine; (void)name; (void)callout;
    (void)weight; (void)flags; (void)guids;
    assert(filter_calls < 4 && IsEqualGUID(layer, layers[filter_calls]));
    assert(type == expected_type && action == expected_action);
    assert(outstanding && count == 1);
    assert(IsEqualGUID(&conditions[0].fieldKey, &FWPM_CONDITION_ALE_PACKAGE_ID));
    assert(conditions[0].matchType == FWP_MATCH_EQUAL);
    assert(conditions[0].conditionValue.type == FWP_SID);
    assert(IsValidSid(conditions[0].conditionValue.sid));
    assert(EqualSid(conditions[0].conditionValue.sid, expected));
    ++filter_calls;
    return filter_calls == fail_at ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;
}
'''

harness = r'''
int main(void) {
    WCHAR valid[] = L"S-1-15-2-1001-1002-1003-1004-1005-1006-1007";
    WCHAR invalid[] = L"S-1-invalid";
    R_STRING path = { sizeof(valid) - sizeof(WCHAR), valid };
    R_BYTE unused_cache = { 0, NULL };
    assert(ConvertStringSidToSidW(valid, &expected));
    app.original_path = &path;
    app.type = DATA_APP_UWP;

    /* An enabled profile-only package has no discovered package bytes. */
    assert(_wfp_createrulefilter(NULL, 0, NULL, 1, NULL, NULL, NULL, 0,
        FWP_ACTION_PERMIT, 0, NULL));
    assert(filter_calls == 4 && app_releases == 1 && byte_releases == 1 && !outstanding);

    /* A manual block rule remains a package-scoped block on every layer. */
    filter_calls = 0; expected_type = 7; expected_action = FWP_ACTION_BLOCK;
    assert(_wfp_createrulefilter(NULL, 7, NULL, 1, NULL, NULL, NULL, 0,
        FWP_ACTION_BLOCK, 0, NULL));
    assert(filter_calls == 4 && app_releases == 2 && byte_releases == 2 && !outstanding);

    /* Existing discovered entries use the same saved SID and release it on failure. */
    app.bytes = &unused_cache;
    filter_calls = 0; fail_at = 2; expected_type = 0; expected_action = FWP_ACTION_PERMIT;
    assert(!_wfp_createrulefilter(NULL, 0, NULL, 1, NULL, NULL, NULL, 0,
        FWP_ACTION_PERMIT, 0, NULL));
    assert(filter_calls == 4 && app_releases == 3 && byte_releases == 3 && !outstanding);

    /* A malformed saved SID must never produce an unscoped permit. */
    path.buffer = invalid; path.length = sizeof(invalid) - sizeof(WCHAR);
    filter_calls = 0; fail_at = 0;
    assert(!_wfp_createrulefilter(NULL, 0, NULL, 1, NULL, NULL, NULL, 0,
        FWP_ACTION_PERMIT, 0, NULL));
    assert(filter_calls == 0 && app_releases == 4 && byte_releases == 3 && !outstanding);

    LocalFree(expected);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-uwp-filter-') as directory:
    source = Path(directory) / 'uwp-filter.c'
    executable = Path(directory) / 'uwp-filter.exe'
    source.write_text(stubs + function(routine, 'PR_BYTE _r_str_tosid (') +
                      function(wfp, 'BOOLEAN _wfp_createrulefilter (') + harness)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra',
                    '-Wno-unused-but-set-variable', '-Wno-macro-redefined',
                    str(source), '-o', str(executable), '-ladvapi32'], check=True)
    subprocess.run([str(executable)], check=True)
print('Synthetic profile UWP SID filter checks passed without WFP changes')
