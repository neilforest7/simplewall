#!/usr/bin/env python3
"""Inject transaction failures into the actual filter-revocation helper.

This covers GUID ownership and cleanup control flow; it does not replace native
Windows WFP integration tests. Failed revokes must remain tracked and protected.
"""
from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'src' / 'wfp.c').read_text()
start = SOURCE.index('BOOLEAN _wfp_destroyfilters_array (')
brace = SOURCE.index('{', start)
depth, end = 1, brace + 1
while depth:
    depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
    end += 1

STUBS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define _In_
#define _Inout_
#define TRUE 1
#define FALSE 0
#define DBG_ARG_VAR file_name, line
typedef uint8_t BOOLEAN;
typedef uint32_t ULONG;
typedef uintptr_t ULONG_PTR;
typedef void *HANDLE;
typedef const wchar_t *LPCWSTR;
typedef unsigned GUID;
typedef const GUID *LPCGUID;
typedef struct { GUID items[3]; size_t count; } ARRAY, *PR_ARRAY;
static int lock_apply, lock_transaction;
static unsigned begin_calls, delete_calls, commit_calls, abort_calls;
static unsigned unprotect_calls, protect_calls, clear_calls, init_calls, restore_calls;
static unsigned active_filters, saved_filters;
static int protected_filters[3];
static int fail_begin, fail_commit, fail_delete;
static int _r_obj_isempty2(PR_ARRAY array) { return !array->count; }
static size_t _r_obj_getarraysize(PR_ARRAY array) { return array->count; }
static void *_r_obj_getarrayitem(PR_ARRAY array, size_t index) {
    assert(index < array->count);
    return &array->items[index];
}
static void _r_obj_cleararray(PR_ARRAY array) { ++clear_calls; array->count = 0; }
static int _r_queuedlock_islocked(int *lock) { return *lock; }
static void _r_queuedlock_acquireexclusive(int *lock) { assert(!*lock); *lock = 1; }
static void _r_queuedlock_releaseexclusive(int *lock) { assert(*lock); *lock = 0; }
static void *_r_app_gethwnd(void) { return (void *)(uintptr_t)1; }
static BOOLEAN _app_initinterfacestate(void *hwnd, BOOLEAN forced) {
    (void)hwnd; (void)forced;
    assert(!lock_transaction);
    ++init_calls;
    return TRUE;
}
static void _app_restoreinterfacestate(void *hwnd, BOOLEAN enabled) {
    (void)hwnd;
    assert(!lock_transaction);
    if (enabled) ++restore_calls;
}
static void _app_setfiltersecurity(HANDLE engine, LPCGUID id, BOOLEAN protect,
    LPCWSTR file_name, ULONG line) {
    (void)engine; (void)file_name; (void)line;
    assert(lock_transaction);
    assert(*id < 3);
    protected_filters[*id] = protect;
    if (protect) ++protect_calls; else ++unprotect_calls;
}
static BOOLEAN _wfp_transact_start(HANDLE engine, LPCWSTR file_name, ULONG line) {
    (void)engine; (void)file_name; (void)line;
    assert(lock_transaction);
    ++begin_calls;
    saved_filters = active_filters;
    return !fail_begin;
}
static void FwpmTransactionAbort0(HANDLE engine) {
    (void)engine;
    assert(lock_transaction);
    ++abort_calls;
    active_filters = saved_filters;
}
static BOOLEAN _wfp_deletefilter(HANDLE engine, LPCGUID id, LPCWSTR file_name, ULONG line) {
    (void)engine; (void)file_name; (void)line;
    assert(lock_transaction);
    ++delete_calls;
    if ((int)*id == fail_delete) return FALSE;
    active_filters &= ~(1u << *id);
    return TRUE;
}
static BOOLEAN _wfp_transact_commit(HANDLE engine, LPCWSTR file_name, ULONG line) {
    (void)file_name; (void)line;
    assert(lock_transaction);
    ++commit_calls;
    /* The real _wfp_transact_commit aborts Windows state on commit failure. */
    if (fail_commit) { FwpmTransactionAbort0(engine); return FALSE; }
    return TRUE;
}
'''

TESTS = r'''
static void run_case(int begin_failure, int delete_failure, int commit_failure, int applying) {
    ARRAY ids = {{0, 1, 2}, 3};
    int success = !begin_failure && delete_failure < 0 && !commit_failure;
    fail_begin = begin_failure;
    fail_delete = delete_failure;
    fail_commit = commit_failure;
    lock_apply = applying;
    begin_calls = delete_calls = commit_calls = abort_calls = 0;
    unprotect_calls = protect_calls = clear_calls = init_calls = restore_calls = 0;
    active_filters = 7;
    for (unsigned i = 0; i < 3; ++i) protected_filters[i] = TRUE;

    assert(_wfp_destroyfilters_array(NULL, &ids, L"test", 1) == success);
    assert(!lock_transaction);
    assert(begin_calls == 1 && unprotect_calls == 3);
    assert(init_calls == (applying ? 0u : 1u));
    assert(restore_calls == (applying ? 0u : 1u));
    assert(delete_calls == (begin_failure ? 0u : 3u));
    assert(commit_calls == ((!begin_failure && delete_failure < 0) ? 1u : 0u));
    assert(abort_calls == ((!begin_failure && (delete_failure >= 0 || commit_failure)) ? 1u : 0u));
    if (success) {
        assert(!ids.count && clear_calls == 1);
        assert(!active_filters && !protect_calls);
    } else {
        assert(ids.count == 3 && !clear_calls);
        assert(active_filters == 7 && protect_calls == 3);
        for (unsigned i = 0; i < 3; ++i) {
            assert(ids.items[i] == i);
            assert(protected_filters[i]);
        }
    }
}
int main(void) {
    ARRAY empty = {{0}, 0};
    assert(_wfp_destroyfilters_array(NULL, &empty, L"test", 1));
    assert(!begin_calls && !init_calls && !clear_calls);
    run_case(1, -1, 0, 0);
    run_case(0, 1, 0, 0);
    run_case(0, -1, 1, 0);
    run_case(0, -1, 0, 0);
    run_case(0, -1, 0, 1); /* Apply worker must not synchronize with the UI. */
    puts("WFP revoke failure ownership, protection, and commit checks passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-revoke-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'revoke.c'
    executable = temporary / 'revoke-test'
    source.write_text(STUBS + SOURCE[start:end] + TESTS)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
