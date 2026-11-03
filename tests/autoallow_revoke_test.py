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
start = SOURCE.index('BOOLEAN _wfp_destroyfilters_array_silent (')
brace = SOURCE.index('{', SOURCE.index('BOOLEAN _wfp_destroyfilters_array (', start))
depth, end = 1, brace + 1
while depth:
    depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
    end += 1

STUBS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#ifdef _In_
#undef _In_
#undef _Inout_
#endif
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
static int lock_apply, lock_transaction, lock_autoallow;
static unsigned begin_calls, delete_calls, commit_calls, abort_calls;
static unsigned unprotect_calls, protect_calls, clear_calls, init_calls, restore_calls;
static unsigned active_filters, saved_filters;
static int protected_filters[3];
static int fail_begin, fail_commit, fail_delete, has_hwnd = 1;
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
static void *_r_app_gethwnd(void) { return has_hwnd ? (void *)(uintptr_t)1 : NULL; }
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
static void run_case(int begin_failure, int delete_failure, int commit_failure, int applying, int window) {
    has_hwnd = window;
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
    assert(init_calls == ((applying || !window) ? 0u : 1u));
    assert(restore_calls == ((applying || !window) ? 0u : 1u));
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
    run_case(1, -1, 0, 0, 1);
    run_case(0, 1, 0, 0, 1);
    run_case(0, -1, 1, 0, 1);
    run_case(0, -1, 0, 0, 1);
    run_case(0, -1, 0, 1, 1); /* Apply worker must not synchronize with the UI. */
    run_case(0, -1, 0, 0, 0); /* Headless commands never touch UI. */
    ARRAY silent_ids = {{0, 1, 2}, 3};
    fail_begin = fail_commit = 0; fail_delete = 1; has_hwnd = 1;
    lock_autoallow = 1; init_calls = restore_calls = 0; active_filters = 7;
    assert(!_wfp_destroyfilters_array_silent(NULL, &silent_ids, L"test", 1));
    assert(silent_ids.count == 3 && active_filters == 7 && !init_calls && !restore_calls);
    assert(lock_autoallow && !lock_transaction);
    lock_autoallow = 0;
    puts("WFP revoke failure ownership, protection, and commit checks passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-revoke-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'revoke.c'
    executable = temporary / ('revoke-test.exe' if os.name == 'nt' else 'revoke-test')
    source.write_text(STUBS + SOURCE[start:end] + TESTS)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)


from pathlib import Path
import os
import subprocess
import tempfile

SOURCE = (Path(__file__).resolve().parents[1] / 'src' / 'wfp.c').read_text()


def function(name):
    marker = name + ' ('
    start = SOURCE.index(marker, SOURCE.index('// The refresh replaces each table'))
    start = SOURCE.rfind('\n', 0, start) + 1
    brace = SOURCE.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
        end += 1
    return SOURCE[start:end]


STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _In_opt_
#endif
#define _In_
#define _In_opt_
#define TRUE 1
#define FALSE 0
#define VOID void
#define DATA_APP_REGULAR 1
#define DATA_RULE_USER 2
#define PR_UPDATE_FORCE 1
#define PR_UPDATE_TYPE 2
#define AF_UNSPEC 0
#define FWP_DIRECTION_MAX 9
#define DBG_ARG L"test", 1
#define _r_obj_isempty2(o) (!(o)->count)
typedef unsigned char BOOLEAN;
typedef unsigned long ULONG;
typedef uintptr_t ULONG_PTR;
typedef void *HWND;
typedef struct table { int refs; unsigned bits; } TABLE, *PR_HASHTABLE;
typedef struct list { unsigned count; void *items[16]; void (*destroy)(void *); } LIST, *PR_LIST;
typedef struct array { unsigned count; } ARRAY, *PR_ARRAY;
typedef struct rule { PR_HASHTABLE auto_apps; PR_ARRAY guids; int is_enabled, is_haveerrors;
    int match, hasauto, protocol, af, direction; void *rule_remote, *rule_local; } RULE, *PITEM_RULE;
typedef struct app { int type, is_autoallow_blocked; unsigned app_hash; } APP, *PITEM_APP;
typedef struct log { int protocol, af, direction; } LOG, *PITEM_LOG;
static int lock_apply, lock_autoallow, lock_autoapps, lock_rules;
static LIST *rules_list;
static int rollback, semantic_error, calls, warnings, installed = 1;
static void _r_obj_dereference(void *p) { if (p) ((TABLE*)p)->refs--; }
static void *_r_obj_reference(void *p) { assert(p); ((TABLE*)p)->refs++; return p; }
/* Rules are referenced too, but their first field is a pointer, not a refcount.
   The fixture uses this identity helper for rule references instead. */
static void *_ref(void *p) { return p; }
static void _drop(void *p) { (void)p; }
static PR_LIST _r_obj_createlist(unsigned cap, void (*d)(void *)) {
    (void)cap; LIST *p = calloc(1, sizeof(*p)); p->destroy=d; return p;
}
static void _r_obj_addlistitem(PR_LIST p, void *value) {
    assert(p->count < 16); p->items[p->count++]=value;
}
static unsigned _r_obj_getlistsize(PR_LIST p) { return p->count; }
static void *_r_obj_getlistitem(PR_LIST p, unsigned i) { assert(i < p->count); return p->items[i]; }
static void *_r_obj_findhashtable(PR_HASHTABLE p, unsigned key) { return (p->bits & (1u<<key)) ? p : NULL; }
static void _r_obj_addhashtableitem(PR_HASHTABLE p, unsigned key, void *unused) { (void)unused; p->bits |= 1u<<key; }
static void _r_obj_removehashtableitem(PR_HASHTABLE p, unsigned key) { p->bits &= ~(1u<<key); }
static int _r_queuedlock_islocked(int *l) { return *l; }
static void _r_queuedlock_acquireexclusive(int *l) { assert(!*l); *l=1; }
static void _r_queuedlock_releaseexclusive(int *l) { assert(*l); *l=0; }
static void _r_queuedlock_acquireshared(int *l) { _r_queuedlock_acquireexclusive(l); }
static void _r_queuedlock_releaseshared(int *l) { _r_queuedlock_releaseexclusive(l); }
static int _wfp_isfiltersinstalled(void) { return installed; }
static void *_wfp_getenginehandle(void) { return NULL; }
static int _app_rule_hasauto(RULE *r) { return r->hasauto; }
static int _app_rule_matchapp(RULE *r, APP *a) { (void)a; return r->match; }
static int _r_obj_isstringempty(void *p) { return !p; }
static void _app_listview_updateitemby_param(HWND h, unsigned x, int y) { (void)h;(void)x;(void)y; }
static void _app_listview_updateby_id(HWND h, int x, int y) { (void)h;(void)x;(void)y; }
static void _wfp_warnruleupdate(HWND h) { (void)h; assert(!lock_autoallow && !lock_autoapps); ++warnings; }
static void _app_rule_refresh_autoapps(RULE *r) {
    TABLE *t = calloc(1, sizeof(*t)); t->refs=1; t->bits=r->match ? 2 : 0;
    r->auto_apps->refs--; r->auto_apps=t;
}
static int _wfp_createrulefilters_internal(void *h, LIST *rules, const wchar_t *f,
        unsigned line, int trans, BOOLEAN *failed) {
    (void)h;(void)rules;(void)f;(void)line;(void)trans;
    ++calls; *failed=rollback;
    return !(rollback || semantic_error);
}
'''

# Reference counting is exercised for the snapshot helpers; lists containing
# rules use fixture-only identity references to avoid modelling all object types.
SNAPSHOT = function('_wfp_snapshotautoapps') + '\n' + function('_wfp_restoreautoapps')
EVENT = function('_wfp_autoallow_app').replace('_r_obj_reference (ptr_rule)', '_ref (ptr_rule)').replace('&_r_obj_dereference', '&_drop')
REFRESH = function('_app_autoallow_refresh').replace('_r_obj_reference (ptr_rule)', '_ref (ptr_rule)').replace('&_r_obj_dereference', '&_drop')
# Lists in this harness do not own their allocations; dereference of lists must
# not touch table reference counts. Table ownership is asserted explicitly.
EVENT = EVENT.replace('_r_obj_dereference (changed)', '(void)(changed)').replace('_r_obj_dereference (candidates)', '(void)(candidates)').replace('_r_obj_dereference (added)', '(void)(added)').replace('_r_obj_dereference (removed)', '(void)(removed)')
REFRESH = REFRESH.replace('_r_obj_dereference (previous_autoapps)', '(void)(previous_autoapps)').replace('_r_obj_dereference (rules)', '(void)(rules)')
TESTS = r'''
int main(void) {
    TABLE old = {1, 2}; ARRAY ids = {1}; RULE rule = {0}; APP app = {DATA_APP_REGULAR, 0, 1};
    LOG log = {0, 0, 0}; LIST all = {0}; rules_list=&all;
    rule.auto_apps=&old; rule.guids=&ids; rule.is_enabled=rule.hasauto=1;
    _r_obj_addlistitem(&all, &rule);
    rollback=1; rule.match=0;
    assert(!_wfp_autoallow_app(NULL, &app, &log));
    assert(old.bits==2 && calls==1 && warnings==1);
    rollback=0;
    assert(!_wfp_autoallow_app(NULL, &app, &log));
    assert(old.bits==0 && calls==2); /* The next event retries removal. */
    rule.match=1; rollback=1;
    assert(!_wfp_autoallow_app(NULL, &app, &log));
    assert(old.bits==0 && calls==3 && warnings==2); /* Failed grant retried too. */
    old.bits=2; rule.match=0; rollback=1;
    _app_autoallow_refresh(NULL);
    assert(rule.auto_apps==&old && old.bits==2 && warnings==3);
    rollback=0; semantic_error=1;
    _app_autoallow_refresh(NULL);
    assert(rule.auto_apps!=&old && rule.auto_apps->bits==0 && warnings==4);
    assert(calls==5); /* Committed partial error must not restore old membership. */
    puts("automatic membership rollback, retry, warning and committed-error checks passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-auto-revoke-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(STUBS + SNAPSHOT + EVENT + REFRESH + TESTS)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


from pathlib import Path
import os
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'src' / 'wfp.c').read_text()
start = source.index('static BOOLEAN _wfp_createrulefilters_internal (', source.index('BOOLEAN _wfp_createrulefilters ('))
brace = source.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1

stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _Out_opt_
#endif
#define _In_
#define _Out_opt_
#define TRUE 1
#define FALSE 0
#define DBG_ARG_VAR file_name, line
#define DIVIDER_RULE L"|"
#define FWP_ACTION_BLOCK 1
#define _r_obj_isempty2(p) (!(p)->count)
#define _r_obj_isempty(p) (!(p) || !(p)->count)
typedef unsigned char BOOLEAN, *PBOOLEAN;
typedef unsigned ULONG;
typedef uintptr_t ULONG_PTR;
typedef const wchar_t *LPCWSTR;
typedef void *HANDLE;
typedef unsigned GUID;
typedef const GUID *LPCGUID;
typedef struct { unsigned count; GUID *items; GUID storage[16]; } ARRAY, *PR_ARRAY;
typedef struct { unsigned count; void *items[16]; } LIST, *PR_LIST;
typedef struct { unsigned length; } R_STRINGREF;
typedef struct { R_STRINGREF sr; } STRING, *PR_STRING;
typedef struct { PR_ARRAY guids; int is_enabled, is_haveerrors, is_forservices, is_fordriver;
    int type, weight, action, config; void *apps, *auto_apps; PR_STRING name, rule_remote, rule_local; } RULE, *PITEM_RULE;
static struct { unsigned ntoskrnl_hash, svchost_hash; } config;
static int lock_transaction, lock_autoapps;
static int fail_begin, fail_delete, fail_commit, active, saved, protected_id, aborts;
static void _r_obj_dereference(void *p) { (void)p; }
static PR_ARRAY _r_obj_createarray(size_t size, unsigned cap, void *d) {
    (void)size;(void)cap;(void)d; ARRAY *a=calloc(1,sizeof(*a)); a->items=a->storage; return a;
}
static PR_LIST _r_obj_createlist(unsigned cap, void (*d)(void *)) { (void)cap;(void)d; return calloc(1,sizeof(LIST)); }
static void _r_obj_addlistitem(PR_LIST l, void *v) { l->items[l->count++]=v; }
static unsigned _r_obj_getlistsize(PR_LIST l) { return l->count; }
static void *_r_obj_getlistitem(PR_LIST l, unsigned i) { assert(i<l->count); return l->items[i]; }
static void _r_obj_addarrayitems(PR_ARRAY a, GUID *v, unsigned n) { for(unsigned i=0;i<n;i++) a->items[a->count++]=v[i]; }
static unsigned _r_obj_getarraysize(PR_ARRAY a) { return a->count; }
static void *_r_obj_getarrayitem(PR_ARRAY a, unsigned i) { assert(i<a->count); return &a->items[i]; }
static void _r_obj_cleararray(PR_ARRAY a) { a->count=0; }
static void _r_queuedlock_acquireexclusive(int *l) { assert(!*l); *l=1; }
static void _r_queuedlock_releaseexclusive(int *l) { assert(*l); *l=0; }
static void _r_queuedlock_acquireshared(int *l) { _r_queuedlock_acquireexclusive(l); }
static void _r_queuedlock_releaseshared(int *l) { _r_queuedlock_releaseexclusive(l); }
static void _app_setfiltersecurity(HANDLE h,LPCGUID id,int p,LPCWSTR f,ULONG line) {
    (void)h;(void)f;(void)line; assert(*id==1); protected_id=p;
}
static int _wfp_transact_start(HANDLE h,LPCWSTR f,ULONG l) { (void)h;(void)f;(void)l; saved=active; return !fail_begin; }
static void FwpmTransactionAbort0(HANDLE h) { (void)h; active=saved; ++aborts; }
static int _wfp_transact_commit(HANDLE h,LPCWSTR f,ULONG l) { (void)f;(void)l; if(fail_commit) { FwpmTransactionAbort0(h); return 0; } return 1; }
static int _wfp_deletefilter(HANDLE h,LPCGUID id,LPCWSTR f,ULONG l) { (void)h;(void)id;(void)f;(void)l; if(fail_delete)return 0; active=0; return 1; }
static int _app_rule_hasauto(RULE *r) { (void)r; return 1; }
static int _app_rule_autoisvalid(RULE *r) { (void)r; return 1; }
static int _app_rule_isglobal(RULE *r) { (void)r; return 0; }
static LPCWSTR _r_obj_getstring(PR_STRING p) { (void)p; return L"rule"; }
static int _r_obj_isstringempty(PR_STRING p) { return !p; }
static void _r_str_splitatchar(R_STRINGREF *a,wchar_t c,R_STRINGREF *b,R_STRINGREF *d) { (void)a;(void)c;b->length=d->length=0; }
static void _r_obj_initializestringrefempty(R_STRINGREF *p) { p->length=0; }
static int _r_obj_enumhashtable(void *t, void *v, ULONG_PTR *h, ULONG_PTR *e) { (void)t;(void)v;(void)h;(void)e;return 0; }
static void *_r_obj_findhashtable(void *t, ULONG h) { (void)t;(void)h;return NULL; }
static int _wfp_createrulefilter(HANDLE h,int t,LPCWSTR n,ULONG hash,void *c,R_STRINGREF *r,R_STRINGREF *l,int w,int a,int flags,PR_ARRAY ids) {
    (void)h;(void)t;(void)n;(void)hash;(void)c;(void)r;(void)l;(void)w;(void)a;(void)flags;(void)ids;return 1;
}
'''
rule_stubs = stubs
tests = r'''
static void run(int begin, int deletion, int commit) {
    ARRAY ids = {0}; ids.items=ids.storage; ids.items[ids.count++]=1;
    RULE r = {0}; r.guids=&ids; r.is_enabled=0;
    LIST rules = {0}; rules.items[rules.count++]=&r;
    BOOLEAN rollback=0;
    fail_begin=begin; fail_delete=deletion; fail_commit=commit;
    active=protected_id=1; aborts=0;
    int success=_wfp_createrulefilters_internal(NULL,&rules,L"test",1,0,&rollback);
    assert(!lock_transaction && !lock_autoapps);
    if (begin || deletion || commit) {
        assert(!success && rollback && r.is_haveerrors);
        assert(ids.count==1 && ids.items[0]==1 && active && protected_id);
        assert(aborts == (begin ? 0 : 1));
    } else {
        assert(success && !rollback && !ids.count && !active);
    }
}
int main(void) {
    run(1,0,0); run(0,1,0); run(0,0,1); run(0,0,0);
    puts("disabled rule transaction failures preserve GUID, active filter and protection");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-rule-revoke-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(stubs + source[start:end] + tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Run the older SDK's application-filter transaction with injected failures.
source = (Path(__file__).resolve().parents[1] / 'src' / 'wfp.c').read_text()
start = source.index('static BOOLEAN _wfp_createappfilters_internal (', source.index('BOOLEAN _wfp_createappfilters ('))
brace = source.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1

stubs = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _Inout_
#undef _Out_opt_
#endif
#define _In_
#define _Out_opt_
#define LOG_LEVEL_ERROR 1
#define TRUE 1
#define FALSE 0
#define DBG_ARG_VAR file_name, line
#define _r_obj_isempty(p) (!(p) || !(p)->count)
#define FW_WEIGHT_APP 1
#define FWP_ACTION_PERMIT 1
typedef unsigned char BOOLEAN, *PBOOLEAN;
typedef unsigned ULONG, GUID;
typedef uintptr_t ULONG_PTR;
typedef const GUID *LPCGUID;
typedef const wchar_t *LPCWSTR;
typedef void *HANDLE;
typedef struct { unsigned count; GUID *items; GUID storage[8]; } ARRAY, *PR_ARRAY;
typedef struct { unsigned count; void *items[8]; } LIST, *PR_LIST;
typedef struct { PR_ARRAY guids; int is_enabled, is_haveerrors, type, app_hash; } APP, *PITEM_APP;
typedef void *PR_STRING;
static int lock_transaction, fail_begin, fail_delete, fail_commit, fail_add, active, saved, protected_id, aborts;
static void _r_obj_dereference(void *p) { (void)p; }
static PR_LIST _r_obj_createlist(unsigned n, void (*d)(void *)) { (void)n;(void)d;return calloc(1,sizeof(LIST)); }
static PR_ARRAY _r_obj_createarray(size_t n, unsigned c, void *d) { (void)n;(void)c;(void)d; ARRAY *a=calloc(1,sizeof(*a));a->items=a->storage;return a; }
static void _r_obj_addlistitem(PR_LIST l,void *p) { l->items[l->count++]=p; }
static unsigned _r_obj_getlistsize(PR_LIST l) { return l->count; }
static void *_r_obj_getlistitem(PR_LIST l,unsigned i) { assert(i<l->count);return l->items[i]; }
static void _r_obj_addarrayitems(PR_ARRAY a,GUID *p,unsigned n) { while(n--)a->items[a->count++]=*p++; }
static void _r_obj_cleararray(PR_ARRAY a) { a->count=0; }
static unsigned _r_obj_getarraysize(PR_ARRAY a) { return a->count; }
static void *_r_obj_getarrayitem(PR_ARRAY a,unsigned i) { assert(i<a->count);return &a->items[i]; }
static void _r_queuedlock_acquireexclusive(int *l) { assert(!*l);*l=1; }
static void _r_queuedlock_releaseexclusive(int *l) { assert(*l);*l=0; }
static void _app_setfiltersecurity(HANDLE h,LPCGUID id,int secure,LPCWSTR f,ULONG line) { (void)h;(void)f;(void)line;assert(lock_transaction && *id==1);protected_id=secure; }
static int _wfp_transact_start(HANDLE h,LPCWSTR f,ULONG l) { (void)h;(void)f;(void)l;saved=active;return !fail_begin; }
static void FwpmTransactionAbort0(HANDLE h) { (void)h;active=saved;++aborts; }
static int _wfp_transact_commit(HANDLE h,LPCWSTR f,ULONG l) { (void)f;(void)l;if(fail_commit){FwpmTransactionAbort0(h);return 0;}return 1; }
static int _wfp_deletefilter(HANDLE h,LPCGUID id,LPCWSTR f,ULONG l) { (void)h;(void)id;(void)f;(void)l;if(fail_delete)return 0;active=0;return 1; }
static void _r_log(int level,void *id,const wchar_t *title,int code,const wchar_t *desc) {(void)level;(void)id;(void)title;(void)code;(void)desc;}
static PR_STRING _app_getappdisplayname(APP *a,int b) { (void)a;(void)b;return NULL; }
static LPCWSTR _r_obj_getstring(PR_STRING s) { (void)s;return L"app"; }
static int _wfp_createrulefilter(HANDLE h,int t,LPCWSTR n,int hash,void *c,void *r,void *l,int w,int a,int flags,PR_ARRAY ids) {
 (void)h;(void)t;(void)n;(void)hash;(void)c;(void)r;(void)l;(void)w;(void)a;(void)flags;(void)ids;return !fail_add;
}
'''
tests = r'''
static void run(int begin,int deletion,int commit,int add) {
 ARRAY ids={0};ids.items=ids.storage;ids.items[ids.count++]=1;
 APP app={0};app.guids=&ids;app.is_enabled=add;
 LIST rules={0};rules.items[rules.count++]=&app;
 fail_begin=begin;fail_delete=deletion;fail_commit=commit;fail_add=add;
 active=protected_id=1;aborts=0;
 int success=_wfp_createappfilters_internal(NULL,&rules,L"test",1,0,NULL);
 assert(!lock_transaction);
 if(begin||deletion||commit||add) {
  assert(!success && app.is_haveerrors && ids.count==1 && ids.items[0]==1 && active && protected_id);
  assert(aborts==(begin?0:1));
 } else assert(success && !ids.count && !active);
}
int main(void) { run(1,0,0,0);run(0,1,0,0);run(0,0,1,0);run(0,0,0,1);run(0,0,0,0);
 puts("application filter transaction rollback checks passed");return 0; }
'''
with tempfile.TemporaryDirectory(prefix='simplewall-app-revoke-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(stubs + source[start:end] + tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Exercise special-target scope in the production rule builder with fake WFP.
# A zero hash would create a global filter, so it must never reach the builder.
source = (Path(__file__).resolve().parents[1] / 'src' / 'wfp.c').read_text()
start = source.index('static BOOLEAN _wfp_createrulefilters_internal (', source.index('BOOLEAN _wfp_createrulefilters ('))
brace = source.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1

scope_stubs = rule_stubs
scope_stubs = scope_stubs.replace('int type, weight, action, config; void *apps, *auto_apps;', 'int type, weight, action, config, hasauto; void *apps, *auto_apps;')
scope_stubs = scope_stubs.replace('static int _app_rule_hasauto(RULE *r) { (void)r; return 1; }', 'static int _app_rule_hasauto(RULE *r) { return r->hasauto; }')
scope_stubs = scope_stubs.replace('static int _app_rule_isglobal(RULE *r) { (void)r; return 0; }', 'typedef struct { unsigned count; ULONG_PTR keys[4]; } TABLE;\nstatic int _app_rule_isglobal(RULE *r) { TABLE *t=r->apps; return !r->hasauto && !t->count; }')
scope_stubs = scope_stubs.replace('static int _r_obj_enumhashtable(void *t, void *v, ULONG_PTR *h, ULONG_PTR *e) { (void)t;(void)v;(void)h;(void)e;return 0; }', 'static int _r_obj_enumhashtable(void *t, void *v, ULONG_PTR *h, ULONG_PTR *e) { TABLE *x=t;(void)v;if(*e>=x->count)return 0;*h=x->keys[(*e)++];return 1; }')
scope_stubs = scope_stubs.replace('static void *_r_obj_findhashtable(void *t, ULONG h) { (void)t;(void)h;return NULL; }', 'static void *_r_obj_findhashtable(void *t, ULONG h) { TABLE *x=t;for(unsigned i=0;i<x->count;i++)if(x->keys[i]==h)return x;return NULL; }')
scope_stubs = scope_stubs.replace('static int _wfp_createrulefilter(HANDLE h,int t,LPCWSTR n,ULONG hash,', 'static unsigned created[16], created_count;\nstatic int _wfp_createrulefilter(HANDLE h,int t,LPCWSTR n,ULONG hash,')
scope_stubs = scope_stubs.replace('(void)h;(void)t;(void)n;(void)hash;(void)c;(void)r;(void)l;(void)w;(void)a;(void)flags;(void)ids;return 1;', '(void)h;(void)t;(void)n;(void)c;(void)r;(void)l;(void)w;(void)a;(void)flags;(void)ids;assert(created_count<16);created[created_count++]=hash;return 1;')
scope_tests = r'''
static unsigned seen(unsigned hash) {
    unsigned count=0; for(unsigned i=0;i<created_count;i++) count += (created[i]==hash); return count;
}
static void check(unsigned driver,unsigned service,unsigned automatic,unsigned with_members) {
    ARRAY ids={0}; ids.items=ids.storage;
    TABLE explicit_apps={0}, auto_apps={0};
    RULE r={0}; r.guids=&ids; r.is_enabled=1; r.is_fordriver=driver; r.is_forservices=service;
    r.hasauto=automatic; r.apps=&explicit_apps; r.auto_apps=&auto_apps;
    if(with_members) {
        TABLE *t=automatic ? &auto_apps : &explicit_apps;
        t->keys[0]=1;t->keys[1]=2;t->keys[2]=3;t->count=3;
    }
    LIST rules={0};rules.items[rules.count++]=&r;
    config.ntoskrnl_hash=1;config.svchost_hash=2;created_count=0;
    assert(_wfp_createrulefilters_internal(NULL,&rules,L"test",1,1,NULL));
    if(with_members) assert(created_count==3 && seen(1)==1 && seen(2)==1 && seen(3)==1 && !seen(0));
    else if(driver || service) assert(created_count==driver+service && seen(1)==driver && seen(2)==service && !seen(0));
    else if(automatic) assert(!created_count);
    else assert(created_count==1 && seen(0)==1);
}
int main(void) {
    for(unsigned driver=0;driver<2;driver++) for(unsigned service=0;service<2;service++) {
        check(driver,service,0,1);check(driver,service,1,1);
        check(driver,service,0,0);check(driver,service,1,0);
    }
    ARRAY ids={0};ids.items=ids.storage;TABLE apps={0},auto_apps={0};
    RULE r={0};r.guids=&ids;r.is_enabled=r.is_fordriver=1;r.apps=&apps;r.auto_apps=&auto_apps;
    LIST rules={0};rules.items[rules.count++]=&r;
    config.ntoskrnl_hash=0;config.svchost_hash=2;created_count=0;
    assert(!_wfp_createrulefilters_internal(NULL,&rules,L"test",1,1,NULL) && r.is_haveerrors && !created_count);
    r.is_fordriver=0;r.is_forservices=1;config.svchost_hash=0;r.is_haveerrors=0;
    assert(!_wfp_createrulefilters_internal(NULL,&rules,L"test",1,1,NULL) && r.is_haveerrors && !created_count);
    r.is_forservices=0;apps.keys[0]=0;apps.count=1;r.is_haveerrors=0;
    assert(!_wfp_createrulefilters_internal(NULL,&rules,L"test",1,1,NULL) && r.is_haveerrors && !created_count);
    apps.count=0;auto_apps.keys[0]=0;auto_apps.count=1;r.hasauto=1;r.is_haveerrors=0;
    assert(!_wfp_createrulefilters_internal(NULL,&rules,L"test",1,1,NULL) && r.is_haveerrors && !created_count);
    config.ntoskrnl_hash=1;config.svchost_hash=2;r.is_fordriver=r.is_forservices=1;
    apps.keys[0]=1;apps.keys[1]=3;apps.count=2;auto_apps.keys[0]=1;auto_apps.keys[1]=2;auto_apps.keys[2]=3;auto_apps.count=3;
    r.is_haveerrors=0;created_count=0;
    assert(_wfp_createrulefilters_internal(NULL,&rules,L"test",1,1,NULL));
    assert(created_count==3 && seen(1)==1 && seen(2)==1 && seen(3)==1 && !seen(0));
    puts("special target scope, explicit members, zero-match and zero-hash checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-special-scope-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(scope_stubs + source[start:end] + scope_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Exercise the real install orchestration and filter builders with fake WFP.
def production_function(marker, start_at=0):
    start = source.index(marker, start_at)
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

rule_start = source.index('BOOLEAN _wfp_createrulefilters (')
app_start = source.index('BOOLEAN _wfp_createappfilters (')
production = '\n'.join([
    production_function('static VOID _wfp_snapshotfilterids ('),
    production_function('static BOOLEAN _wfp_createrulefilters_internal (', rule_start),
    production_function('static BOOLEAN _wfp_createappfilters_internal (', app_start),
    production_function('BOOLEAN _wfp_installfilters ('),
    production_function('BOOLEAN _wfp_destroyfilters ('),
])
install_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _Out_opt_
#endif
#define _In_
#define _Out_opt_
#define TRUE 1
#define FALSE 0
#define VOID void
#define FWP_ACTION_BLOCK 1
#define FWP_ACTION_PERMIT 2
#define FW_WEIGHT_APP 9
#define ERROR_SUCCESS 0
#define ERROR_NOT_FOUND 2
#define LOG_LEVEL_ERROR 1
#define DBG_ARG L"install-test", 1
#define DBG_ARG_VAR file_name, line
#define DIVIDER_RULE L"|"
#define _r_obj_isempty(p) (!(p) || !(p)->count)
#define _r_obj_isempty2(p) (!(p)->count)
typedef unsigned char BOOLEAN, *PBOOLEAN;
typedef unsigned ULONG, GUID;
typedef uintptr_t ULONG_PTR;
typedef const GUID *LPCGUID;
typedef const wchar_t *LPCWSTR;
typedef void *HANDLE, **PVOID_PTR;
typedef struct { unsigned count; GUID *items; GUID storage[32]; } ARRAY, *PR_ARRAY;
typedef struct { unsigned count; void *items[32]; } LIST, *PR_LIST;
typedef struct { unsigned length; } R_STRINGREF;
typedef struct { R_STRINGREF sr; } STRING, *PR_STRING;
typedef struct { PR_ARRAY guids; int is_enabled,is_haveerrors,type; ULONG_PTR app_hash; } APP, *PITEM_APP;
typedef struct { PR_ARRAY guids; int is_enabled,is_haveerrors,is_fordriver,is_forservices;
    int type,weight,action,config; void *apps,*auto_apps; PR_STRING name,rule_remote,rule_local; } RULE, *PITEM_RULE;
typedef struct { APP *apps[4]; unsigned count; } APP_TABLE;
static struct { ULONG_PTR ntoskrnl_hash,svchost_hash; } config;
static int lock_transaction,lock_autoallow,lock_apps,lock_rules,lock_autoapps;
static LIST all_rules; static APP_TABLE all_apps; static PR_LIST rules_list=&all_rules;
static APP_TABLE *apps_table=&all_apps;
static ARRAY global_ids; static PR_ARRAY filter_ids=&global_ids;
static const GUID GUID_WfpProvider=100,GUID_WfpSublayer=101;
static unsigned active,saved,protected_ids,commits,aborts,warnings,errors;
static int app_failure,block_failure,cleanup_failure,invalid_auto,destroy_failure,dump_failure,begin_failure,commit_failure;
static void _r_obj_dereference(void *p) {(void)p;}
static void *_r_obj_reference(void *p) {return p;}
static PR_ARRAY _r_obj_createarray(size_t size,unsigned capacity,void *cleanup) {
    (void)size;(void)capacity;(void)cleanup; PR_ARRAY a=calloc(1,sizeof(*a));a->items=a->storage;return a;
}
static PR_LIST _r_obj_createlist(unsigned capacity,void (*cleanup)(void *)) {(void)capacity;(void)cleanup;return calloc(1,sizeof(LIST));}
static void _r_obj_addlistitem(PR_LIST l,void *p) {assert(l->count<32);l->items[l->count++]=p;}
static unsigned _r_obj_getlistsize(PR_LIST l) {return l->count;}
static void *_r_obj_getlistitem(PR_LIST l,unsigned i) {assert(i<l->count);return l->items[i];}
static void _r_obj_clearlist(PR_LIST l) {l->count=0;}
static void _r_obj_addarrayitems(PR_ARRAY a,const GUID *p,unsigned n) {while(n--){assert(a->count<32);a->items[a->count++]=*p++;}}
static void _r_obj_cleararray(PR_ARRAY a) {a->count=0;}
static unsigned _r_obj_getarraysize(PR_ARRAY a) {return a->count;}
static void *_r_obj_getarrayitem(PR_ARRAY a,unsigned i) {assert(i<a->count);return &a->items[i];}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static void _r_queuedlock_acquireshared(int *l) {_r_queuedlock_acquireexclusive(l);}
static void _r_queuedlock_releaseshared(int *l) {_r_queuedlock_releaseexclusive(l);}
static int _r_obj_enumhashtablepointer(APP_TABLE *t,void **out,void *unused,ULONG_PTR *i) {
    (void)unused;if(*i>=t->count)return 0;*out=t->apps[(*i)++];return 1;
}
static int _r_obj_enumhashtable(void *t,void *v,ULONG_PTR *h,ULONG_PTR *i) {(void)t;(void)v;(void)h;(void)i;return 0;}
static void *_r_obj_findhashtable(void *t,ULONG_PTR h) {(void)t;(void)h;return NULL;}
static void _app_setprovidersecurity(HANDLE h,LPCGUID g,int v) {(void)h;(void)g;(void)v;}
static void _app_setsublayersecurity(HANDLE h,LPCGUID g,int v) {(void)h;(void)g;(void)v;}
static void _app_setfiltersecurity(HANDLE h,LPCGUID g,int v,LPCWSTR f,ULONG line) {
    (void)h;(void)f;(void)line;if(v)protected_ids|=1u<<*g;else protected_ids&=~(1u<<*g);
}
static void _app_rule_refresh_autoapps(RULE *r) {(void)r;}
static PR_LIST _wfp_snapshotautoapps(PR_LIST r) {(void)r;return _r_obj_createlist(1,NULL);}
static void _wfp_restoreautoapps(PR_LIST r,PR_LIST p) {(void)r;(void)p;}
static int _app_rule_hasauto(RULE *r) {(void)r;return invalid_auto;}
static int _app_rule_autoisvalid(RULE *r) {(void)r;return !invalid_auto;}
static int _app_rule_isglobal(RULE *r) {(void)r;return 1;}
static LPCWSTR _r_obj_getstring(PR_STRING p) {(void)p;return L"fixture";}
static int _r_obj_isstringempty(PR_STRING p) {return !p;}
static void _r_str_splitatchar(R_STRINGREF *a,wchar_t c,R_STRINGREF *b,R_STRINGREF *d) {(void)a;(void)c;b->length=d->length=0;}
static void _r_obj_initializestringrefempty(R_STRINGREF *p) {p->length=0;}
static void *_r_app_gethwnd(void) {return NULL;}
static PR_STRING _app_getappdisplayname(APP *a,int v) {(void)a;(void)v;return NULL;}
static void _r_log(int l,void *g,LPCWSTR t,int e,LPCWSTR d) {(void)l;(void)g;(void)t;(void)e;(void)d;errors++;}
static void _wfp_warnruleupdate(void *h) {(void)h;warnings++;}
static unsigned _wfp_dumpfilters(HANDLE h,LPCGUID provider,PR_ARRAY *out) {
    (void)h;(void)provider;*out=NULL;if(dump_failure)return 5;if(!active)return ERROR_NOT_FOUND;
    *out=_r_obj_createarray(sizeof(GUID),4,NULL);
    for(GUID i=0;i<16;i++)if(active&(1u<<i))_r_obj_addarrayitems(*out,&i,1);
    return ERROR_SUCCESS;
}
static int _wfp_transact_start(HANDLE h,LPCWSTR f,ULONG l) {(void)h;(void)f;(void)l;saved=active;return !begin_failure;}
static void FwpmTransactionAbort0(HANDLE h) {(void)h;active=saved;aborts++;}
static int _wfp_transact_commit(HANDLE h,LPCWSTR f,ULONG l) {(void)f;(void)l;commits++;if(commit_failure){FwpmTransactionAbort0(h);return 0;}return 1;}
static int _wfp_deletefilter(HANDLE h,LPCGUID id,LPCWSTR f,ULONG l) {
    (void)h;(void)f;(void)l;if(cleanup_failure && *id==3)return 0;active &= ~(1u<<*id);return 1;
}
static void add_filter(PR_ARRAY ids,GUID id) {active|=1u<<id;_r_obj_addarrayitems(ids,&id,1);}
static int _wfp_createrulefilter(HANDLE h,int t,LPCWSTR n,ULONG_PTR hash,void *cfg,R_STRINGREF *rem,R_STRINGREF *loc,int weight,int action,int flags,PR_ARRAY ids) {
    (void)h;(void)t;(void)n;(void)cfg;(void)rem;(void)loc;(void)weight;(void)flags;
    if(action==FWP_ACTION_BLOCK) {add_filter(ids,4);return !block_failure;}
    if(hash==99) {if(app_failure==2)add_filter(ids,3);return !app_failure;}
    add_filter(ids,2);return 1;
}
static int _wfp_destroyfilters_array(HANDLE h,PR_ARRAY ids,LPCWSTR f,ULONG line) {
    (void)h;(void)f;(void)line;
    if(destroy_failure)return FALSE;
    for(unsigned i=0;i<ids->count;i++)active &= ~(1u<<ids->items[i]);
    _r_obj_cleararray(ids);return TRUE;
}
static void _wfp_clearfilter_ids(void) {
    _r_obj_cleararray(filter_ids);
    for(unsigned i=0;i<all_apps.count;i++)_r_obj_cleararray(all_apps.apps[i]->guids);
    for(unsigned i=0;i<all_rules.count;i++)_r_obj_cleararray(((RULE *)all_rules.items[i])->guids);
}
static int _wfp_createglobalfilters(HANDLE h,LPCWSTR f,ULONG l,int t) {(void)h;(void)f;(void)l;(void)t;add_filter(filter_ids,5);return 1;}
'''
install_tests = r'''
static void reset(void) {
    all_apps.count=all_rules.count=0;global_ids.items=global_ids.storage;global_ids.count=0;
    active=saved=protected_ids=commits=aborts=warnings=errors=0;
    lock_transaction=lock_autoallow=lock_apps=lock_rules=lock_autoapps=0;
    app_failure=block_failure=cleanup_failure=invalid_auto=destroy_failure=dump_failure=begin_failure=commit_failure=0;
}
static void app_install(int mode,int fail_cleanup) {
    reset();ARRAY badids={0},goodids={0};badids.items=badids.storage;goodids.items=goodids.storage;
    APP bad={&badids,1,0,0,99},good={&goodids,1,0,0,7};
    all_apps.apps[all_apps.count++]=&bad;all_apps.apps[all_apps.count++]=&good;
    app_failure=mode;cleanup_failure=fail_cleanup;
    assert(!_wfp_installfilters(NULL));
    assert(!lock_transaction && !lock_autoallow && warnings==1 && errors>=1 && bad.is_haveerrors);
    if(fail_cleanup) {
        assert(aborts==1 && !commits && !active && !badids.count && !goodids.count && !global_ids.count);
    } else {
        assert(commits==1 && !aborts && active==((1u<<2)|(1u<<5)));
        assert(!badids.count && goodids.count==1 && global_ids.count==1);
        assert((protected_ids & active)==active);
    }
}
static void app_cleanup_old(void) {
    reset();ARRAY ids={0};ids.items=ids.storage;GUID old=1;_r_obj_addarrayitems(&ids,&old,1);
    APP app={&ids,1,0,0,99};all_apps.apps[all_apps.count++]=&app;
    active=protected_ids=1u<<1;app_failure=2;cleanup_failure=1;
    assert(!_wfp_installfilters(NULL));
    assert(!commits && aborts==1 && warnings==1 && app.is_haveerrors);
    assert(active==(1u<<1) && ids.count==1 && ids.items[0]==1 && (protected_ids&(1u<<1)));
}
static void block_install(int previous) {
    reset();ARRAY ids={0};ids.items=ids.storage;RULE r={0};r.guids=&ids;r.is_enabled=1;r.action=FWP_ACTION_BLOCK;
    if(previous) {GUID old=1;_r_obj_addarrayitems(&ids,&old,1);active=protected_ids=1u<<1;}
    all_rules.items[all_rules.count++]=&r;block_failure=1;
    assert(!_wfp_installfilters(NULL));
    assert(!lock_transaction && !lock_autoallow && !commits && aborts==1 && warnings==1 && r.is_haveerrors);
    assert(active==(previous ? (1u<<1) : 0));
    assert(ids.count==(unsigned)previous);
    if(previous)assert(ids.items[0]==1 && (protected_ids&(1u<<1)));
}
static void block_rebuild(void) {
    reset();ARRAY ids={0};ids.items=ids.storage;GUID old=1;_r_obj_addarrayitems(&ids,&old,1);
    RULE r={0};r.guids=&ids;r.is_enabled=1;r.action=FWP_ACTION_BLOCK;
    LIST rules={0};rules.items[rules.count++]=&r;active=protected_ids=1u<<1;block_failure=1;
    BOOLEAN fatal=FALSE;
    assert(!_wfp_createrulefilters_internal(NULL,&rules,L"test",1,FALSE,&fatal));
    assert(fatal && r.is_haveerrors && aborts==1 && !commits && active==(1u<<1));
    assert(ids.count==1 && ids.items[0]==1 && (protected_ids&(1u<<1)) && !lock_transaction);
}
static void invalid_block_rebuild(void) {
    reset();ARRAY ids={0};ids.items=ids.storage;GUID old=1;_r_obj_addarrayitems(&ids,&old,1);
    RULE r={0};r.guids=&ids;r.is_enabled=1;r.action=FWP_ACTION_BLOCK;
    LIST rules={0};rules.items[rules.count++]=&r;active=protected_ids=1u<<1;invalid_auto=1;
    BOOLEAN fatal=FALSE;
    assert(!_wfp_createrulefilters_internal(NULL,&rules,L"test",1,FALSE,&fatal));
    assert(fatal && r.is_haveerrors && aborts==1 && !commits && active==(1u<<1));
    assert(ids.count==1 && ids.items[0]==1 && (protected_ids&(1u<<1)));
}
static void zero_hash_install(void) {
    reset();ARRAY badids={0},goodids={0};badids.items=badids.storage;goodids.items=goodids.storage;
    APP bad={&badids,1,0,0,0},good={&goodids,1,0,0,7};
    all_apps.apps[all_apps.count++]=&bad;all_apps.apps[all_apps.count++]=&good;
    assert(!_wfp_installfilters(NULL));
    assert(commits==1 && !aborts && warnings==1 && bad.is_haveerrors && !badids.count);
    assert(active==((1u<<2)|(1u<<5)) && global_ids.count==1);
}
static void install_transaction_outcome(int fail_begin,int fail_commit) {
    reset();GUID old=1;_r_obj_addarrayitems(filter_ids,&old,1);active=protected_ids=1u<<1;
    begin_failure=fail_begin;commit_failure=fail_commit;
    assert(!_wfp_installfilters(NULL) && warnings==1 && active==(1u<<1));
    assert(filter_ids->count==1 && filter_ids->items[0]==1 && (protected_ids&(1u<<1)));
    assert(aborts==(unsigned)fail_commit && commits==(unsigned)!fail_begin);
}
static void destroy_outcome(void) {
    reset();ARRAY ids={0};ids.items=ids.storage;GUID old=1;_r_obj_addarrayitems(&ids,&old,1);
    APP app={&ids,1,0,0,7};all_apps.apps[all_apps.count++]=&app;active=protected_ids=1u<<1;
    destroy_failure=1;
    assert(!_wfp_destroyfilters(NULL) && warnings==1 && active==(1u<<1) && ids.count==1);
    destroy_failure=0;dump_failure=1;
    assert(!_wfp_destroyfilters(NULL) && warnings==2 && active==(1u<<1) && ids.count==1);
    dump_failure=0;
    assert(_wfp_destroyfilters(NULL) && !active && !ids.count);
    assert(_wfp_destroyfilters(NULL)); /* Already absent is success. */
}
int main(void) {
    destroy_outcome();
    install_transaction_outcome(1,0);
    install_transaction_outcome(0,1);
    reset();
    assert(_wfp_installfilters(NULL) && commits==1 && !aborts && !warnings && active==(1u<<5));
    app_install(1,0); /* Unresolvable app: default block and other apps commit. */
    app_install(2,0); /* Failed partial allow is removed before commit. */
    app_install(2,1); /* Failed cleanup aborts every staged filter. */
    app_cleanup_old(); /* Existing filters and ACL are restored on cleanup failure. */
    zero_hash_install(); /* Invalid application IDs never create a global permit. */
    block_install(0); /* First-install block failure never commits a partial policy. */
    block_install(1); /* Full rebuild restores the old block and its ACL. */
    block_rebuild();  /* A standalone rule update does the same. */
    invalid_block_rebuild(); /* Invalid block configuration also aborts. */
    puts("install app-failure recovery and block-rule rollback checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-install-rollback-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(install_stubs + production + install_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Exercise the production bounded status enumeration, including cleanup/error paths.
status_source = production_function('static ULONG _wfp_hasproviderfilters (') + '\n' + production_function('ENUM_INSTALL_TYPE _wfp_getinstalltype (')
status_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _Out_
#endif
#define _In_
#define _Out_
#define ERROR_SUCCESS 0
#define ERROR_NOT_FOUND 2
#define ERROR_INVALID_DATA 13
#define TRUE 1
#define FALSE 0
#define LOG_LEVEL_ERROR 1
typedef int ENUM_INSTALL_TYPE;
enum { INSTALL_DISABLED, INSTALL_ENABLED, INSTALL_ENABLED_TEMPORARY };
typedef unsigned char BOOLEAN,*PBOOLEAN;
typedef void *HANDLE,**PVOID_PTR;
typedef unsigned ULONG,UINT32,GUID;
typedef const GUID *LPCGUID;
typedef struct { GUID *providerKey; } FWPM_FILTER0;
static GUID GUID_WfpProvider=1, foreign_provider=2;
static FWPM_FILTER0 filters[1200],*page[64];
static int lock_transaction,provider,create_error,enum_error_call,destroy_error,malformed;
static int create_calls,enum_calls,destroy_calls,free_calls,warnings,logs;
static unsigned total,cursor,match_index;
static HANDLE _wfp_getenginehandle(void) {return NULL;}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static ENUM_INSTALL_TYPE _wfp_isproviderinstalled(HANDLE h) {(void)h;assert(lock_transaction);return provider;}
static ULONG FwpmFilterCreateEnumHandle0(HANDLE h,void *templ,HANDLE *out) {
 (void)h;assert(lock_transaction && !templ);create_calls++;*out=(HANDLE)(uintptr_t)1;return create_error;
}
static ULONG FwpmFilterEnum0(HANDLE h,HANDLE e,UINT32 requested,FWPM_FILTER0 ***out,UINT32 *count) {
 (void)h;(void)e;assert(lock_transaction && requested==64);enum_calls++;
 if(enum_calls==enum_error_call){*out=page;*count=0;return 5;}
 unsigned n=total-cursor;if(n>requested)n=requested;*count=n;
 if(malformed){*out=NULL;*count=1;return ERROR_SUCCESS;}
 for(unsigned i=0;i<n;i++) {
  unsigned idx=cursor+i;filters[idx].providerKey=idx==match_index?&GUID_WfpProvider:(idx%3?&foreign_provider:NULL);
  page[i]=&filters[idx];
 }
 cursor+=n;*out=n?page:NULL;return ERROR_SUCCESS;
}
static int IsEqualGUID(const GUID *a,const GUID *b) {return *a==*b;}
static void FwpmFreeMemory0(PVOID_PTR p) {assert(lock_transaction && *p==page);free_calls++;*p=NULL;}
static ULONG FwpmFilterDestroyEnumHandle0(HANDLE h,HANDLE e) {(void)h;(void)e;assert(lock_transaction);destroy_calls++;return destroy_error;}
static void *_r_app_gethwnd(void) {return NULL;}
static void _r_log(int l,void *g,const wchar_t *t,int e,void *d) {(void)l;(void)g;(void)t;(void)e;(void)d;assert(!lock_transaction);logs++;}
static void _wfp_warnruleupdate(void *h) {(void)h;assert(!lock_transaction);warnings++;}
'''
status_tests = r'''
static void reset(void) {
 provider=INSTALL_ENABLED;create_error=enum_error_call=destroy_error=malformed=0;
 create_calls=enum_calls=destroy_calls=free_calls=warnings=logs=0;
 total=cursor=0;match_index=999;
}
int main(void) {
 reset();assert(_wfp_getinstalltype()==INSTALL_DISABLED && enum_calls==1 && destroy_calls==1 && !warnings);
 reset();total=130;match_index=2;
 assert(_wfp_getinstalltype()==INSTALL_ENABLED && enum_calls==1 && cursor==64 && free_calls==1 && destroy_calls==1);
 reset();total=130;match_index=65;provider=INSTALL_ENABLED_TEMPORARY;
 assert(_wfp_getinstalltype()==INSTALL_ENABLED_TEMPORARY && enum_calls==2 && cursor==128 && free_calls==2);
 reset();total=1100;match_index=1000;
 assert(_wfp_getinstalltype()==INSTALL_ENABLED && enum_calls==16 && cursor==1024 && free_calls==16);
 reset();total=130;
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && enum_calls==3 && cursor==130 && free_calls==3 && !warnings);
 reset();total=64; /* An exact page requires a final empty read. */
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && enum_calls==2 && cursor==64 && free_calls==1 && !warnings);
 reset();create_error=5;
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && warnings==1 && logs==1 && !enum_calls && !destroy_calls);
 reset();total=130;enum_error_call=2;
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && warnings==1 && logs==1 && enum_calls==2 && free_calls==2 && destroy_calls==1);
 reset();malformed=1;
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && warnings==1 && destroy_calls==1);
 reset();total=1;match_index=0;destroy_error=5;
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && warnings==1 && free_calls==1 && destroy_calls==1);
 reset();provider=INSTALL_DISABLED;
 assert(_wfp_getinstalltype()==INSTALL_DISABLED && !create_calls && !warnings);
 assert(!lock_transaction);
 puts("bounded provider status pages, early exit and error cleanup passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-filter-status-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(status_stubs + status_source + status_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Run the real command callback and entry point with the routine SDK's callback
# contract modelled in memory; no Windows firewall APIs are invoked.
main_source = (Path(__file__).resolve().parents[1] / 'src' / 'main.c').read_text()
def main_function(marker):
    start = main_source.index(marker)
    brace = main_source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (main_source[end] == '{') - (main_source[end] == '}')
        end += 1
    return main_source[start:end]

cli_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#undef _In_opt_
#endif
#define _In_
#define _In_opt_
#define NTAPI
#define APIENTRY
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_GEN_FAILURE 31
#define ERROR_APP_INIT_FAILURE 575
#define ERROR_CANCELLED 1223
#define MB_OK 0
#define MB_ICONINFORMATION 0
#define IDD_MAIN 1
#define IDI_MAIN 2
#define IDA_MAIN 3
#define MAKEINTRESOURCE(i) ((void *)(uintptr_t)(i))
typedef unsigned char BOOLEAN;
typedef unsigned ULONG;
typedef int INT;
typedef void *HANDLE,*HWND,*HINSTANCE;
typedef wchar_t *LPWSTR;
typedef enum {CmdlineHelp,CmdlineInstall,CmdlineUninstall} R_CMDLINE_INFO_CLASS;
static ULONG command_exit_code = ERROR_APP_INIT_FAILURE;
static struct { int is_filterstemporary; } config;
static int mode, silent, confirmed, init_ok, install_ok, destroy_ok, cleanup_ok, filter_installed;
static int init_calls,install_calls,destroy_calls,cleanup_calls,prompts,windows_firewall_changes,app_init_calls,engine_calls,help_calls;
static void _app_initialize(void *h) {(void)h;app_init_calls++;}
static HANDLE _wfp_getenginehandle(void) {engine_calls++;return NULL;}
static void _r_show_message(void *h,int flags,const wchar_t *title,const wchar_t *message) {(void)h;(void)flags;(void)title;(void)message;help_calls++;}
static const wchar_t *_r_sys_getcommandline(void) {return L"fixture";}
static int _r_sys_getopt(const wchar_t *cmd,const wchar_t *opt,void *out) {
 (void)cmd;(void)out;return !wcscmp(opt,L"silent") ? silent : 0;
}
static int _app_installmessage(void *h,int installing) {
 (void)h;(void)installing;prompts++;if(confirmed)windows_firewall_changes++;return confirmed;
}
static void _app_profile_initialize(void) {}
static void _app_profile_load(void *h,void *p) {(void)h;(void)p;}
static int _wfp_initialize(void *h,HANDLE e) {(void)h;(void)e;init_calls++;return init_ok;}
static int _wfp_installfilters(HANDLE e) {(void)e;install_calls++;return install_ok;}
static int _wfp_uninitialize(HANDLE e,int full) {(void)e;cleanup_calls++;return full?cleanup_ok:TRUE;}
static int _wfp_destroyfilters(HANDLE e) {(void)e;destroy_calls++;return destroy_ok;}
static int _wfp_isfiltersinstalled(void) {return filter_installed;}
static int DlgProc;
static HWND _r_app_createwindow(HINSTANCE h,void *r,void *i,void *p) {(void)h;(void)r;(void)i;(void)p;assert(0);return NULL;}
static ULONG _r_wnd_message_callback(HWND h,void *r) {(void)h;(void)r;return 0;}
typedef BOOLEAN (*CMD_CALLBACK)(R_CMDLINE_INFO_CLASS);
static int _r_app_initialize(CMD_CALLBACK cb) {
    /* The adjacent routine SDK returns FALSE when the callback handles a command. */
    if(mode<0)return FALSE;
    return !cb(mode==0?CmdlineInstall:(mode==1?CmdlineUninstall:CmdlineHelp));
}
'''
cli_tests = r'''
static void reset(int command) {
 command_exit_code=ERROR_APP_INIT_FAILURE;mode=command;silent=1;confirmed=1;
 init_ok=install_ok=destroy_ok=cleanup_ok=filter_installed=1;
 init_calls=install_calls=destroy_calls=cleanup_calls=prompts=windows_firewall_changes=app_init_calls=engine_calls=help_calls=0;
}
static int run(void) {return wWinMain(NULL,NULL,NULL,0);}
int main(void) {
 reset(0);assert(run()==ERROR_SUCCESS && init_calls==1 && install_calls==1 && cleanup_calls==1);
 reset(0);init_ok=0;assert(run()==ERROR_GEN_FAILURE && !install_calls && cleanup_calls==1);
 reset(0);install_ok=0;assert(run()==ERROR_GEN_FAILURE && install_calls==1 && cleanup_calls==1);
 reset(0);silent=0;confirmed=0;assert(run()==ERROR_CANCELLED && prompts==1 && !install_calls);
 reset(1);assert(run()==ERROR_SUCCESS && destroy_calls==1 && cleanup_calls==1 && !prompts && !windows_firewall_changes);
 reset(1);filter_installed=0;assert(run()==ERROR_SUCCESS && destroy_calls==1 && cleanup_calls==1 && !prompts);
 reset(1);destroy_ok=0;assert(run()==ERROR_GEN_FAILURE && destroy_calls==1 && !cleanup_calls && !prompts);
 reset(1);cleanup_ok=0;assert(run()==ERROR_GEN_FAILURE && destroy_calls==1 && cleanup_calls==1 && !prompts);
 reset(1);silent=0;confirmed=0;assert(run()==ERROR_CANCELLED && prompts==1 && !destroy_calls);
 reset(2);assert(run()==ERROR_SUCCESS && help_calls==1 && !app_init_calls && !engine_calls);
 reset(-1);assert(run()==ERROR_APP_INIT_FAILURE);
 puts("command exit codes and silent uninstall checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-cli-status-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(cli_stubs + main_function('BOOLEAN NTAPI _app_parseargs (') + main_function('INT APIENTRY wWinMain (') + cli_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Check the real provider/sublayer cleanup outcome used by silent uninstall.
uninitialize_source = production_function('BOOLEAN _wfp_uninitialize (')
uninitialize_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#endif
#define _In_
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_NOT_FOUND 2
#define FWP_E_CALLOUT_NOT_FOUND 3
#define FWP_E_SUBLAYER_NOT_FOUND 4
#define FWP_E_PROVIDER_NOT_FOUND 5
#define FWP_UINT32 1
#define FWPM_ENGINE_COLLECT_NET_EVENTS 1
#define LOG_LEVEL_ERROR 1
#define DBG_ARG L"test", 1
#define RtlZeroMemory(p,n) memset((p),0,(n))
typedef unsigned char BOOLEAN;
typedef unsigned ULONG,GUID;
typedef uintptr_t ULONG_PTR;
typedef const wchar_t *LPCWSTR;
typedef void *HANDLE;
typedef GUID *LPGUID;
typedef const GUID *LPCGUID;
typedef void *PR_STRING;
typedef struct { unsigned count; GUID ids[2]; } ARRAY,*PR_ARRAY;
typedef struct {int type,uint32;} FWP_VALUE0;
static GUID GUID_WfpProvider,GUID_WfpSublayer,GUID_TrayIcon;
static struct {int is_neteventset,is_neteventenabled;} config;
static int lock_transaction,fail_dump,fail_begin,fail_sublayer,fail_provider,fail_commit;
static int aborts,commits,warnings,protect_provider,protect_sublayer;
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static void _wfp_logunsubscribe(HANDLE h) {(void)h;}
static ULONG FwpmEngineSetOption0(HANDLE h,int opt,FWP_VALUE0 *v) {(void)h;(void)opt;(void)v;return 0;}
static void _app_setprovidersecurity(HANDLE h,LPCGUID g,int v) {(void)h;(void)g;protect_provider=v;}
static void _app_setsublayersecurity(HANDLE h,LPCGUID g,int v) {(void)h;(void)g;protect_sublayer=v;}
static ULONG _wfp_dumpcallouts(HANDLE h,LPCGUID g,PR_ARRAY *out) {(void)h;(void)g;*out=NULL;return fail_dump?10:ERROR_NOT_FOUND;}
static unsigned _r_obj_getarraysize(PR_ARRAY a) {return a->count;}
static void *_r_obj_getarrayitem(PR_ARRAY a,unsigned i) {assert(i<a->count);return &a->ids[i];}
static void _app_setcalloutsecurity(HANDLE h,LPCGUID g,int v) {(void)h;(void)g;(void)v;}
static int _wfp_transact_start(HANDLE h,LPCWSTR f,ULONG l) {(void)h;(void)f;(void)l;return !fail_begin;}
static ULONG FwpmCalloutDeleteByKey0(HANDLE h,LPGUID g) {(void)h;(void)g;return 0;}
static void _r_str_fromguid(LPGUID g,int v,PR_STRING *s) {(void)g;(void)v;*s=NULL;}
static const wchar_t *_r_obj_getstring(PR_STRING s) {(void)s;return L"fixture";}
static void _r_obj_dereference(void *p) {(void)p;}
static void _r_log(int l,const GUID *g,const wchar_t *t,ULONG s,const wchar_t *d) {(void)l;(void)g;(void)t;(void)s;(void)d;}
static ULONG FwpmSubLayerDeleteByKey0(HANDLE h,LPCGUID g) {(void)h;(void)g;return fail_sublayer?10:0;}
static ULONG FwpmProviderDeleteByKey0(HANDLE h,LPCGUID g) {(void)h;(void)g;return fail_provider?10:0;}
static void FwpmTransactionAbort0(HANDLE h) {(void)h;aborts++;}
static int _wfp_transact_commit(HANDLE h,LPCWSTR f,ULONG l) {(void)f;(void)l;commits++;if(fail_commit){FwpmTransactionAbort0(h);return 0;}return 1;}
static void *_r_app_gethwnd(void) {return NULL;}
static void _wfp_warnruleupdate(void *h) {(void)h;assert(!lock_transaction);warnings++;}
'''
uninitialize_tests = r'''
static void run(int dump,int begin,int sublayer,int provider,int commit) {
 fail_dump=dump;fail_begin=begin;fail_sublayer=sublayer;fail_provider=provider;fail_commit=commit;
 aborts=commits=warnings=0;protect_provider=protect_sublayer=1;
 int ok=_wfp_uninitialize(NULL,TRUE);
 assert(!lock_transaction);
 if(dump||begin||sublayer||provider||commit) {
  assert(!ok && warnings==1 && protect_provider && protect_sublayer);
  assert(aborts==((sublayer||provider||commit)?1:0));
 } else assert(ok && !warnings && commits==1 && !aborts);
}
int main(void) {
 run(0,0,0,0,0);run(1,0,0,0,0);run(0,1,0,0,0);run(0,0,1,0,0);run(0,0,0,1,0);run(0,0,0,0,1);
 puts("provider cleanup status and failure rollback checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-uninitialize-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(uninitialize_stubs + uninitialize_source + uninitialize_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Verify the real app-filter entry point serializes with deletion and rejects
# stale objects, without taking the serialization lock across synchronous UI.
app_entry = production_function('BOOLEAN _wfp_createappfilters (')
app_entry_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#endif
#define _In_
#define TRUE 1
#define FALSE 0
#define DBG_ARG_VAR file_name, line
#define _r_obj_isempty(p) (!(p) || !(p)->count)
typedef unsigned char BOOLEAN;
typedef unsigned ULONG;
typedef uintptr_t ULONG_PTR;
typedef const wchar_t *LPCWSTR;
typedef void *HANDLE;
typedef struct {ULONG_PTR app_hash;int is_haveerrors;} APP,*PITEM_APP;
typedef struct {unsigned count;void *items[3];} LIST,*PR_LIST;
static int lock_autoallow,lock_apply,calls,ui_start,ui_end;
static APP *current;
static int _r_queuedlock_islocked(int *l) {return *l;}
static void _r_queuedlock_acquireexclusive(int *l) {assert(!*l);*l=1;}
static void _r_queuedlock_releaseexclusive(int *l) {assert(*l);*l=0;}
static void *_r_app_gethwnd(void) {return (void *)(uintptr_t)1;}
static int _app_initinterfacestate(void *h,int v) {(void)h;(void)v;assert(!lock_autoallow);ui_start++;return 1;}
static void _app_restoreinterfacestate(void *h,int v) {(void)h;(void)v;assert(!lock_autoallow);ui_end++;}
static unsigned _r_obj_getlistsize(PR_LIST l) {return l->count;}
static void *_r_obj_getlistitem(PR_LIST l,unsigned i) {assert(i<l->count);return l->items[i];}
static PITEM_APP _app_getappitem(ULONG_PTR hash) {(void)hash;assert(lock_autoallow);return current;}
static void _r_obj_dereference(void *p) {(void)p;}
static int _wfp_createappfilters_internal(HANDLE h,PR_LIST l,LPCWSTR f,ULONG n,int t,void *out) {
 (void)h;(void)l;(void)f;(void)n;(void)out;assert(t || lock_autoallow);calls++;return 1;
}
'''
app_entry_tests = r'''
int main(void) {
 APP app={7,0},replacement={7,0};LIST list={1,{&app}};
 current=&app;assert(_wfp_createappfilters(NULL,&list,L"test",1,FALSE) && calls==1 && !lock_autoallow);
 current=NULL;assert(!_wfp_createappfilters(NULL,&list,L"test",1,FALSE) && app.is_haveerrors && calls==1);
 app.is_haveerrors=0;current=&replacement;
 assert(!_wfp_createappfilters(NULL,&list,L"test",1,FALSE) && app.is_haveerrors && calls==1);
 assert(ui_start==3 && ui_end==3 && !lock_autoallow);
 puts("app filter rebuild serialization and stale-object checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-app-serialization-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(app_entry_stubs + app_entry + app_entry_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)


# Run the monitor drain and its actual main-window toggle/close branches with a
# fake message loop. Worker and queue state are controlled without WFP calls.
main_source = (Path(__file__).resolve().parents[1] / 'src' / 'main.c').read_text()
def main_case(marker, start):
    pos = main_source.index(marker, start)
    brace = main_source.index('{', pos)
    end, depth = brace + 1, 1
    while depth:
        depth += (main_source[end] == '{') - (main_source[end] == '}')
        end += 1
    return main_source[pos:end]

config_pos = main_source.index('VOID _app_config_apply (')
first_case = main_case('case IDM_USEAPPMONITOR_CHK:', config_pos)
second_case = main_case('case IDM_USEAPPMONITOR_CHK:', main_source.index(first_case, config_pos) + len(first_case))
close_case = main_case('case WM_CLOSE:', main_source.index('INT_PTR CALLBACK DlgProc ('))
monitor_funcs = '\n'.join(main_function(n) for n in (
    'static VOID _app_monitor_schedule_drain (',
    'static BOOLEAN _app_monitor_finish_drain (',
    'static BOOLEAN _app_monitor_start_checked (',
))
monitor_stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#define TRUE 1
#define FALSE 0
#define VOID void
#define APP_MONITOR_DRAIN_TIMER 91
#define LOG_LEVEL_ERROR 1
#define IDM_USEAPPMONITOR_CHK 2
#define WM_CLOSE 3
#define WM_NULL 0
#define MF_BYCOMMAND 0
#define DWLP_MSGRESULT 0
#define IDS_QUESTION_TIMER 1
#define IDS_QUESTION_EXIT 2
#define UNREFERENCED_PARAMETER(p) (void)(p)
typedef int BOOLEAN;typedef int32_t LONG;typedef unsigned UINT;typedef const wchar_t *LPCWSTR;
typedef void *HWND,*HMENU;
typedef struct {volatile int32_t busy_count;} QUEUE;
static QUEUE file_queue,wfp_queue;
static int monitor_disabling,monitor_closing,monitor_timer_failed;
static int busy,running,cfg=1,hashes=1,start_ok=1,stop_calls,starts,checked=1,menu_enabled=1,destroyed;
static int timer_ok=1,timers,kills,logs,applying,installed,confirm_ok=1,confirm_calls,posts;
static int GUID_TrayIcon;
static LONG InterlockedCompareExchange(volatile LONG *p,LONG v,LONG c) {LONG old=*p;if(old==c)*p=v;return old;}
static int SetTimer(HWND h,int id,int ms,void *cb) {(void)h;(void)id;(void)ms;(void)cb;timers++;return timer_ok;}
static int PostMessageW(HWND h,int msg,int w,int l) {(void)h;(void)msg;(void)w;(void)l;posts++;return 1;}
static int KillTimer(HWND h,int id) {(void)h;(void)id;kills++;return 1;}
static unsigned GetLastError(void) {return 5;}
static void _r_log(int l,void *g,const wchar_t *t,int code,void *d) {(void)l;(void)g;(void)t;(void)code;(void)d;logs++;}
static int _app_monitor_isbusy(void) {return busy;}
static int _app_monitor_isrunning(void) {return running;}
static void _app_monitor_stop(void) {stop_calls++;running=0;}
static void _app_fileloggingenable(void) {starts++;running=start_ok;}
static int _wfp_isfiltersapplying(void) {return applying;}
static int DestroyWindow(HWND h) {(void)h;assert(!busy && !file_queue.busy_count && !wfp_queue.busy_count && !applying);destroyed++;return 1;}
static HMENU GetMenu(HWND h) {(void)h;return (void *)(uintptr_t)1;}
static void _r_menu_checkitem(HMENU h,int id,int p,int flags,int value) {(void)h;(void)id;(void)p;(void)flags;checked=value;}
static void _r_menu_enableitem(HMENU h,int id,int p,int value) {(void)h;(void)id;(void)p;menu_enabled=value;}
static int _r_config_getboolean(const wchar_t *name,int fallback) {(void)fallback;return !wcscmp(name,L"IsHashesEnabled")?hashes:cfg;}
static void _r_config_setboolean(const wchar_t *name,int value) {(void)name;cfg=value;}
static int _wfp_isfiltersinstalled(void) {return installed;}
static int _app_istimersactive(void) {return 0;}
static const wchar_t *_r_locale_getstring(UINT i) {(void)i;return L"fixture";}
static int _r_show_confirmmessage(HWND h,const wchar_t *a,void *b,LPCWSTR c,int d) {(void)h;(void)a;(void)b;(void)c;(void)d;confirm_calls++;return confirm_ok;}
static void SetWindowLongPtrW(HWND h,int i,int v) {(void)h;(void)i;(void)v;}
'''
monitor_wrappers = ("\nstatic void toggle(HWND hwnd) { HMENU hmenu=GetMenu(hwnd); BOOLEAN new_val=FALSE; "
    "switch(IDM_USEAPPMONITOR_CHK) {" + first_case + "} switch(IDM_USEAPPMONITOR_CHK) {" + second_case + "} }\n"
    "static int close_event(HWND hwnd) { switch(WM_CLOSE) {" + close_case + "} return FALSE; }\n")
monitor_tests = r'''
static void reset(void) {
 monitor_disabling=monitor_closing=monitor_timer_failed=0;
 busy=0;running=cfg=hashes=start_ok=checked=menu_enabled=timer_ok=confirm_ok=1;
 stop_calls=starts=destroyed=timers=kills=logs=applying=installed=confirm_calls=posts=0;
 file_queue.busy_count=wfp_queue.busy_count=0;
}
int main(void) {
 HWND h=(void *)(uintptr_t)1;
 reset();busy=1;toggle(h);
 assert(!cfg && !running && monitor_disabling && stop_calls==1 && checked && !menu_enabled && timers);
 toggle(h);assert(!starts && monitor_disabling); /* Cannot restart before drain. */
 busy=0;_app_monitor_finish_drain(h);
 assert(!monitor_disabling && !checked && menu_enabled && !destroyed);
 toggle(h);assert(cfg && running && starts==1 && checked);
 reset();cfg=0;running=0;busy=1;checked=0;toggle(h);
 assert(!cfg && !running && monitor_disabling && !starts && stop_calls==1 && !menu_enabled);
 toggle(h);assert(!starts); /* A stale generation cannot be restarted. */
 busy=0;_app_monitor_finish_drain(h);toggle(h);
 assert(cfg && running && starts==1 && checked);
 reset();cfg=0;running=0;busy=1;
 assert(!_app_monitor_start_checked(h) && !cfg && !starts);
 reset();cfg=0;running=0;start_ok=0;toggle(h);
 assert(!cfg && !running && !checked && logs==1); /* Failed startup. */
 reset();busy=1;installed=1;close_event(h);
 assert(monitor_closing && !running && stop_calls==1 && confirm_calls==1 && !destroyed && cfg);
 close_event(h);assert(stop_calls==1 && confirm_calls==1);
 busy=0;file_queue.busy_count=1;_app_monitor_finish_drain(h);assert(!destroyed);
 file_queue.busy_count=0;wfp_queue.busy_count=1;_app_monitor_finish_drain(h);assert(!destroyed);
 wfp_queue.busy_count=0;applying=1;_app_monitor_finish_drain(h);assert(!destroyed);
 applying=0;assert(_app_monitor_finish_drain(h) && destroyed==1);
 reset();busy=1;timer_ok=0;close_event(h);
 assert(monitor_closing && !destroyed && monitor_timer_failed && logs==1 && posts==1);
 timer_ok=1;busy=0;assert(_app_monitor_finish_drain(h) && destroyed==1);
 reset();installed=1;confirm_ok=0;assert(close_event(h) && !stop_calls && !destroyed && !monitor_closing);
 reset();assert(close_event(h) && stop_calls==1 && destroyed==1 && cfg);
 puts("monitor disable, shutdown drain, start failure and timer failure checks passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-monitor-ui-') as td:
    src = Path(td) / 'test.c'
    exe = Path(td) / 'test.exe'
    src.write_text(monitor_stubs + monitor_funcs + monitor_wrappers + monitor_tests)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
