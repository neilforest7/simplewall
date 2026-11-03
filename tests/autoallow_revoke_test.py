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
start = source.index('BOOLEAN _wfp_createappfilters (')
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
#endif
#define _In_
#define TRUE 1
#define FALSE 0
#define DBG_ARG_VAR file_name, line
#define _r_obj_isempty(p) (!(p) || !(p)->count)
#define FW_WEIGHT_APP 1
#define FWP_ACTION_PERMIT 1
typedef unsigned char BOOLEAN;
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
static void *_r_app_gethwnd(void) { return NULL; }
static int _app_initinterfacestate(void *h,int f) { (void)h;(void)f;return 1; }
static void _app_restoreinterfacestate(void *h,int f) { (void)h;(void)f;assert(!lock_transaction); }
static void _r_queuedlock_acquireexclusive(int *l) { assert(!*l);*l=1; }
static void _r_queuedlock_releaseexclusive(int *l) { assert(*l);*l=0; }
static void _app_setfiltersecurity(HANDLE h,LPCGUID id,int secure,LPCWSTR f,ULONG line) { (void)h;(void)f;(void)line;assert(lock_transaction && *id==1);protected_id=secure; }
static int _wfp_transact_start(HANDLE h,LPCWSTR f,ULONG l) { (void)h;(void)f;(void)l;saved=active;return !fail_begin; }
static void FwpmTransactionAbort0(HANDLE h) { (void)h;active=saved;++aborts; }
static int _wfp_transact_commit(HANDLE h,LPCWSTR f,ULONG l) { (void)f;(void)l;if(fail_commit){FwpmTransactionAbort0(h);return 0;}return 1; }
static int _wfp_deletefilter(HANDLE h,LPCGUID id,LPCWSTR f,ULONG l) { (void)h;(void)id;(void)f;(void)l;if(fail_delete)return 0;active=0;return 1; }
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
 int success=_wfp_createappfilters(NULL,&rules,L"test",1,0);
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
