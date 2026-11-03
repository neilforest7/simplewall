"""Isolated Windows checks for monitor drain and hash-baseline ownership.

Run with MSVC on PATH: python tests/monitor_hash_lock_test.py
No simplewall process, profile, or firewall is used.
"""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'src' / 'helper.c').read_text(encoding='utf-8')

def get_function(signature):
    start = source.index(signature)
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

start = source.index('// The session owns its stop event')
timer_start = source.index('NTSTATUS NTAPI _app_timercallback (', start)
timer_function = get_function('NTSTATUS NTAPI _app_timercallback (')
hash_function = get_function('PR_STRING _app_getfilehashinfo (')
assert '_r_workqueue_queueitem' not in timer_function

stubs = r'''
#include <windows.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define INFO_DISABLE 1
#define STATUS_SUCCESS 0
#define NtCurrentProcess() GetCurrentProcess()
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#define NT_SUCCESS(s) ((s) >= 0)
typedef LONG NTSTATUS;
typedef struct { const char *sr; } STRING, *PR_STRING;
typedef struct { ULONG_PTR app_hash; PR_STRING hash; int is_autoallow_blocked; PR_STRING real_path; } ITEM_APP, *PITEM_APP;
typedef void *PR_LIST;
static SRWLOCK lock_apps = SRWLOCK_INIT, lock_autoallow = SRWLOCK_INIT;
static HANDLE hash_entered, hash_continue, change_complete;
static PITEM_APP apps_table, list_app;
static int changes, enabled, starts, fail_start;
static STRING produced_hash = {"new"};
static void *last_thread_context;
static NTSTATUS NTAPI _app_timercallback(void *context);
static int _r_config_getboolean(const wchar_t *name, int def) { (void)name; (void)def; return enabled; }
static void *_r_mem_allocate(size_t n) { void *p = malloc(n); assert(p); return p; }
static void _r_mem_free(void *p) { free(p); }
static NTSTATUS _r_sys_createthread(void *out, HANDLE proc, NTSTATUS (NTAPI *fn)(void *), void *arg, void *env, const wchar_t *name) {
    (void)out; (void)proc; (void)fn; (void)env; (void)name;
    starts++; last_thread_context = arg; return fail_start ? -1 : 0;
}
static void _r_queuedlock_acquireexclusive(SRWLOCK *lock) { AcquireSRWLockExclusive(lock); }
static void _r_queuedlock_releaseexclusive(SRWLOCK *lock) { ReleaseSRWLockExclusive(lock); }
static void _r_queuedlock_acquireshared(SRWLOCK *lock) { AcquireSRWLockShared(lock); }
static void _r_queuedlock_releaseshared(SRWLOCK *lock) { ReleaseSRWLockShared(lock); }
static PITEM_APP _r_obj_findhashtablepointer(PITEM_APP table, ULONG_PTR key) {
    return table && table->app_hash == key ? table : NULL;
}
static PITEM_APP _app_getappitem(ULONG_PTR key) {
    PITEM_APP item; AcquireSRWLockShared(&lock_apps);
    item = _r_obj_findhashtablepointer(apps_table, key);
    ReleaseSRWLockShared(&lock_apps); return item;
}
static int _r_str_isequal(const char **a, const char **b, int ignorecase) {
    (void)ignorecase; return strcmp(*a, *b) == 0;
}
static void _r_obj_movereference(PR_STRING *slot, PR_STRING value) { *slot = value; }
static void _r_obj_dereference(void *p) { (void)p; }
static void *_r_obj_reference(void *p) { return p; }
static void *_r_obj_referencesafe(void *p) { return p; }
static PR_LIST _r_obj_createlist(int size, void (*cleanup)(void *)) { (void)size; (void)cleanup; return (void *)1; }
static int _r_obj_enumhashtablepointer(PITEM_APP table, PITEM_APP *app, void *value, ULONG_PTR *key) {
    (void)value; if (*key == 0 && table) { *app = table; (*key)++; return 1; } return 0;
}
static void _r_obj_addlistitem(PR_LIST list, void *item) { (void)list; list_app = item; }
static size_t _r_obj_getlistsize(PR_LIST list) { (void)list; return list_app ? 1 : 0; }
static void *_r_obj_getlistitem(PR_LIST list, ULONG_PTR i) { (void)list; (void)i; return list_app; }
static int _app_isappvalidbinary(PR_STRING s) { return s != NULL; }
static int _app_isappused(PITEM_APP app) { (void)app; return 1; }
static NTSTATUS _r_crypt_getfilehash(const wchar_t *alg, const char **path, HANDLE file, PR_STRING *hash) {
    (void)alg;
    if (path) { SetEvent(hash_entered); assert(WaitForSingleObject(hash_continue, 5000) == WAIT_OBJECT_0); }
    else { assert(file); }
    *hash = &produced_hash; return 0;
}
static DWORD _r_calc_minutes2milliseconds(DWORD n) { return n * 60000; }
static HWND _r_app_gethwnd(void) { return NULL; }
static void _app_setappinfo(PITEM_APP app, int info, void *value) { (void)app; (void)info; (void)value; changes++; }
static void _app_autoallow_refresh(HWND hwnd) { (void)hwnd; changes++; }
static void _app_profile_save(HWND hwnd) { (void)hwnd; changes++; SetEvent(change_complete); }
'''
test = r'''
static DWORD WINAPI run_monitor(void *arg) { return (DWORD)_app_timercallback(arg); }
static HANDLE start_monitor(void) {
    HANDLE worker;
    _app_fileloggingenable(); assert(_app_monitor_isrunning());
    worker = CreateThread(NULL, 0, run_monitor, last_thread_context, 0, NULL);
    assert(worker && WaitForSingleObject(hash_entered, 5000) == WAIT_OBJECT_0);
    return worker;
}
static void stop_and_join(HANDLE worker) {
    _app_monitor_stop();
    assert(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
    assert(!_app_monitor_isbusy()); CloseHandle(worker);
}
static void reset_events(void) { ResetEvent(hash_entered); ResetEvent(hash_continue); ResetEvent(change_complete); }
int main(void) {
    STRING old_hash = {"old"}, later_hash = {"later"};
    ITEM_APP app = {1, &old_hash, 0, &old_hash};
    PR_STRING info;
    HANDLE worker;
    apps_table = &app;
    hash_entered = CreateEventW(NULL, TRUE, FALSE, NULL); assert(hash_entered);
    hash_continue = CreateEventW(NULL, TRUE, FALSE, NULL); assert(hash_continue);
    change_complete = CreateEventW(NULL, TRUE, FALSE, NULL); assert(change_complete);
    enabled = 1;

    /* Background info refresh while hashing must preserve the old baseline. */
    worker = start_monitor();
    info = _app_getfilehashinfo((HANDLE)1, 1);
    assert(info == &produced_hash && app.hash == &old_hash);
    SetEvent(hash_continue);
    assert(WaitForSingleObject(change_complete, 5000) == WAIT_OBJECT_0);
    assert(app.hash == &produced_hash && app.is_autoallow_blocked && changes == 3);
    stop_and_join(worker);

    /* A concurrent writer installing the new hash cannot swallow the change. */
    reset_events(); app.hash = &old_hash; app.is_autoallow_blocked = 0; changes = 0;
    worker = start_monitor();
    AcquireSRWLockExclusive(&lock_apps); app.hash = &produced_hash; ReleaseSRWLockExclusive(&lock_apps);
    SetEvent(hash_continue);
    assert(WaitForSingleObject(change_complete, 5000) == WAIT_OBJECT_0);
    assert(app.hash == &produced_hash && app.is_autoallow_blocked && changes == 3);
    stop_and_join(worker);

    /* A newer different hash must also be preserved. */
    reset_events(); app.hash = &old_hash; app.is_autoallow_blocked = 0; changes = 0;
    worker = start_monitor();
    AcquireSRWLockExclusive(&lock_apps); app.hash = &later_hash; ReleaseSRWLockExclusive(&lock_apps);
    SetEvent(hash_continue);
    assert(WaitForSingleObject(change_complete, 5000) == WAIT_OBJECT_0);
    assert(app.hash == &later_hash && app.is_autoallow_blocked && changes == 3);
    stop_and_join(worker);

    /* Stop during file IO, refuse restart until the old thread has drained. */
    reset_events(); app.hash = &old_hash; app.is_autoallow_blocked = 0; changes = 0;
    worker = start_monitor();
    _app_monitor_stop(); assert(_app_monitor_isbusy());
    { int old_starts = starts; _app_fileloggingenable(); assert(starts == old_starts && !_app_monitor_isrunning()); }
    assert(WaitForSingleObject(worker, 0) == WAIT_TIMEOUT);
    SetEvent(hash_continue);
    assert(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
    assert(!_app_monitor_isbusy() && changes == 0 && app.hash == &old_hash);
    CloseHandle(worker);

    reset_events(); worker = start_monitor(); _app_monitor_stop(); SetEvent(hash_continue);
    assert(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
    assert(!_app_monitor_isbusy() && changes == 0); CloseHandle(worker);
    fail_start = 1; _app_fileloggingenable();
    assert(!_app_monitor_isrunning() && !_app_monitor_isbusy());
    CloseHandle(hash_entered); CloseHandle(hash_continue); CloseHandle(change_complete);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-monitor-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(stubs + hash_function + source[start:timer_start] + timer_function + test, encoding='utf-8')
    subprocess.run(['cl', '/nologo', '/W4', '/WX', 'test.c', '/Fe:test.exe'], cwd=path, check=True)
    subprocess.run([str(path / 'test.exe')], cwd=path, check=True)
print('monitor baseline, concurrent refresh, stop and restart: passed')

# Verify the actual routine helper's NULL-handle convention, independently of
# the monitor harness above. Windows thread APIs are exercised through small native API shims.
routine = (Path(__file__).resolve().parents[2] / 'routine' / 'src' / 'routine.c').read_text(encoding='utf-8')
start = routine.index('NTSTATUS _r_sys_createthread (')
brace = routine.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (routine[end] == '{') - (routine[end] == '}')
    end += 1
thread_stubs = r'''
#include <windows.h>
#include <assert.h>
#define NT_SUCCESS(s) ((s) >= 0)
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 1
#define WINDOWS_10 10
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(PVOID);
typedef struct { PUSER_THREAD_START_ROUTINE base_address; PVOID arglist; } FAKE_THREAD_CONTEXT, *PR_THREAD_CONTEXT;
typedef void *PR_FREE_LIST;
typedef void *PR_ENVIRONMENT;
static FAKE_THREAD_CONTEXT fake_context;
static int resumed, closed, deleted, fail_create;
static NTSTATUS NTAPI _r_sys_basethreadstart(PVOID arg) {
    PR_THREAD_CONTEXT c = arg; return c->base_address(c->arglist);
}
static DWORD WINAPI fake_thread_start(void *arg) { return (DWORD)_r_sys_basethreadstart(arg); }
static NTSTATUS NTAPI signal_started(PVOID arg) { SetEvent((HANDLE)arg); return 0; }
static PR_FREE_LIST _r_sys_getthreadfreelist(void) { return &fake_context; }
static PR_THREAD_CONTEXT _r_freelist_allocateitem(PR_FREE_LIST list) { (void)list; return &fake_context; }
static void _r_freelist_deleteitem(PR_FREE_LIST list, PR_THREAD_CONTEXT item) { (void)list; (void)item; deleted++; }
static NTSTATUS NtCreateThreadEx(PHANDLE out, ULONG access, void *attributes, HANDLE process,
    PUSER_THREAD_START_ROUTINE start, void *arg, ULONG flags, SIZE_T zero, SIZE_T stack, SIZE_T max, void *attrs) {
    (void)access; (void)attributes; (void)process; (void)start; (void)arg; (void)zero; (void)stack; (void)max; (void)attrs;
    assert(flags == THREAD_CREATE_FLAGS_CREATE_SUSPENDED);
    if (fail_create) return -1;
    *out = CreateThread(NULL, 0, fake_thread_start, arg, CREATE_SUSPENDED, NULL);
    return *out ? 0 : -1;
}
static NTSTATUS NtResumeThread(HANDLE h, void *previous) { (void)previous; resumed++; return ResumeThread(h) == (DWORD)-1 ? -1 : 0; }
static NTSTATUS NtClose(HANDLE h) { closed++; return CloseHandle(h) ? 0 : -1; }
static void _r_sys_setthreadenvironment(HANDLE h, PR_ENVIRONMENT env) { (void)h; (void)env; }
static int _r_sys_isosversiongreaterorequal(int version) { (void)version; return 0; }
static void _r_sys_setthreadname(HANDLE h, LPCWSTR name) { (void)h; (void)name; }
'''
thread_test = r'''
int main(void) {
    HANDLE thread = NULL, started = CreateEventW(NULL, TRUE, FALSE, NULL); assert(started);
    assert(NT_SUCCESS(_r_sys_createthread(NULL, NULL, signal_started, started, NULL, NULL)));
    assert(resumed == 1 && closed == 1 && WaitForSingleObject(started, 5000) == WAIT_OBJECT_0);
    ResetEvent(started);
    assert(NT_SUCCESS(_r_sys_createthread(&thread, NULL, signal_started, started, NULL, NULL)));
    assert(thread && resumed == 1 && closed == 1);
    assert(WaitForSingleObject(started, 0) == WAIT_TIMEOUT);
    assert(ResumeThread(thread) != (DWORD)-1);
    assert(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
    assert(WaitForSingleObject(started, 0) == WAIT_OBJECT_0);
    CloseHandle(thread);
    fail_create = 1; thread = (HANDLE)1;
    assert(!NT_SUCCESS(_r_sys_createthread(&thread, NULL, signal_started, started, NULL, NULL)));
    assert(!thread && deleted == 1 && resumed == 1 && closed == 1);
    CloseHandle(started);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-thread-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(thread_stubs + routine[start:end] + thread_test, encoding='utf-8')
    subprocess.run(['cl', '/nologo', '/W4', '/WX', 'test.c', '/Fe:test.exe'], cwd=path, check=True)
    subprocess.run([str(path / 'test.exe')], cwd=path, check=True)
print('thread helper resumes and closes its internally owned handle: passed')

# Exercise the real hash helper's ownership and replacement behavior.
start = source.index('PR_STRING _app_getfilehashinfo (')
brace = source.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
hash_stubs = r'''
#include <windows.h>
#include <assert.h>
#include <string.h>
#define NT_SUCCESS(s) ((s) >= 0)
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
typedef LONG NTSTATUS;
typedef struct { int refs; const char *value; } STRING, *PR_STRING;
typedef struct { int refs; ULONG_PTR app_hash; PR_STRING hash; } ITEM_APP, *PITEM_APP;
static SRWLOCK lock_apps = SRWLOCK_INIT;
static PITEM_APP apps_table, replacement;
static STRING new_hash = {0, "new"};
static int mode;
static void *_r_obj_reference(void *p) { assert(p); (*(int *)p)++; return p; }
static void _r_obj_dereference(void *p) { assert(p && *(int *)p > 0); (*(int *)p)--; }
static void _r_queuedlock_acquireexclusive(SRWLOCK *l) { AcquireSRWLockExclusive(l); }
static void _r_queuedlock_releaseexclusive(SRWLOCK *l) { ReleaseSRWLockExclusive(l); }
static PITEM_APP _r_obj_findhashtablepointer(PITEM_APP app, ULONG_PTR key) {
    return app && app->app_hash == key ? _r_obj_reference(app) : NULL;
}
static PITEM_APP _app_getappitem(ULONG_PTR key) {
    PITEM_APP app; AcquireSRWLockShared(&lock_apps);
    app = _r_obj_findhashtablepointer(apps_table, key);
    ReleaseSRWLockShared(&lock_apps); return app;
}
static void _r_obj_movereference(PR_STRING *slot, void *value) {
    assert(!TryAcquireSRWLockShared(&lock_apps));
    if (*slot) _r_obj_dereference(*slot); *slot = value;
}
static NTSTATUS _r_crypt_getfilehash(const wchar_t *alg, void *path, HANDLE file, PR_STRING *out) {
    (void)alg; (void)path; (void)file;
    assert(TryAcquireSRWLockExclusive(&lock_apps)); ReleaseSRWLockExclusive(&lock_apps);
    if (mode == 1) return -1;
    if (mode == 2) { AcquireSRWLockExclusive(&lock_apps); apps_table = replacement; ReleaseSRWLockExclusive(&lock_apps); }
    new_hash.refs = 1; *out = &new_hash; return 0;
}
'''
hash_test = r'''
int main(void) {
    STRING old_hash = {1, "old"}, later = {1, "later"};
    ITEM_APP app = {1, 1, &old_hash}, other = {1, 1, NULL};
    PR_STRING retained;
    apps_table = &app; replacement = &other;
    retained = _app_getfilehashinfo(NULL, 1);
    assert(retained == &new_hash && new_hash.refs == 1 && app.hash == &old_hash && old_hash.refs == 1 && app.refs == 1);
    _r_obj_dereference(retained); assert(new_hash.refs == 0);
    AcquireSRWLockExclusive(&lock_apps); _r_obj_movereference(&app.hash, NULL); ReleaseSRWLockExclusive(&lock_apps);
    retained = _app_getfilehashinfo(NULL, 1);
    assert(retained == &new_hash && new_hash.refs == 2 && app.hash == &new_hash && old_hash.refs == 0);
    AcquireSRWLockExclusive(&lock_apps); _r_obj_movereference(&app.hash, &later); ReleaseSRWLockExclusive(&lock_apps);
    assert(new_hash.refs == 1 && strcmp(retained->value, "new") == 0);
    _r_obj_dereference(retained); assert(new_hash.refs == 0);
    mode = 1; assert(!_app_getfilehashinfo(NULL, 1));
    assert(app.hash == &later && later.refs == 1 && app.refs == 1);
    mode = 2; assert(!_app_getfilehashinfo(NULL, 1));
    assert(app.hash == &later && !other.hash && new_hash.refs == 0 && app.refs == 1 && other.refs == 1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-hash-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(hash_stubs + source[start:end] + hash_test, encoding='utf-8')
    subprocess.run(['cl', '/nologo', '/W4', '/WX', 'test.c', '/Fe:test.exe'], cwd=path, check=True)
    subprocess.run([str(path / 'test.exe')], cwd=path, check=True)
print('hash reference lifetime, failed hashing, and removed app: passed')
