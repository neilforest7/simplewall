#!/usr/bin/env python3
"""Exercise the real platform-independent rule guards with small API stubs.

This does not simulate Windows trust or WFP. The Windows matcher test covers
matching; these checks cover the security boundary between derived scope,
manual associations, and a legacy global rule, without requiring a Windows SDK.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'src' / 'profile.c').read_text()
db_source = (ROOT / 'src' / 'db.c').read_text()
save_start = db_source.index('NTSTATUS _app_db_savetofile (')
save_end = db_source.index('VOID _app_db_save_app (', save_start)
save_call = db_source[save_start:save_end]
assert save_call.index('_r_queuedlock_acquireshared (&lock_autoallow)') < save_call.index('_app_db_save_app (db_info)') < save_call.index('_app_db_save_rule (db_info)') < save_call.index('_r_queuedlock_releaseshared (&lock_autoallow)')

FUNCTIONS = (
    '_app_rule_hasauto', '_app_rule_autoisvalid', '_app_rule_isglobal',
    '_app_rule_issystemapp', '_app_rule_containsapp', '_app_rule_matchapp',
)


def function_source(name, source=SOURCE, return_type='BOOLEAN'):
    start = source.index(return_type + ' ' + name + ' (')
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


STUBS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#endif
#define _In_
#ifdef _Inout_
#undef _Inout_
#endif
#define _Inout_
#define VOID void
#define FWP_DIRECTION_OUTBOUND 0
#define AF_UNSPEC 0
#define DIVIDER_APP L"|"
#define TRUE 1
#define FALSE 0
#define DATA_RULE_USER 10
#define FWP_ACTION_PERMIT 1
#define FWP_ACTION_BLOCK 2
#define DATA_APP_REGULAR 1
#define DATA_APP_SERVICE 4
#define DATA_APP_UWP 5
#define DATA_APP_NETWORK 3
#define DATA_APP_DEVICE 2
#define DATA_APP_PICO 6
typedef unsigned char BOOLEAN;
typedef uint32_t ULONG;
typedef uintptr_t ULONG_PTR;
typedef struct { const wchar_t *buffer; size_t sr; } STRING, *PR_STRING;
typedef struct { unsigned keys; } TABLE, *PR_HASHTABLE;
typedef struct {
    PR_HASHTABLE apps, auto_apps;
    PR_STRING auto_filename, auto_directory, auto_publisher;
    int type, action, is_readonly, is_forservices, is_fordriver;
    int is_enabled, is_haveerrors;
    PR_STRING name, rule_remote, rule_local, comment;
    unsigned profile, direction, protocol, af;
} ITEM_RULE, *PITEM_RULE;
typedef struct {
    int type, is_autoallow_blocked;
    ULONG app_hash;
    PR_STRING real_path;
} ITEM_APP, *PITEM_APP;
static struct { ULONG_PTR ntoskrnl_hash, svchost_hash; } config = {29, 30};
static int lock_autoapps, lock_autoallow, lock_apps, lock_rules;
static int autoallow_held, apps_held, rules_held, edit_pending, edit_applied;
static PITEM_RULE edited_rule;
static PR_STRING edited_name, edited_selector;
static PR_HASHTABLE edited_apps;
static void apply_pending_edit(void) {
    if (!edit_pending || autoallow_held) return;
    edited_rule->name = edited_name;
    edited_rule->auto_filename = edited_selector;
    edited_rule->apps = edited_apps;
    edit_pending = 0;
    edit_applied = 1;
}
static int match_calls, match_result = TRUE;
static int valid_filename = TRUE, valid_directory = TRUE;
static const wchar_t *expected_filename, *expected_directory, *expected_publisher;
static int sw_autoallow_valid_filename(const wchar_t *value) {
    return value && *value && valid_filename;
}
static int sw_autoallow_valid_directory(const wchar_t *value) {
    return value && *value && valid_directory;
}
static const wchar_t *_r_obj_getstring(PR_STRING s) { return s && *s->buffer ? s->buffer : NULL; }
static int _r_obj_isstringempty(PR_STRING s) { return !s || !*s->buffer; }
static size_t _r_str_getlength2(size_t *length) { return *length; }
static void *_r_obj_findhashtable(PR_HASHTABLE table, ULONG hash) {
    return table && (table->keys & (1u << hash)) ? table : NULL;
}
static int _r_obj_isempty(PR_HASHTABLE table) { return !table || !table->keys; }
static void _r_queuedlock_acquireshared(int *lock) {
    if (lock == &lock_autoallow) { assert(!autoallow_held && !rules_held); autoallow_held = 1; }
    if (lock == &lock_apps) { assert(autoallow_held && !apps_held && !rules_held); apps_held = 1; }
    if (lock == &lock_rules) { assert(autoallow_held && apps_held && !rules_held); rules_held = 1; }
}
static void _r_queuedlock_releaseshared(int *lock) {
    if (lock == &lock_rules) { assert(rules_held && autoallow_held); rules_held = 0; }
    if (lock == &lock_apps) { assert(apps_held && !rules_held); apps_held = 0; }
    if (lock == &lock_autoallow) {
        assert(autoallow_held && !apps_held && !rules_held);
        autoallow_held = 0;
        apply_pending_edit();
    }
}
static int _app_issystemhash(ULONG hash) { return hash == 31; }
static int sw_autoallow_match(const wchar_t *path, const wchar_t *filename,
    const wchar_t *directory, const wchar_t *publisher) {
    assert(path && *path);
    assert(filename == expected_filename);
    assert(directory == expected_directory);
    assert(publisher == expected_publisher);
    ++match_calls;
    return match_result;
}
'''
XML_STUBS = r'''
typedef struct { int unused; } XML_LIBRARY;
typedef struct { XML_LIBRARY xml_library; } DB_INFORMATION, *PDB_INFORMATION;
typedef struct { PITEM_RULE rules[4]; } LIST, *PR_LIST;
static LIST saved_rules;
static PR_LIST rules_list = &saved_rules;
static int section, custom_items, automatic_items, app_attributes;
static unsigned legacy_fields, legacy_system_flags;
static STRING serialized_apps = {L"C:\\Manual.exe", 13};
static ULONG_PTR _r_obj_getlistsize(PR_LIST list) { (void)list; return 4; }
static void *_r_obj_getlistitem(PR_LIST list, ULONG_PTR index) { return list->rules[index]; }
static void _app_db_writeelementstart(PDB_INFORMATION info, const wchar_t *tag) {
    (void)info;
    assert(autoallow_held && rules_held);
    section = wcscmp(tag, L"rules_auto") == 0 ? 1 : 0;
}
static void _app_db_writeelementend(PDB_INFORMATION info) {
    (void)info;
    assert(autoallow_held && rules_held);
    if (!section) {
        /* An editor attempts to move a legacy rule into rules_auto here. */
        edit_pending = 1;
        apply_pending_edit();
        assert(!edit_applied);
    }
}
static void _r_xml_writewhitespace(XML_LIBRARY *xml, const wchar_t *text) { (void)xml; (void)text; }
static void _r_xml_writestartelement(XML_LIBRARY *xml, const wchar_t *tag) {
    (void)xml; assert(wcscmp(tag, L"item") == 0);
    if (section) ++automatic_items; else ++custom_items;
}
static void _r_xml_writeendelement(XML_LIBRARY *xml) { (void)xml; }
static void _r_xml_setattribute(XML_LIBRARY *xml, const wchar_t *name, const wchar_t *value) {
    (void)xml;
    if (wcscmp(name, L"name") == 0) {
        assert((wcscmp(value, L"legacy") == 0) == !section);
    }
    if (wcscmp(name, L"apps") == 0) {
        ++app_attributes;
        assert(wcscmp(value, serialized_apps.buffer) == 0);
    }
    if (!section && !wcscmp(name, L"name")) legacy_fields |= 1;
    if (!section && !wcscmp(name, L"apps")) legacy_fields |= 2;
    if (!section && !wcscmp(name, L"rule")) { assert(!wcscmp(value, L"443")); legacy_fields |= 4; }
    if (!section && !wcscmp(name, L"rule_local")) { assert(!wcscmp(value, L"127.0.0.1")); legacy_fields |= 8; }
    if (wcsncmp(name, L"auto_", 5) == 0) assert(section);
}
static void _r_xml_setattribute_long(XML_LIBRARY *xml, const wchar_t *name, unsigned value) {
    (void)xml;
    if (!section && !wcscmp(name, L"dir")) { assert(value == 2); legacy_fields |= 16; }
}
static void _r_xml_setattribute_boolean(XML_LIBRARY *xml, const wchar_t *name, int value) {
    (void)xml;
    if (!section && !wcscmp(name, L"is_block")) { assert(value); legacy_fields |= 32; }
    if (!section && !wcscmp(name, L"is_enabled")) { assert(value); legacy_fields |= 64; }
    if (!section && !wcscmp(name, L"is_services")) { assert(value); legacy_system_flags |= 1; }
    if (!section && !wcscmp(name, L"is_kernel")) { assert(value); legacy_system_flags |= 2; }
}
static PR_STRING _app_rulesexpandapps_locked(PITEM_RULE rule, const wchar_t *divider) {
    assert(apps_held && rules_held); (void)divider;
    assert(rule->apps->keys); /* Derived cache alone must never trigger serialization. */
    return &serialized_apps;
}
static void _r_obj_dereference(void *object) { (void)object; }
'''

TESTS = r'''
int main(void) {
    TABLE manual = {0}, automatic = {0};
    STRING filename = {L"blender.exe", 11}, empty = {L"", 0};
    STRING directory = {L"C:\\Apps", 7}, publisher = {L"Trusted Publisher", 17};
    STRING path = {L"C:\\Apps\\blender.exe", 19}, oversized = {L"CN", 1024};
    ITEM_RULE rule = {0};
    ITEM_APP app = {DATA_APP_REGULAR, FALSE, 2, &path};
    rule.apps = &manual;
    rule.auto_apps = &automatic;
    rule.type = DATA_RULE_USER;
    rule.action = FWP_ACTION_PERMIT;
    rule.is_enabled = TRUE;

    assert(_app_rule_isglobal(&rule));
    rule.is_forservices = TRUE;
    assert(!_app_rule_isglobal(&rule)); /* Service-only rules are scoped. */
    assert(_app_rule_issystemapp(&rule, config.svchost_hash));
    assert(!_app_rule_issystemapp(&rule, config.ntoskrnl_hash));
    assert(_app_rule_containsapp(&rule, config.svchost_hash));
    rule.is_forservices = FALSE;
    rule.is_fordriver = TRUE;
    assert(!_app_rule_isglobal(&rule));
    assert(_app_rule_issystemapp(&rule, config.ntoskrnl_hash));
    assert(!_app_rule_issystemapp(&rule, config.svchost_hash));
    assert(_app_rule_containsapp(&rule, config.ntoskrnl_hash));
    assert(!_app_rule_issystemapp(&rule, 0));
    rule.is_fordriver = FALSE;
    manual.keys = 1u << 2;
    assert(!_app_rule_isglobal(&rule));
    assert(_app_rule_containsapp(&rule, 2));
    manual.keys = 0;

    rule.auto_filename = &filename;
    assert(_app_rule_hasauto(&rule));
    assert(_app_rule_autoisvalid(&rule));
    assert(!_app_rule_isglobal(&rule)); /* Zero matches must not become global. */
    rule.auto_filename = &empty;
    assert(!_app_rule_isglobal(&rule));
    assert(!_app_rule_autoisvalid(&rule));
    rule.auto_filename = NULL;
    rule.auto_directory = &directory;
    assert(!_app_rule_isglobal(&rule));
    assert(!_app_rule_autoisvalid(&rule));
    rule.auto_directory = NULL;
    rule.auto_publisher = &publisher;
    assert(!_app_rule_isglobal(&rule));
    assert(!_app_rule_autoisvalid(&rule));
    rule.auto_filename = &filename;
    rule.auto_directory = &directory;

    automatic.keys = 1u << 2;
    assert(_app_rule_containsapp(&rule, 2));
    rule.is_haveerrors = TRUE;
    assert(!_app_rule_containsapp(&rule, 2)); /* Failed WFP writes are not grants. */
    manual.keys = 1u << 2;
    assert(_app_rule_containsapp(&rule, 2)); /* Preserve manual association. */
    manual.keys = 0;
    rule.is_haveerrors = FALSE;
    rule.auto_filename = rule.auto_directory = rule.auto_publisher = NULL;
    assert(!_app_rule_containsapp(&rule, 2)); /* Ignore stale derived cache. */
    rule.auto_filename = &filename;
    rule.auto_directory = &directory;
    rule.auto_publisher = &publisher;

    rule.action = FWP_ACTION_BLOCK;
    assert(!_app_rule_autoisvalid(&rule));
    rule.action = FWP_ACTION_PERMIT;
    rule.is_readonly = TRUE;
    assert(!_app_rule_autoisvalid(&rule));
    rule.is_readonly = FALSE;
    rule.is_forservices = TRUE;
    assert(!_app_rule_autoisvalid(&rule));
    rule.is_forservices = FALSE;
    rule.is_fordriver = TRUE;
    assert(!_app_rule_autoisvalid(&rule));
    rule.is_fordriver = FALSE;
    rule.type = 9;
    assert(!_app_rule_autoisvalid(&rule));
    rule.type = DATA_RULE_USER;
    rule.auto_publisher = &oversized;
    assert(!_app_rule_autoisvalid(&rule));
    rule.auto_publisher = &publisher;
    valid_filename = FALSE;
    assert(!_app_rule_autoisvalid(&rule));
    valid_filename = TRUE;
    valid_directory = FALSE;
    assert(!_app_rule_autoisvalid(&rule));
    valid_directory = TRUE;

    expected_filename = filename.buffer;
    expected_directory = directory.buffer;
    expected_publisher = publisher.buffer;
    assert(_app_rule_matchapp(&rule, &app));
    assert(match_calls == 1); /* All three supplied conditions forwarded together. */
    match_result = FALSE;
    assert(!_app_rule_matchapp(&rule, &app));
    match_result = TRUE;
    match_calls = 0;
    app.is_autoallow_blocked = TRUE;
    assert(!_app_rule_matchapp(&rule, &app));
    app.is_autoallow_blocked = FALSE;
    for (int type = DATA_APP_DEVICE; type <= DATA_APP_PICO; ++type) {
        app.type = type;
        assert(!_app_rule_matchapp(&rule, &app));
    }
    app.type = DATA_APP_REGULAR;
    app.app_hash = 31;
    assert(!_app_rule_matchapp(&rule, &app));
    app.app_hash = 2;
    rule.is_enabled = FALSE;
    assert(!_app_rule_matchapp(&rule, &app));
    assert(match_calls == 0); /* Ineligible apps do no file/signature work. */
    /* Exercise the actual XML serializer: older binaries only read rules_custom. */
    DB_INFORMATION db = {0};
    ITEM_RULE legacy = {0}, selector = rule, malformed = rule, mixed = rule;
    STRING legacy_name = {L"legacy", 6}, selector_name = {L"selector", 8};
    STRING malformed_name = {L"malformed", 9}, mixed_name = {L"mixed", 5};
    STRING remote = {L"443", 3}, local = {L"127.0.0.1", 9};
    TABLE no_manual = {0}, explicit_manual = {1u << 3};
    legacy.name = &legacy_name;
    legacy.apps = &explicit_manual;
    legacy.rule_remote = &remote;
    legacy.rule_local = &local;
    legacy.direction = 2;
    legacy.action = FWP_ACTION_BLOCK;
    legacy.is_enabled = TRUE;
    legacy.is_forservices = TRUE;
    legacy.is_fordriver = TRUE;
    selector.name = &selector_name;
    selector.apps = &no_manual;
    malformed.name = &malformed_name;
    malformed.apps = &no_manual;
    malformed.auto_filename = &empty;
    mixed.name = &mixed_name;
    mixed.apps = &explicit_manual;
    saved_rules.rules[0] = &legacy;
    saved_rules.rules[1] = &selector;
    saved_rules.rules[2] = &malformed;
    saved_rules.rules[3] = &mixed;
    edited_rule = &legacy;
    edited_name = &selector_name;
    edited_selector = &filename;
    edited_apps = &explicit_manual;
    _r_queuedlock_acquireshared(&lock_autoallow);
    _app_db_save_rule(&db);
    _r_queuedlock_releaseshared(&lock_autoallow);
    assert(custom_items == 1);
    assert(automatic_items == 3);
    assert(app_attributes == 2); /* Only explicitly associated apps were persisted. */
    assert(legacy_system_flags == 3); /* Separate v6 attributes are both persisted. */
    assert(legacy_fields == 127); /* Version 6 user's common rule fields survive serialization. */
    assert(edit_applied && !edit_pending && !autoallow_held && !apps_held && !rules_held);
    assert(legacy.name == &selector_name && legacy.auto_filename == &filename);
    assert(legacy.apps == &explicit_manual); /* The waiting edit proceeds after the snapshot. */
    puts("Automatic rule scope, eligibility, and safe XML serialization checks passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-scope-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'scope.c'
    executable = temporary / 'scope-test'
    source.write_text(STUBS + '\n'.join(function_source(name) for name in FUNCTIONS) + XML_STUBS +
                      function_source('_app_db_save_rule', (ROOT / 'src' / 'db.c').read_text(), 'VOID') + TESTS)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

# Exercise both application revocation entry points using the actual production
# setter and a failing WFP stub. No Windows firewall calls are made.
APP_REVOKE_STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#endif
#ifdef _Inout_
#undef _Inout_
#endif
#ifdef _In_opt_
#undef _In_opt_
#endif
#define _In_
#define _Inout_
#define _In_opt_
#define VOID void
#define TRUE 1
#define FALSE 0
#define MB_OK 0
#define MB_ICONERROR 1
#define DBG_ARG L"test", 1
#define PtrToInt(value) ((int)(intptr_t)(value))
typedef uint8_t BOOLEAN;
typedef int64_t LONG64, *PLONG64;
typedef uintptr_t ULONG_PTR;
typedef void *PVOID;
typedef void *HANDLE;
typedef struct { int count; } ARRAY, *PR_ARRAY;
typedef struct {
    void *bytes, *comment, *hash;
    LONG64 timestamp, timer;
    int is_enabled, is_haveerrors, is_silent, is_undeletable;
    ULONG_PTR app_hash;
    PR_ARRAY guids;
} ITEM_APP, *PITEM_APP;
typedef enum {
    INFO_BYTES_DATA, INFO_COMMENT, INFO_HASH, INFO_TIMESTAMP, INFO_TIMER,
    INFO_DISABLE, INFO_IS_ENABLED, INFO_IS_SILENT, INFO_IS_UNDELETABLE
} ENUM_INFO_DATA;
static int failure, warnings, updates, revokes, lock_apps, lock_autoallow;
static void _r_queuedlock_acquireexclusive(int *lock) { assert((lock == &lock_apps || lock == &lock_autoallow) && !*lock); *lock = 1; }
static void _r_queuedlock_releaseexclusive(int *lock) { assert((lock == &lock_apps || lock == &lock_autoallow) && *lock); *lock = 0; }
static void *_wfp_getenginehandle(void) { assert(!lock_autoallow); return NULL; }
static BOOLEAN _wfp_destroyfilters_array_silent(void *engine, PR_ARRAY ids, const wchar_t *file, int line) {
    (void)engine; (void)file; (void)line; assert(lock_autoallow); ++revokes;
    if (failure) return FALSE;
    ids->count = 0; return TRUE;
}
static void *_r_app_gethwnd(void) { return NULL; }
static void _wfp_warnruleupdate(void *hwnd) {
    (void)hwnd; assert(!lock_autoallow); ++warnings;
}
static void _app_listview_updateitemby_param(void *hwnd, ULONG_PTR hash, int is_app) {
    (void)hwnd; (void)hash; (void)is_app; ++updates;
}
static LONG64 _r_unixtime_now(void) { return 100; }
static void _r_obj_movereference(void *target, void *value) { *(void **)target = value; }
static void _app_notify_freeobject(void *hwnd, PITEM_APP app) { (void)hwnd; (void)app; }
'''
APP_REVOKE_TEST = r'''
int main(void) {
    ARRAY ids = {2};
    ITEM_APP app = {0};
    LONG64 expired = 50;
    int hash_value = 42;
    _app_setappinfo(&app, INFO_HASH, &hash_value);
    assert(app.hash == &hash_value && !lock_apps);
    app.guids = &ids; app.is_enabled = TRUE; app.timer = 75;
    failure = TRUE;
    _app_setappinfo(&app, INFO_DISABLE, NULL);
    assert(ids.count == 2 && app.is_enabled && app.timer == 75 && app.is_haveerrors);
    assert(warnings == 1 && updates == 1 && revokes == 1);
    app.is_haveerrors = FALSE;
    _app_setappinfo(&app, INFO_TIMER, &expired);
    assert(ids.count == 2 && app.is_enabled && app.timer == 75 && app.is_haveerrors);
    assert(warnings == 2 && updates == 2 && revokes == 2);
    failure = FALSE;
    _app_setappinfo(&app, INFO_TIMER, &expired);
    assert(ids.count == 0 && !app.is_enabled && app.timer == 0);
    ids.count = 2; app.is_enabled = TRUE; app.timer = 75;
    _app_setappinfo(&app, INFO_DISABLE, NULL);
    assert(ids.count == 0 && !app.is_enabled && app.timer == 75);
    assert(warnings == 2 && updates == 4 && revokes == 4);
    ids.count = 2; app.is_enabled = TRUE; app.timer = 0; failure = TRUE;
    _app_setappinfo(&app, INFO_TIMER, &expired);
    assert(ids.count == 2 && app.is_enabled && app.timer == expired && app.is_haveerrors);
    assert(warnings == 3 && updates == 5 && revokes == 5 && !lock_autoallow);
    puts("Application revoke failure preserves filter IDs and state");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-app-revoke-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'app-revoke.c'
    executable = temporary / 'app-revoke-test'
    source.write_text(APP_REVOKE_STUBS + function_source('_app_revokeappfilters') + '\n' +
                      function_source('_app_setappinfo', return_type='VOID') + APP_REVOKE_TEST)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

COLOR_STUBS = r'''
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
#define UNREFERENCED_PARAMETER(value) (void)(value)
typedef int INT;
typedef uintptr_t ULONG_PTR;
typedef unsigned COLORREF;
typedef struct { int is_enabled, is_haveerrors, is_forservices, is_fordriver; } ITEM_RULE, *PITEM_RULE;
static ITEM_RULE rule;
static struct { ULONG_PTR color_invalid, color_special; } config = {17, 23};
static PITEM_RULE _app_getrulebyid(ULONG_PTR id) { (void)id; return &rule; }
static int _r_config_getboolean_ex(const wchar_t *name, int fallback, const wchar_t *section) {
    (void)name; (void)section; return fallback;
}
static int _app_rule_isglobal(PITEM_RULE value) { return !value->is_forservices && !value->is_fordriver; }
static void _r_obj_dereference(void *value) { (void)value; }
static COLORREF _app_getcolorvalue(ULONG_PTR value) { return (COLORREF)value; }
'''
COLOR_TEST = r'''
int main(void) {
    rule.is_enabled = FALSE;
    rule.is_haveerrors = TRUE;
    assert(_app_getrulecolor(0, 0) == config.color_invalid);
    rule.is_haveerrors = FALSE;
    assert(_app_getrulecolor(0, 0) == 0);
    rule.is_forservices = TRUE;
    assert(_app_getrulecolor(0, 0) == config.color_special);
    rule.is_forservices = FALSE; rule.is_fordriver = TRUE;
    assert(_app_getrulecolor(0, 0) == config.color_special);
    puts("Disabled rules retain visible error highlighting");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-rule-color-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'rule-color.c'
    executable = temporary / 'rule-color-test'
    source.write_text(COLOR_STUBS + function_source('_app_getrulecolor', return_type='COLORREF') + COLOR_TEST)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
