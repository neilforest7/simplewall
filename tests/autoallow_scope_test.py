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
FUNCTIONS = (
    '_app_rule_hasauto', '_app_rule_autoisvalid', '_app_rule_isglobal',
    '_app_rule_containsapp', '_app_rule_matchapp',
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
#define _In_
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
    int type, action, is_readonly, is_fordriver, is_forservice;
    int is_enabled, is_haveerrors;
    PR_STRING name, rule_remote, rule_local, comment;
    unsigned profile, direction, protocol, af;
} ITEM_RULE, *PITEM_RULE;
typedef struct {
    int type, is_autoallow_blocked;
    ULONG app_hash;
    PR_STRING real_path;
} ITEM_APP, *PITEM_APP;
static int lock_autoapps;
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
static void _r_queuedlock_acquireshared(int *lock) { (void)lock; }
static void _r_queuedlock_releaseshared(int *lock) { (void)lock; }
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
static int lock_rules, section, custom_items, automatic_items, app_attributes;
static STRING serialized_apps = {L"C:\\Manual.exe", 13};
static ULONG_PTR _r_obj_getlistsize(PR_LIST list) { (void)list; return 4; }
static void *_r_obj_getlistitem(PR_LIST list, ULONG_PTR index) { return list->rules[index]; }
static void _app_db_writeelementstart(PDB_INFORMATION info, const wchar_t *tag) {
    (void)info;
    section = wcscmp(tag, L"rules_auto") == 0 ? 1 : 0;
}
static void _app_db_writeelementend(PDB_INFORMATION info) { (void)info; }
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
    if (wcsncmp(name, L"auto_", 5) == 0) assert(section);
}
static void _r_xml_setattribute_long(XML_LIBRARY *xml, const wchar_t *name, unsigned value) {
    (void)xml; (void)name; (void)value;
}
static void _r_xml_setattribute_boolean(XML_LIBRARY *xml, const wchar_t *name, int value) {
    (void)xml; (void)name; (void)value;
}
static PR_STRING _app_rulesexpandapps(PITEM_RULE rule, int display, const wchar_t *divider) {
    assert(!display); (void)divider;
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
    rule.is_fordriver = TRUE;
    assert(!_app_rule_autoisvalid(&rule));
    rule.is_fordriver = FALSE;
    rule.is_forservice = TRUE;
    assert(!_app_rule_autoisvalid(&rule));
    rule.is_forservice = FALSE;
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
    TABLE no_manual = {0}, explicit_manual = {1u << 3};
    legacy.name = &legacy_name;
    legacy.apps = &no_manual;
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
    _app_db_save_rule(&db);
    assert(custom_items == 1);
    assert(automatic_items == 3);
    assert(app_attributes == 1); /* Only the explicit manual app was persisted. */
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
