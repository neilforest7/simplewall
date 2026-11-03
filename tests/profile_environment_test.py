#!/usr/bin/env python3
"""Exercise production profile path reads and writes using synthetic paths."""

import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = (Path(__file__).resolve().parents[1] / 'src' / 'db.c').read_text()


def function_source(name):
    start = SOURCE.index('VOID ' + name + ' (')
    brace = SOURCE.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
        end += 1
    return SOURCE[start:end]


# Extract the real rule-reference expansion and normalization, too. The XML and
# Windows environment APIs are modeled with synthetic values in this harness.
rule_start = SOURCE.index('\t\t\tstatus = _r_str_environmentexpandstring (NULL, &first_part, &path_string);')
rule_end = SOURCE.index('\n\n', SOURCE.index('\t\t\tapp_hash = _r_str_gethash2', rule_start))

STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef _Inout_
#undef _Inout_
#endif
#define _Inout_
#define VOID void
#define TRUE 1
#define FALSE 0
#define DATA_UNKNOWN 0
#define DATA_APP_SERVICE 1
#define DATA_APP_UWP 2
#define INFO_HASH 1
#define INFO_COMMENT 2
#define INFO_IS_SILENT 3
#define INFO_IS_ENABLED 4
#define INFO_IS_UNDELETABLE 5
#define INFO_TIMESTAMP 6
#define INFO_TIMER 7
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_SUCCESS 0
#define IntToPtr(x) ((void *)(intptr_t)(x))
typedef int BOOLEAN, NTSTATUS;
typedef int64_t LONG64;
typedef uintptr_t ULONG_PTR;
typedef struct { const wchar_t *buffer; } R_STRINGREF;
typedef struct { R_STRINGREF sr; const wchar_t *buffer; } STRING, *PR_STRING;
typedef struct {
    PR_STRING original_path, hash, comment;
    LONG64 timestamp, timer;
    int profile, type, is_enabled, is_silent, is_undeletable, is_autoallow_blocked;
} ITEM_APP, *PITEM_APP;
typedef struct { wchar_t path[512]; } XML_LIBRARY;
typedef struct { XML_LIBRARY xml_library; } DB_INFORMATION, *PDB_INFORMATION;
static ITEM_APP app;
static int apps_table, lock_apps, setting = -1, bad_unexpand, fail_expand;

static PR_STRING make_string(const wchar_t *value) {
    size_t size = (wcslen(value) + 1) * sizeof(wchar_t);
    PR_STRING result = malloc(sizeof(*result));
    wchar_t *copy = malloc(size);
    assert(result && copy);
    memcpy(copy, value, size);
    result->buffer = result->sr.buffer = copy;
    return result;
}
static PR_STRING _r_obj_createstring2(R_STRINGREF *s) { return make_string(s->buffer); }
static PR_STRING _r_obj_reference(PR_STRING s) { return s; }
static void _r_obj_dereference(void *s) { (void)s; }
static void _r_obj_movereference(PR_STRING *dst, PR_STRING src) { *dst = src; }
static int _r_obj_isstringempty(PR_STRING s) { return !s || !*s->buffer; }
static int _r_obj_isstringempty2(PR_STRING s) { return _r_obj_isstringempty(s); }
static size_t _r_str_findchar(R_STRINGREF *s, wchar_t c, int ignore) {
    (void)ignore; return wcschr(s->buffer, c) ? 0 : SIZE_MAX;
}
static int _r_str_isstartswith2(R_STRINGREF *s, const wchar_t *prefix, int ignore) {
    (void)ignore; return wcsncmp(s->buffer, prefix, wcslen(prefix)) == 0;
}
static int _r_str_isequal(R_STRINGREF *a, R_STRINGREF *b, int ignore) {
    (void)ignore; return wcscmp(a->buffer, b->buffer) == 0;
}
static PR_STRING _r_path_dospathfromnt(R_STRINGREF *s) { (void)s; return NULL; }
static NTSTATUS _r_str_environmentexpandstring(void *env, R_STRINGREF *s, PR_STRING *out) {
    (void)env;
    if (fail_expand) { *out = NULL; return -1; }
    if (!wcscmp(s->buffer, L"%SYNTHETIC_ROOT%\\app.exe"))
        *out = make_string(L"C:\\Synthetic\\app.exe");
    else if (!wcscmp(s->buffer, L"%WRONG_ROOT%\\app.exe"))
        *out = make_string(L"C:\\Different\\app.exe");
    else *out = make_string(s->buffer);
    return STATUS_SUCCESS;
}
static PR_STRING _r_str_environmentunexpandstring(R_STRINGREF *s) {
    if (!wcscmp(s->buffer, L"C:\\Synthetic\\app.exe"))
        return make_string(bad_unexpand ? L"%WRONG_ROOT%\\app.exe" : L"%SYNTHETIC_ROOT%\\app.exe");
    return make_string(s->buffer);
}
static int _r_config_getboolean(const wchar_t *name, int default_value) {
    if (!wcscmp(name, L"IsSaveAppsWithEnvironment")) return setting < 0 ? default_value : setting;
    if (!wcscmp(name, L"IsKeepUnusedApps")) return TRUE;
    return default_value;
}
static PR_STRING _r_xml_getattribute_string(XML_LIBRARY *xml, const wchar_t *name) {
    return !wcscmp(name, L"path") ? make_string(xml->path) : NULL;
}
static int _r_xml_getattribute_boolean(XML_LIBRARY *xml, const wchar_t *name) {
    (void)xml; return !wcscmp(name, L"is_enabled");
}
static LONG64 _r_xml_getattribute_long64(XML_LIBRARY *xml, const wchar_t *name) {
    (void)xml; (void)name; return 0;
}
static void _r_xml_setattribute(XML_LIBRARY *xml, const wchar_t *name, const wchar_t *value) {
    if (!wcscmp(name, L"path")) { size_t n = wcslen(value); assert(n < 512); memcpy(xml->path, value, (n + 1) * sizeof(wchar_t)); }
}
static void _r_xml_setattribute_long64(XML_LIBRARY *x, const wchar_t *n, LONG64 v) { (void)x; (void)n; (void)v; }
static void _r_xml_setattribute_long(XML_LIBRARY *x, const wchar_t *n, long v) { (void)x; (void)n; (void)v; }
static void _r_xml_setattribute_boolean(XML_LIBRARY *x, const wchar_t *n, int v) { (void)x; (void)n; (void)v; }
static void _r_xml_writewhitespace(XML_LIBRARY *x, const wchar_t *s) { (void)x; (void)s; }
static void _r_xml_writestartelement(XML_LIBRARY *x, const wchar_t *s) { (void)x; (void)s; }
static void _r_xml_writeendelement(XML_LIBRARY *x) { (void)x; }
static void _app_db_writeelementstart(PDB_INFORMATION db, const wchar_t *tag) { (void)db; (void)tag; }
static void _app_db_writeelementend(PDB_INFORMATION db) { (void)db; }
static void _r_queuedlock_acquireshared(int *lock) { (void)lock; }
static void _r_queuedlock_releaseshared(int *lock) { (void)lock; }
static int _r_obj_enumhashtablepointer(int table, PITEM_APP *out, void *unused, ULONG_PTR *key) {
    (void)table; (void)unused; if ((*key)++) return 0; *out = &app; return 1;
}
static int _app_isappused(PITEM_APP p) { (void)p; return 1; }
static int _app_istimerset(PITEM_APP p) { (void)p; return 0; }
static ULONG_PTR _app_addapplication(void *hwnd, int type, PR_STRING path, void *display, void *real) {
    (void)hwnd; (void)type; (void)display; (void)real; app.original_path = path; return 1;
}
static PITEM_APP _app_getappitem(ULONG_PTR hash) { assert(hash == 1); return &app; }
static void _app_setappinfo(PITEM_APP p, int field, void *value) { (void)p; (void)field; (void)value; }
static ULONG_PTR _r_str_gethash2(R_STRINGREF *s, int ignore) {
    ULONG_PTR hash = 5381; (void)ignore;
    for (const wchar_t *p = s->buffer; *p; ++p) hash = hash * 33 + (ULONG_PTR)*p;
    return hash;
}
'''

HARNESS = r'''
static ULONG_PTR rule_hash(R_STRINGREF first_part) {
    PR_STRING path_string, dos_path;
    NTSTATUS status;
    ULONG_PTR app_hash;
''' + SOURCE[rule_start:rule_end] + r'''
    return app_hash;
}
static void check(int option, int wrong, int fail, const wchar_t *expected) {
    DB_INFORMATION input = {{L"%SYNTHETIC_ROOT%\\app.exe"}}, output = {{L""}};
    setting = option; bad_unexpand = wrong; fail_expand = 0;
    _app_db_parse_app(&input);
    assert(!wcscmp(app.original_path->buffer, L"C:\\Synthetic\\app.exe"));
    R_STRINGREF rule = {L"%SYNTHETIC_ROOT%\\app.exe"};
    assert(rule_hash(rule) == _r_str_gethash2(&app.original_path->sr, TRUE));
    fail_expand = fail;
    _app_db_save_app(&output);
    assert(!wcscmp(output.xml_library.path, expected));
    fail_expand = 0;
    _app_db_parse_app(&output);
    assert(!wcscmp(app.original_path->buffer, L"C:\\Synthetic\\app.exe"));
    assert(rule_hash(rule) == _r_str_gethash2(&app.original_path->sr, TRUE));
}
int main(void) {
    check(-1, 0, 0, L"%SYNTHETIC_ROOT%\\app.exe"); /* Unset defaults to enabled. */
    check(0, 0, 0, L"C:\\Synthetic\\app.exe");
    check(1, 0, 0, L"%SYNTHETIC_ROOT%\\app.exe");
    check(1, 1, 0, L"C:\\Synthetic\\app.exe"); /* Wrong expansion is rejected. */
    check(1, 0, 1, L"C:\\Synthetic\\app.exe"); /* Failed expansion is rejected. */
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-profile-environment-') as temporary:
    source = Path(temporary) / 'profile-environment.c'
    executable = Path(temporary) / ('profile-environment.exe' if os.name == 'nt' else 'profile-environment')
    source.write_text(STUBS + function_source('_app_db_parse_app') +
                      function_source('_app_db_save_app') + HARNESS)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
print('Synthetic profile environment path round trip passed')
