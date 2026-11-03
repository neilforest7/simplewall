#!/usr/bin/env python3
"""Run the actual XML attribute-presence helper and parser fallback guard.

XmlLite distinguishes a missing attribute (S_FALSE) from a present empty one
(S_OK). The general routine string helper does not preserve that distinction.
These cases protect legacy rules from becoming malformed automatic selectors.
"""
from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'src' / 'db.c').read_text()


def function_source(name):
    start = SOURCE.index('BOOLEAN ' + name + ' (')
    brace = SOURCE.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
        end += 1
    return SOURCE[start:end]


STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifdef _Inout_
#undef _Inout_
#endif
#define _Inout_
#ifdef _In_
#undef _In_
#endif
#define _In_
#define TRUE 1
#define FALSE 0
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_FAIL ((HRESULT)INT32_C(-2147467259))
#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
typedef uint8_t BOOLEAN;
typedef int32_t HRESULT;
typedef const wchar_t *LPCWSTR;
typedef const wchar_t *PR_STRING;
typedef struct { unsigned present; int fail; int on_attribute; } READER;
typedef struct { READER *reader; } XML_LIBRARY;
typedef struct { XML_LIBRARY xml_library; } DB_INFORMATION, *PDB_INFORMATION;
typedef struct { PR_STRING auto_filename, auto_directory, auto_publisher; } RULE;
static unsigned move_calls, restore_calls;
static unsigned attribute_bit(LPCWSTR name) {
    if (wcscmp(name, L"auto_filename") == 0) return 1;
    if (wcscmp(name, L"auto_directory") == 0) return 2;
    if (wcscmp(name, L"auto_publisher") == 0) return 4;
    assert(0);
    return 0;
}
static HRESULT IXmlReader_MoveToAttributeByName(READER *reader, LPCWSTR name, void *ns) {
    assert(ns == NULL);
    ++move_calls;
    if (reader->fail) return E_FAIL;
    if (!(reader->present & attribute_bit(name))) return S_FALSE;
    reader->on_attribute = 1;
    return S_OK;
}
static HRESULT IXmlReader_MoveToElement(READER *reader) {
    ++restore_calls;
    reader->on_attribute = 0;
    return S_OK;
}
static PR_STRING _r_obj_createstring(LPCWSTR value) { return value; }
'''

# Exercise the actual fallback condition as well as the helper. A changed helper
# which is correct but not used by the parser must not make this test pass.
start = SOURCE.index('\tif (!ptr_rule->auto_filename &&', SOURCE.index('VOID _app_db_parse_rule ('))
end = SOURCE.index('\n\n', start)
fallback_guard = SOURCE[start:end]
HARNESS = r'''
static void parse_guard(PDB_INFORMATION db_info, RULE *ptr_rule, BOOLEAN is_automatic) {
''' + fallback_guard + r'''
}

int main(void) {
    READER reader = {0};
    DB_INFORMATION db = {{&reader}};
    RULE rule = {0};
    const wchar_t *names[] = {L"auto_filename", L"auto_directory", L"auto_publisher"};
    for (unsigned i = 0; i < 3; ++i) {
        reader.present = 0;
        assert(!_app_db_hasattribute(&db, names[i]));
        assert(!reader.on_attribute);
        reader.present = 1u << i;
        assert(_app_db_hasattribute(&db, names[i])); /* Includes empty values. */
        assert(!reader.on_attribute);
        reader.fail = 1;
        assert(!_app_db_hasattribute(&db, names[i]));
        assert(!reader.on_attribute);
        reader.fail = 0;
    }
    reader.present = 0;
    parse_guard(&db, &rule, FALSE);
    assert(!rule.auto_filename); /* Ordinary legacy rules retain their scope. */

    for (unsigned i = 0; i < 3; ++i) {
        reader.present = 1u << i;
        rule = (RULE){0};
        parse_guard(&db, &rule, FALSE);
        assert(rule.auto_filename && !*rule.auto_filename);
    }
    reader.present = 0;
    rule = (RULE){0};
    parse_guard(&db, &rule, TRUE);
    assert(rule.auto_filename && !*rule.auto_filename); /* Malformed rules_auto stays scoped. */

    rule = (RULE){L"app.exe", NULL, NULL};
    parse_guard(&db, &rule, FALSE);
    assert(wcscmp(rule.auto_filename, L"app.exe") == 0);
    rule = (RULE){NULL, L"C:\\Apps", NULL};
    parse_guard(&db, &rule, FALSE);
    assert(rule.auto_filename && !*rule.auto_filename);
    rule = (RULE){NULL, NULL, L"Publisher"};
    parse_guard(&db, &rule, FALSE);
    assert(rule.auto_filename && !*rule.auto_filename);
    assert(move_calls == restore_calls);
    puts("XML attribute presence and legacy/automatic parser scope checks passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='simplewall-xml-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'xml-presence.c'
    executable = temporary / 'xml-presence-test'
    source.write_text(STUBS + function_source('_app_db_hasattribute') + HARNESS)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

# Exercise the production application parser and rule-path expansion with a
# synthetic profile. The stubs model registered service and UWP identifiers.
APP_STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef _Inout_
#undef _Inout_
#endif
#define _Inout_
#define VOID void
#define FALSE 0
#define TRUE 1
#define DATA_UNKNOWN 0
#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_SUCCESS 0
#define IntToPtr(x) ((void *)(intptr_t)(x))
typedef int NTSTATUS;
typedef int64_t LONG64;
typedef uintptr_t ULONG_PTR;
typedef unsigned char BOOLEAN;
typedef struct { const wchar_t *buffer; } R_STRINGREF;
typedef struct { R_STRINGREF sr; const wchar_t *buffer; } STRING, *PR_STRING;
typedef struct { const wchar_t *path; int enabled, silent, undeletable, excluded; } XML_LIBRARY;
typedef struct { XML_LIBRARY xml_library; } DB_INFORMATION, *PDB_INFORMATION;
typedef struct { int type, enabled, silent, undeletable, is_autoallow_blocked; } ITEM_APP, *PITEM_APP;
enum { INFO_HASH, INFO_COMMENT, INFO_IS_SILENT, INFO_IS_ENABLED, INFO_IS_UNDELETABLE, INFO_TIMESTAMP, INFO_TIMER };
enum { REGULAR = 1, SERVICE, UWP, SYSTEM };
static ITEM_APP app;
static ULONG_PTR loaded_hash;
static int expansion_calls, fail_expansion;
static const wchar_t *loaded_path;
static PR_STRING make_string(const wchar_t *value) {
    PR_STRING s = malloc(sizeof(*s));
    assert(s);
    s->buffer = value;
    s->sr.buffer = value;
    return s;
}
static PR_STRING _r_xml_getattribute_string(XML_LIBRARY *xml, const wchar_t *name) {
    return wcscmp(name, L"path") == 0 && xml->path ? make_string(xml->path) : NULL;
}
static int _r_xml_getattribute_boolean(XML_LIBRARY *xml, const wchar_t *name) {
    if (!wcscmp(name, L"is_enabled")) return xml->enabled;
    if (!wcscmp(name, L"is_silent")) return xml->silent;
    if (!wcscmp(name, L"is_undeletable")) return xml->undeletable;
    if (!wcscmp(name, L"is_autoallow_blocked")) return xml->excluded;
    assert(0); return 0;
}
static LONG64 _r_xml_getattribute_long64(XML_LIBRARY *xml, const wchar_t *name) {
    (void)xml; (void)name; return 0;
}
static int _r_obj_isstringempty(PR_STRING s) { return !s || !s->buffer || !*s->buffer; }
static int _r_obj_isstringempty2(PR_STRING s) { return !s->buffer || !*s->buffer; }
static ULONG_PTR _r_str_findchar(R_STRINGREF *s, wchar_t ch, int reverse) {
    const wchar_t *found = reverse ? wcsrchr(s->buffer, ch) : wcschr(s->buffer, ch);
    return found ? (ULONG_PTR)(found - s->buffer) : SIZE_MAX;
}
static NTSTATUS _r_str_environmentexpandstring(void *environment, R_STRINGREF *input, PR_STRING *output) {
    const wchar_t *value = input->buffer;
    assert(!environment);
    ++expansion_calls;
    if (fail_expansion) { *output = NULL; return -1; }
    if (!wcscmp(value, L"%TESTROOT%\\app.exe")) value = L"C:\\Synthetic\\app.exe";
    if (!wcscmp(value, L"%TESTDEVICE%\\app.exe")) value = L"\\device\\synthetic\\app.exe";
    *output = make_string(value);
    return STATUS_SUCCESS;
}
static PR_STRING _r_obj_createstring2(R_STRINGREF *s) { return make_string(s->buffer); }
static void _r_obj_dereference(void *object) { if (object != &app) free(object); }
static void _r_obj_movereference(PR_STRING *target, PR_STRING value) {
    _r_obj_dereference(*target); *target = value;
}
static int _r_str_isstartswith2(R_STRINGREF *s, const wchar_t *prefix, int ignorecase) {
    (void)ignorecase; return wcsncmp(s->buffer, prefix, wcslen(prefix)) == 0;
}
static PR_STRING _r_path_dospathfromnt(R_STRINGREF *s) {
    if (!wcscmp(s->buffer, L"\\device\\synthetic\\app.exe")) return make_string(L"C:\\Synthetic\\app.exe");
    return NULL;
}
static ULONG_PTR _r_str_gethash2(R_STRINGREF *s, int ignorecase) {
    ULONG_PTR hash = 5381; (void)ignorecase;
    for (const wchar_t *p = s->buffer; *p; ++p) hash = hash * 33 + (ULONG_PTR)*p;
    return hash;
}
static ULONG_PTR _app_addapplication(void *hwnd, int type, PR_STRING path, void *display, void *real) {
    (void)hwnd; (void)type; (void)display; (void)real;
    loaded_path = path->buffer;
    loaded_hash = _r_str_gethash2(&path->sr, TRUE);
    if (!wcscmp(loaded_path, L"S-1-5-80-100")) app.type = SERVICE;
    else if (!wcscmp(loaded_path, L"S-1-15-2-100")) app.type = UWP;
    else if (!wcscmp(loaded_path, L"System")) app.type = SYSTEM;
    else app.type = REGULAR;
    return loaded_hash;
}
static PITEM_APP _app_getappitem(ULONG_PTR hash) { assert(hash == loaded_hash); return &app; }
static void _app_setappinfo(PITEM_APP item, int field, void *value) {
    if (field == INFO_IS_ENABLED) item->enabled = (int)(intptr_t)value;
    else if (field == INFO_IS_SILENT) item->silent = (int)(intptr_t)value;
    else if (field == INFO_IS_UNDELETABLE) item->undeletable = (int)(intptr_t)value;
    else assert(0);
}
'''
app_start = SOURCE.index('VOID _app_db_parse_app (')
app_end = SOURCE.index('\nVOID _app_db_parse_rule (', app_start)
app_parser = SOURCE[app_start:app_end]
rule_start = SOURCE.index('\t\t\tstatus = _r_str_environmentexpandstring (NULL, &first_part, &path_string);')
rule_end = SOURCE.index('\n\n', SOURCE.index('app_hash = _r_str_gethash2', rule_start))
rule_expansion = SOURCE[rule_start:rule_end]
APP_TEST = r'''
static ULONG_PTR rule_hash(const wchar_t *path) {
    R_STRINGREF first_part = {path};
    PR_STRING path_string = NULL, dos_path;
    NTSTATUS status;
    ULONG_PTR app_hash;
''' + rule_expansion + r'''
    _r_obj_dereference(path_string);
    return app_hash;
}
static void check(const wchar_t *path, const wchar_t *expected, int expected_type, int excluded) {
    DB_INFORMATION db = {{path, 1, 1, 1, excluded}};
    app = (ITEM_APP){0}; loaded_hash = 0; loaded_path = NULL;
    _app_db_parse_app(&db);
    assert(loaded_path && !wcscmp(loaded_path, expected));
    assert(app.type == expected_type);
    assert(app.enabled && app.silent && app.undeletable);
    assert(app.is_autoallow_blocked == excluded);
    assert(loaded_hash == rule_hash(path));
}
int main(void) {
    check(L"%TESTROOT%\\app.exe", L"C:\\Synthetic\\app.exe", REGULAR, 1);
    check(L"C:\\Synthetic\\app.exe", L"C:\\Synthetic\\app.exe", REGULAR, 0);
    check(L"S-1-5-80-100", L"S-1-5-80-100", SERVICE, 1);
    check(L"S-1-15-2-100", L"S-1-15-2-100", UWP, 0);
    check(L"System", L"System", SYSTEM, 0);
    /* Expansion precedes device conversion for both app and rule paths. */
    check(L"%TESTDEVICE%\\app.exe", L"C:\\Synthetic\\app.exe", REGULAR, 0);
    fail_expansion = 1;
    check(L"%TESTROOT%\\app.exe", L"%TESTROOT%\\app.exe", REGULAR, 0);
    assert(expansion_calls > 0);
    puts("Synthetic app path expansion, rule association, and identity checks passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-app-path-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'app-path.c'
    executable = temporary / 'app-path-test'
    source.write_text(APP_STUBS + app_parser + APP_TEST)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

# Decode synthetic version-6 and version-5 XML using the production version
# gate. The XmlLite operations are represented by a small in-memory stub.
VERSION_STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef _In_
#undef _In_
#endif
#ifdef _Inout_
#undef _Inout_
#endif
#define _In_
#define _Inout_
#define NT_SUCCESS(status) ((status) >= 0)
#define FAILED(status) ((status) < 0)
#define STATUS_BUFFER_ALL_ZEROS (-1)
#define STATUS_MORE_PROCESSING_REQUIRED 1
#define STATUS_DATA_ERROR (-2)
#define STATUS_NDIS_INVALID_DATA (-3)
#define STATUS_FILE_NOT_SUPPORTED (-4)
#define STATUS_SUCCESS 0
#define XML_VERSION_MAXIMUM 6
typedef unsigned long ULONG;
typedef int NTSTATUS;
typedef int ENUM_TYPE_XML;
typedef int ENUM_VERSION_XML;
typedef struct { char *buffer; size_t length; } BYTES;
typedef struct { char *xml; } XML_LIBRARY;
typedef struct { BYTES *bytes; XML_LIBRARY xml_library; long long timestamp; int type, version; } DB_INFORMATION, *PDB_INFORMATION;
static NTSTATUS _app_db_decodebody(PDB_INFORMATION db) { (void)db; return STATUS_SUCCESS; }
static NTSTATUS _r_xml_parsestring(XML_LIBRARY *xml, char *buffer, ULONG length) {
    (void)length; xml->xml = buffer; return STATUS_SUCCESS;
}
static int _r_xml_findchildbytagname(XML_LIBRARY *xml, const wchar_t *name) {
    (void)name; return strstr(xml->xml, "<root ") != NULL;
}
static long _r_xml_getattribute_long(XML_LIBRARY *xml, const wchar_t *name) {
    const char *field = !wcscmp(name, L"version") ? "version=\"" : "type=\"";
    const char *found = strstr(xml->xml, field);
    return found ? strtol(found + strlen(field), NULL, 10) : 0;
}
static long long _r_xml_getattribute_long64(XML_LIBRARY *xml, const wchar_t *name) {
    (void)xml; (void)name; return 123;
}
'''
version_start = SOURCE.index('NTSTATUS _app_db_decodebuffer (')
version_end = SOURCE.index('\nBOOLEAN _app_db_parse (', version_start)
VERSION_TEST = r'''
int main(void) {
    char v6[] = "<root version=\"6\" type=\"1\"><rules_custom><item name=\"Example\" apps=\"%TESTROOT%\\app.exe\" dir=\"2\" is_block=\"1\" is_enabled=\"1\" rule=\"443\" rule_local=\"127.0.0.1\"/></rules_custom></root>";
    char v5[] = "<root version=\"5\" type=\"1\"/>";
    char v7[] = "<root version=\"7\" type=\"1\"/>";
    BYTES bytes = {v6, sizeof(v6) - 1};
    DB_INFORMATION db = {0}; db.bytes = &bytes;
    assert(_app_db_decodebuffer(&db, 1, 3) == STATUS_SUCCESS && db.version == 6);
    assert(_app_db_decodebuffer(&db, 2, 3) == STATUS_NDIS_INVALID_DATA);
    bytes.buffer = v5; bytes.length = sizeof(v5) - 1;
    assert(_app_db_decodebuffer(&db, 1, 3) == STATUS_SUCCESS && db.version == 5);
    assert(_app_db_decodebuffer(&db, 1, 6) == STATUS_FILE_NOT_SUPPORTED);
    bytes.buffer = v7; bytes.length = sizeof(v7) - 1;
    assert(_app_db_decodebuffer(&db, 1, 3) == STATUS_FILE_NOT_SUPPORTED);
    puts("Synthetic version-5/6 input and unsupported version gates passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-profile-version-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'profile-version.c'
    executable = temporary / 'profile-version-test'
    source.write_text(VERSION_STUBS + SOURCE[version_start:version_end] + VERSION_TEST)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

# Use the production rule-attribute reads with a synthetic item. The companion
# scope test exercises the production serializer for these same fields.
RULE_READ_STUBS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#define FWP_ACTION_BLOCK 2
#define FWP_ACTION_PERMIT 1
typedef uint8_t UINT8;
typedef int FWP_DIRECTION, FWP_ACTION_TYPE, ADDRESS_FAMILY;
typedef struct { const wchar_t *buffer; } STRING, *PR_STRING;
typedef struct { STRING name, remote, local; int dir, block, enabled; } XML_LIBRARY;
typedef struct { XML_LIBRARY xml_library; } DB_INFORMATION, *PDB_INFORMATION;
typedef struct { PR_STRING name, remote, local; int dir, action, enabled; } ITEM_RULE, *PITEM_RULE;
static ITEM_RULE parsed;
static PR_STRING _r_xml_getattribute_string(XML_LIBRARY *xml, const wchar_t *name) {
    if (!wcscmp(name, L"name")) return &xml->name;
    if (!wcscmp(name, L"rule")) return &xml->remote;
    if (!wcscmp(name, L"rule_local")) return &xml->local;
    return NULL;
}
static int _r_xml_getattribute_long(XML_LIBRARY *xml, const wchar_t *name) {
    return !wcscmp(name, L"dir") ? xml->dir : 0;
}
static int _r_xml_getattribute_boolean(XML_LIBRARY *xml, const wchar_t *name) {
    if (!wcscmp(name, L"is_block")) return xml->block;
    if (!wcscmp(name, L"is_enabled")) return xml->enabled;
    return 0;
}
static PITEM_RULE _app_addrule(PR_STRING name, PR_STRING remote, PR_STRING local,
    int dir, int action, UINT8 protocol, int af) {
    (void)protocol; (void)af;
    parsed = (ITEM_RULE){name, remote, local, dir, action, 0};
    return &parsed;
}
'''
rule_read_start = SOURCE.index('\trule_name = _r_xml_getattribute_string', SOURCE.index('VOID _app_db_parse_rule ('))
rule_read_end = SOURCE.index('\n\n', SOURCE.index('\tptr_rule = _app_addrule', rule_read_start))
rule_enabled_start = SOURCE.index('\tptr_rule->is_enabled = _r_xml_getattribute_boolean', rule_read_end)
rule_enabled_end = SOURCE.index('\n', rule_enabled_start)
rule_read = SOURCE[rule_read_start:rule_read_end].replace('return;', 'return NULL;') + '\n' + SOURCE[rule_enabled_start:rule_enabled_end]
RULE_READ_TEST = r'''
static PITEM_RULE read_rule(PDB_INFORMATION db_info) {
    PR_STRING rule_name, rule_remote, rule_local, comment;
    FWP_DIRECTION direction;
    FWP_ACTION_TYPE action;
    UINT8 protocol;
    ADDRESS_FAMILY af;
    PITEM_RULE ptr_rule;
''' + rule_read + r'''
    (void)comment;
    return ptr_rule;
}
int main(void) {
    DB_INFORMATION db = {{{L"Example"}, {L"443"}, {L"127.0.0.1"}, 2, 1, 1}};
    PITEM_RULE rule = read_rule(&db);
    assert(!wcscmp(rule->name->buffer, L"Example"));
    assert(!wcscmp(rule->remote->buffer, L"443"));
    assert(!wcscmp(rule->local->buffer, L"127.0.0.1"));
    assert(rule->dir == 2 && rule->action == FWP_ACTION_BLOCK && rule->enabled);
    puts("Synthetic custom rule attribute reads passed");
    return 0;
}
'''
# The baseline member uses is_enabled rather than the short stub name.
RULE_READ_STUBS = RULE_READ_STUBS.replace('int dir, action, enabled;', 'int dir, action, is_enabled;')
RULE_READ_TEST = RULE_READ_TEST.replace('rule->enabled', 'rule->is_enabled')
with tempfile.TemporaryDirectory(prefix='simplewall-rule-read-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'rule-read.c'
    executable = temporary / 'rule-read-test'
    source.write_text(RULE_READ_STUBS + RULE_READ_TEST)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

# Use production flag reads and writes to verify legacy v5 semantics and v6
# service/driver round trips without accessing any real profile.
FLAGS_STUBS = r'''
#include <assert.h>
#include <stdio.h>
#include <wchar.h>
#define TRUE 1
#define XML_VERSION_6 6
typedef struct { int services, kernel; } XML_LIBRARY;
typedef struct { XML_LIBRARY xml_library; int version; } DB_INFORMATION, *PDB_INFORMATION;
typedef struct { int is_forservices, is_fordriver; } ITEM_RULE, *PITEM_RULE;
static int _r_xml_getattribute_boolean(XML_LIBRARY *xml, const wchar_t *name) {
    if (!wcscmp(name, L"is_services")) return xml->services;
    assert(!wcscmp(name, L"is_kernel")); return xml->kernel;
}
static void _r_xml_setattribute_boolean(XML_LIBRARY *xml, const wchar_t *name, int value) {
    if (!wcscmp(name, L"is_services")) xml->services = value;
    else { assert(!wcscmp(name, L"is_kernel")); xml->kernel = value; }
}
'''
flags_parse_start = SOURCE.index('\tptr_rule->is_forservices = _r_xml_getattribute_boolean', SOURCE.index('VOID _app_db_parse_rule ('))
flags_parse_end = SOURCE.index('\n\tptr_rule->is_readonly', flags_parse_start)
flags_write_start = SOURCE.index('\t\t\tif (ptr_rule->is_forservices)', SOURCE.index('VOID _app_db_save_rule ('))
flags_write_end = SOURCE.index('\n\t\t\tif (ptr_rule->action', flags_write_start)
FLAGS_TEST = r'''
static void read_flags(PDB_INFORMATION db_info, PITEM_RULE ptr_rule) {
''' + SOURCE[flags_parse_start:flags_parse_end] + r'''
}
static void write_flags(PDB_INFORMATION db_info, PITEM_RULE ptr_rule) {
''' + SOURCE[flags_write_start:flags_write_end] + r'''
}
int main(void) {
    for (int service = 0; service < 2; ++service) {
        for (int driver = 0; driver < 2; ++driver) {
            DB_INFORMATION input = {{service, driver}, 6}, output = {{0, 0}, 6};
            ITEM_RULE rule = {0}, reread = {0};
            read_flags(&input, &rule);
            assert(rule.is_forservices == service && rule.is_fordriver == driver);
            write_flags(&output, &rule);
            read_flags(&output, &reread);
            assert(reread.is_forservices == service && reread.is_fordriver == driver);
        }
    }
    DB_INFORMATION legacy_internal = {{1, 0}, 5}, upgraded = {{0, 0}, 6};
    ITEM_RULE old = {0}, reread = {0};
    read_flags(&legacy_internal, &old);
    assert(old.is_forservices && old.is_fordriver);
    write_flags(&upgraded, &old);
    read_flags(&upgraded, &reread);
    assert(reread.is_forservices && reread.is_fordriver);
    puts("Legacy service scope and version-6 service/kernel round trips passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='simplewall-service-flags-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'service-flags.c'
    executable = temporary / 'service-flags-test'
    source.write_text(FLAGS_STUBS + FLAGS_TEST)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
