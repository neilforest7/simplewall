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
#define _Inout_
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
