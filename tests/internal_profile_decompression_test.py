#!/usr/bin/env python3
"""Exercise the profile decoder with Windows' native compression routines.

Run from an MSVC developer command prompt: python tests/internal_profile_decompression_test.py
The test compiles the decoder from src/db.c with small object/crypto stubs. It
does not start Simplewall or access the machine's firewall or profile files.
"""
from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'src' / 'db.c').read_text(encoding='utf-8')


def function_source(signature):
    start = SOURCE.index(signature)
    brace = SOURCE.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
        end += 1
    return SOURCE[start:end]


STUBS = r'''
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif
#define PR_SIZE_BUFFER_OVERFLOW (256 * 1024 * 1024)
#define PROFILE2_ID_COMPRESSED ((BYTE)0x31)
#define PROFILE2_ID_ENCRYPTED ((BYTE)0x32)
#define PROFILE2_FOURCC_LENGTH 4
#define PROFILE2_SHA256_LENGTH 32
#define PROFILE2_HEADER_LENGTH (PROFILE2_FOURCC_LENGTH + PROFILE2_SHA256_LENGTH)
static const BYTE profile2_fourcc[] = {'s', 'w', 'c'};

typedef struct _R_BYTEREF { ULONG_PTR length; char *buffer; } R_BYTEREF, *PR_BYTEREF;
typedef struct _R_BYTE {
    union { R_BYTEREF sr; struct { ULONG_PTR length; char *buffer; }; };
    char data[1];
} R_BYTE, *PR_BYTE, **PR_BYTE_PTR;
typedef struct _DB_INFORMATION { PR_BYTE hash; PR_BYTE bytes; } DB_INFORMATION, *PDB_INFORMATION;

__declspec(dllimport) NTSTATUS NTAPI RtlDecompressBuffer(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
__declspec(dllimport) NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(USHORT, PULONG, PULONG);
__declspec(dllimport) NTSTATUS NTAPI RtlCompressBuffer(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);

static ULONG_PTR largest_allocation;
static PR_BYTE _r_obj_createbyte_ex(const char *source, ULONG_PTR length) {
    PR_BYTE bytes = malloc(offsetof(R_BYTE, data) + length + 1);
    assert(bytes);
    if (length > largest_allocation) largest_allocation = length;
    bytes->length = length;
    bytes->buffer = bytes->data;
    if (source) memcpy(bytes->buffer, source, length);
    bytes->buffer[length] = 0;
    return bytes;
}
static void _r_obj_setbytelength_ex(PR_BYTE bytes, ULONG_PTR length, ULONG_PTR capacity) {
    assert(length <= capacity);
    bytes->length = length;
    bytes->buffer[length] = 0;
}
static void _r_obj_dereference(PR_BYTE bytes) { free(bytes); }
static void _r_obj_movereference(PR_BYTE_PTR old, PR_BYTE value) { free(*old); *old = value; }
static void _r_obj_skipbytelength(PR_BYTEREF bytes, ULONG_PTR length) {
    assert(bytes->length >= length);
    bytes->buffer += length;
    bytes->length -= length;
}
static NTSTATUS _app_db_decrypt(PR_BYTEREF buffer, PR_BYTE_PTR output) {
    (void)buffer; (void)output; return STATUS_NOT_SUPPORTED;
}
static USHORT test_architecture = PROCESSOR_ARCHITECTURE_AMD64;
static NTSTATUS _r_sys_getprocessorinformation(USHORT *architecture, void *a, void *b) {
    (void)a; (void)b; *architecture = test_architecture; return STATUS_SUCCESS;
}
static void sha256(const void *input, ULONG length, BYTE digest[32]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    ULONG object_length = 0, returned = 0;
    PUCHAR object;
    assert(NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0)));
    assert(NT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
                                        sizeof(object_length), &returned, 0)));
    object = malloc(object_length);
    assert(object);
    assert(NT_SUCCESS(BCryptCreateHash(algorithm, &hash, object, object_length, NULL, 0, 0)));
    assert(NT_SUCCESS(BCryptHashData(hash, (PUCHAR)input, length, 0)));
    assert(NT_SUCCESS(BCryptFinishHash(hash, digest, 32, 0)));
    assert(NT_SUCCESS(BCryptDestroyHash(hash)));
    free(object);
    assert(NT_SUCCESS(BCryptCloseAlgorithmProvider(algorithm, 0)));
}
static NTSTATUS _app_db_ishashvalid(PR_BYTEREF buffer, PR_BYTEREF expected) {
    BYTE digest[32];
    assert(expected->length == sizeof(digest));
    sha256(buffer->buffer, (ULONG)buffer->length, digest);
    return memcmp(digest, expected->buffer, sizeof(digest)) ? STATUS_INVALID_IMAGE_HASH : STATUS_SUCCESS;
}
'''


HARNESS = r'''
static PR_BYTE readfile(const char *path) {
    FILE *file = fopen(path, "rb");
    long length;
    PR_BYTE bytes;
    assert(file);
    assert(fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
    bytes = _r_obj_createbyte_ex(NULL, (ULONG)length);
    assert(fread(bytes->buffer, 1, length, file) == (size_t)length);
    fclose(file);
    return bytes;
}
static void destroy_db(PDB_INFORMATION db) {
    _r_obj_dereference(db->hash);
    _r_obj_dereference(db->bytes);
}
static void check_internal(const char *profile_path, const char *xml_path) {
    PR_BYTE profile = readfile(profile_path);
    PR_BYTE xml = readfile(xml_path);
    DB_INFORMATION db = {0};
    ULONG compressed_length = (ULONG)profile->length - PROFILE2_HEADER_LENGTH;
    ULONG capacity = compressed_length * 2, returned = 0;
    PUCHAR small_buffer = malloc(capacity);
    NTSTATUS status;
    BYTE digest[32];
    assert(small_buffer && profile->length > PROFILE2_HEADER_LENGTH);
    assert(!memcmp(profile->buffer, "swc1", PROFILE2_FOURCC_LENGTH));
    assert(xml->length > capacity);
    status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, small_buffer, capacity,
        (PUCHAR)profile->buffer + PROFILE2_HEADER_LENGTH, compressed_length, &returned);
    if (NT_SUCCESS(status)) {
        assert(returned <= capacity && !memcmp(small_buffer, xml->buffer, returned));
        sha256(small_buffer, returned, digest);
        assert(memcmp(digest, profile->buffer + PROFILE2_FOURCC_LENGTH, sizeof(digest)));
        printf("Native truncated success: %lu/%llu bytes\n", returned, (unsigned long long)xml->length);
    } else {
        assert(status == STATUS_BAD_COMPRESSION_BUFFER);
        printf("Native small-buffer status: 0x%08lx\n", (unsigned long)status);
    }
    free(small_buffer);

    db.bytes = profile;
    status = _app_db_decodebody(&db);
    assert(status == STATUS_SUCCESS);
    assert(db.bytes->length == xml->length);
    assert(!memcmp(db.bytes->buffer, xml->buffer, xml->length));
    printf("Internal profile: %lu compressed -> %llu full bytes, SHA-256 valid\n",
        compressed_length, (unsigned long long)db.bytes->length);
    destroy_db(&db);

    profile = readfile(profile_path);
    profile->buffer[PROFILE2_FOURCC_LENGTH] ^= 1;
    db.hash = NULL;
    db.bytes = profile;
    assert(_app_db_decodebody(&db) == STATUS_INVALID_IMAGE_HASH);
    destroy_db(&db);

    profile = readfile(profile_path);
    profile->buffer[PROFILE2_FOURCC_LENGTH] ^= 1;
    db.hash = NULL;
    db.bytes = profile;
    test_architecture = PROCESSOR_ARCHITECTURE_ARM64;
    assert(_app_db_decodebody(&db) == STATUS_SUCCESS);
    assert(db.bytes->length == xml->length && !memcmp(db.bytes->buffer, xml->buffer, xml->length));
    test_architecture = PROCESSOR_ARCHITECTURE_AMD64;
    destroy_db(&db);
    _r_obj_dereference(xml);
}
static void check_compressed(USHORT format, const char *name) {
    ULONG size = 104013, work_size = 0, fragment_size = 0, compressed_length = 0;
    PUCHAR plain = malloc(size), compressed = malloc(size * 2), work;
    DB_INFORMATION db = {0};
    BYTE digest[32];
    assert(plain && compressed);
    for (ULONG i = 0; i < size; ++i)
        plain[i] = format == COMPRESSION_FORMAT_XPRESS ? (BYTE)(i % 48) : (BYTE)"abc1234567890"[i % 13];
    assert(NT_SUCCESS(RtlGetCompressionWorkSpaceSize(format, &work_size, &fragment_size)));
    work = malloc(work_size);
    assert(work);
    assert(NT_SUCCESS(RtlCompressBuffer(format, plain, size, compressed,
        size * 2, 4096, &compressed_length, work)));
    assert(compressed_length && size > compressed_length * 128);
    if (format == COMPRESSION_FORMAT_XPRESS) {
        ULONG capacity = compressed_length * 2, returned = 0;
        PUCHAR wrong_format = malloc(capacity);
        NTSTATUS status;
        assert(wrong_format);
        status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, wrong_format, capacity,
                                     compressed, compressed_length, &returned);
        if (NT_SUCCESS(status) && returned < capacity) {
            assert(returned != size || memcmp(wrong_format, plain, returned));
            printf("XPRESS misidentified as LZNT1: %lu bytes\n", returned);
        }
        free(wrong_format);
    }
    {
        R_BYTEREF input = {compressed_length, (char *)compressed};
        PR_BYTE output = (PR_BYTE)1;
        largest_allocation = 0;
        assert(_app_db_decompressbuffer_with_test_limit(format, &input, &output) == STATUS_INSUFFICIENT_RESOURCES);
        assert(output == NULL && largest_allocation == 4096);
    }
    sha256(plain, size, digest);
    db.bytes = _r_obj_createbyte_ex(NULL, PROFILE2_HEADER_LENGTH + compressed_length);
    memcpy(db.bytes->buffer, "swc1", PROFILE2_FOURCC_LENGTH);
    memcpy(db.bytes->buffer + PROFILE2_FOURCC_LENGTH, digest, sizeof(digest));
    memcpy(db.bytes->buffer + PROFILE2_HEADER_LENGTH, compressed, compressed_length);
    assert(_app_db_decodebody(&db) == STATUS_SUCCESS);
    assert(db.bytes->length == size && !memcmp(db.bytes->buffer, plain, size));
    printf("%s profile: %lu compressed -> %lu full bytes, SHA-256 valid\n", name, compressed_length, size);
    destroy_db(&db);
    free(work); free(compressed); free(plain);
}
static void check_nested(const char *profile_path, const char *xml_path) {
    PR_BYTE inner = readfile(profile_path), xml = readfile(xml_path);
    ULONG work_size = 0, fragment_size = 0, compressed_length = 0;
    PUCHAR compressed = malloc(inner->length * 2), work;
    DB_INFORMATION db = {0};
    assert(compressed);
    assert(NT_SUCCESS(RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &work_size, &fragment_size)));
    work = malloc(work_size);
    assert(work);
    assert(NT_SUCCESS(RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1, (PUCHAR)inner->buffer, (ULONG)inner->length,
                                        compressed, (ULONG)inner->length * 2, 4096, &compressed_length, work)));
    db.bytes = _r_obj_createbyte_ex(NULL, PROFILE2_HEADER_LENGTH + compressed_length);
    memcpy(db.bytes->buffer, "swc1", PROFILE2_FOURCC_LENGTH);
    memset(db.bytes->buffer + PROFILE2_FOURCC_LENGTH, 0, PROFILE2_SHA256_LENGTH);
    memcpy(db.bytes->buffer + PROFILE2_HEADER_LENGTH, compressed, compressed_length);
    assert(_app_db_decodebody(&db) == STATUS_MORE_PROCESSING_REQUIRED);
    assert(db.bytes->length == inner->length && !memcmp(db.bytes->buffer, inner->buffer, inner->length));
    assert(_app_db_decodebody(&db) == STATUS_SUCCESS);
    assert(db.bytes->length == xml->length && !memcmp(db.bytes->buffer, xml->buffer, xml->length));
    destroy_db(&db);
    _r_obj_dereference(inner); _r_obj_dereference(xml);
    free(work); free(compressed);
}
static void check_bounds(void) {
    R_BYTEREF input = { PR_SIZE_BUFFER_OVERFLOW / 2 + 1, "x" };
    PR_BYTE output = (PR_BYTE)1;
    assert(_app_db_decompressbuffer(COMPRESSION_FORMAT_LZNT1, &input, &output) == STATUS_INSUFFICIENT_RESOURCES);
    assert(output == NULL);
    input.length = (ULONG_PTR)-1;
    assert(_app_db_decompressbuffer(COMPRESSION_FORMAT_LZNT1, &input, &output) == STATUS_INSUFFICIENT_RESOURCES);
    assert(output == NULL);
    input.length = 0;
    assert(_app_db_decompressbuffer(COMPRESSION_FORMAT_XPRESS, &input, &output) == STATUS_INSUFFICIENT_RESOURCES);
    assert(output == NULL);
}
int main(int argc, char **argv) {
    assert(argc == 3);
    check_internal(argv[1], argv[2]);
    check_compressed(COMPRESSION_FORMAT_LZNT1, "LZNT1");
    check_compressed(COMPRESSION_FORMAT_XPRESS, "XPRESS");
    check_nested(argv[1], argv[2]);
    check_bounds();
    puts("Profile decompression regression passed");
    return 0;
}
'''


if os.name != 'nt':
    raise SystemExit('This regression requires Windows and an MSVC developer command prompt.')

with tempfile.TemporaryDirectory(prefix='simplewall-decompression-') as temporary:
    directory = Path(temporary)
    source = directory / 'test.c'
    executable = directory / 'test.exe'
    decompress = function_source('static NTSTATUS _app_db_decompressbuffer (')
    bounded_copy = ('\n#undef PR_SIZE_BUFFER_OVERFLOW\n#define PR_SIZE_BUFFER_OVERFLOW 4096\n'
                    '#define _app_db_decompressbuffer _app_db_decompressbuffer_with_test_limit\n' +
                    decompress + '\n#undef _app_db_decompressbuffer\n#undef PR_SIZE_BUFFER_OVERFLOW\n'
                    '#define PR_SIZE_BUFFER_OVERFLOW (256 * 1024 * 1024)\n')
    source.write_text(STUBS + decompress + bounded_copy +
                      function_source('NTSTATUS _app_db_decodebody (') + HARNESS, encoding='utf-8')
    subprocess.run(['cl', '/nologo', '/W3', '/WX', '/std:c11', '/D_CRT_SECURE_NO_WARNINGS',
                    str(source), '/Fe:' + str(executable), '/link', 'ntdll.lib', 'bcrypt.lib'],
                   cwd=directory, check=True)
    subprocess.run([str(executable), str(ROOT / 'bin' / 'profile_internal.sp'),
                    str(ROOT / 'bin' / 'profile_internal.xml')], check=True)
