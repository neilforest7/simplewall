/* Enumerate simplewall objects; never alter WFP. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <rpc.h>
#include <initguid.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static const GUID provider_key = {0xb0d553e2, 0xc6a0, 0x4a9a,
    {0xae, 0xb8, 0xc7, 0x52, 0x48, 0x3e, 0xd6, 0x2f}};
static const GUID sublayer_key = {0x9fee6f59, 0xb951, 0x4f9a,
    {0xb5, 0x2f, 0x13, 0x3d, 0xcf, 0x7a, 0x42, 0x79}};

static int check_gone_key(const wchar_t *text)
{
    HANDLE engine = NULL;
    FWPM_FILTER0 *filter = NULL;
    GUID key;
    DWORD status = UuidFromStringW((RPC_WSTR)text, &key);
    int result = 1;
    if (status != RPC_S_OK) goto done;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (status != ERROR_SUCCESS) goto done;
    status = FwpmFilterGetByKey0(engine, &key, &filter);
    if (status == FWP_E_FILTER_NOT_FOUND) { wprintf(L"dynamic_filter_key_absent\n"); result = 0; }
    else if (status == ERROR_SUCCESS) { fwprintf(stderr, L"dynamic filter key still exists\n"); result = 2; }
done:
    if (result == 1) fwprintf(stderr, L"WFP filter key lookup failed: 0x%08lx\n", status);
    if (filter) FwpmFreeMemory0((void **)&filter);
    if (engine) FwpmEngineClose0(engine);
    return result;
}

static int check_block(int argc, wchar_t **argv)
{
    HANDLE engine = NULL;
    FWPM_FILTER0 *filter = NULL;
    UINT64 id;
    DWORD status;
    wchar_t *end;
    unsigned long port = 0;
    unsigned seen = 0;
    int gone = wcscmp(argv[1], L"gone") == 0, bad = 0, result = 1;
    if ((gone && argc != 3) || (!gone && argc != 4)) return 1;
    id = _wcstoui64(argv[2], &end, 10);
    if (!id || *end) return 1;
    if (!gone) {
        port = wcstoul(argv[3], &end, 10);
        if (*end || !port || port > 65535) return 1;
    }
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (status != ERROR_SUCCESS) goto error;
    status = FwpmFilterGetById0(engine, id, &filter);
    if (status == FWP_E_FILTER_NOT_FOUND && gone) {
        wprintf(L"dynamic_filter_absent=%llu\n", (unsigned long long)id);
        result = 0;
        goto cleanup;
    }
    if (status != ERROR_SUCCESS) goto error;
    if (gone) {
        fwprintf(stderr, L"dynamic filter still exists: %llu\n", (unsigned long long)id);
        goto cleanup;
    }
    if (!IsEqualGUID(&filter->layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
        !IsEqualGUID(&filter->subLayerKey, &sublayer_key) || filter->providerKey ||
        filter->action.type != FWP_ACTION_BLOCK || filter->weight.type != FWP_UINT8 ||
        filter->weight.uint8 != 0x0a || filter->numFilterConditions != 4 ||
        (filter->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME))) bad = 1;
    for (UINT32 i = 0; i < filter->numFilterConditions; ++i) {
        FWPM_FILTER_CONDITION0 *c = &filter->filterCondition[i];
        if (c->matchType != FWP_MATCH_EQUAL) { bad = 1; continue; }
        if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_LOCAL_ADDRESS) &&
            c->conditionValue.type == FWP_UINT32 && c->conditionValue.uint32 == 0x7f000001u) seen |= 1;
        else if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_REMOTE_ADDRESS) &&
            c->conditionValue.type == FWP_UINT32 && c->conditionValue.uint32 == 0x7f000001u) seen |= 2;
        else if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT) &&
            c->conditionValue.type == FWP_UINT16 && c->conditionValue.uint16 == port) seen |= 4;
        else if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_PROTOCOL) &&
            c->conditionValue.type == FWP_UINT8 && c->conditionValue.uint8 == IPPROTO_TCP) seen |= 8;
        else bad = 1;
    }
    wprintf(L"dynamic_filter=%llu conditions=%u valid=%u\n", (unsigned long long)id, seen, !bad && seen == 15);
    result = (!bad && seen == 15) ? 0 : 2;
    goto cleanup;
error:
    fwprintf(stderr, L"WFP filter lookup failed: 0x%08lx\n", status);
cleanup:
    if (filter) FwpmFreeMemory0((void **)&filter);
    if (engine) FwpmEngineClose0(engine);
    return result;
}

int wmain(int argc, wchar_t **argv)
{
    HANDLE engine = NULL, enumeration = NULL, callout_enumeration = NULL, layer_enumeration = NULL;
    FWPM_PROVIDER0 *provider = NULL;
    FWPM_SUBLAYER0 *sublayer = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 query = {0};
    FWPM_FILTER0 **filters = NULL;
    FWPM_CALLOUT0 **callouts = NULL;
    FWPM_LAYER0 **layers = NULL;
    FWP_BYTE_BLOB *expected = NULL;
    UINT32 count = 0, layer_count = 0, total = 0, matched = 0, callout_count = 0;
    DWORD status = ERROR_SUCCESS;
    int result = 1, bad = 0, empty, transaction = 0;
    wchar_t description[256];

    if (argc == 3 && !wcscmp(argv[1], L"gone-key")) return check_gone_key(argv[2]);
    if (argc >= 2 && (!wcscmp(argv[1], L"block") || !wcscmp(argv[1], L"gone")))
        return check_block(argc, argv);
    if (argc != 2 && argc != 4) {
        fwprintf(stderr, L"usage: wfp_inventory empty | rule NAME PATH_OR_DASH\n");
        return 1;
    }
    empty = wcscmp(argv[1], L"empty") == 0;
    if ((!empty && (argc != 4 || wcscmp(argv[1], L"rule") != 0)) ||
        (empty && argc != 2)) return 1;
    if (!empty) {
        if (swprintf_s(description, 256, L"User rule\\%ls", argv[2]) < 0) return 1;
        if (wcscmp(argv[3], L"-") != 0) {
            status = FwpmGetAppIdFromFileName0(argv[3], &expected);
            if (status != ERROR_SUCCESS) goto error;
        }
    }
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (status != ERROR_SUCCESS) goto error;
    status = FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY);
    if (status != ERROR_SUCCESS) goto error;
    transaction = 1;
    status = FwpmProviderGetByKey0(engine, &provider_key, &provider);
    if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND) goto error;
    status = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
    if (status != ERROR_SUCCESS && status != FWP_E_SUBLAYER_NOT_FOUND) goto error;
    wprintf(L"provider=%u sublayer=%u\n", provider != NULL, sublayer != NULL);
    if (provider && (provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT)) bad = 1;
    if (sublayer && (sublayer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT)) bad = 1;

    /* A NULL template spans all layers; filter the results by provider below. */
    status = FwpmCalloutCreateEnumHandle0(engine, NULL, &callout_enumeration);
    if (status != ERROR_SUCCESS) goto error;
    do {
        status = FwpmCalloutEnum0(engine, callout_enumeration, 128, &callouts, &count);
        if (status != ERROR_SUCCESS) goto error;
        for (UINT32 i = 0; i < count; ++i) {
            if (callouts[i]->providerKey && IsEqualGUID(callouts[i]->providerKey, &provider_key))
                ++callout_count;
        }
        if (callouts) FwpmFreeMemory0((void **)&callouts);
    } while (count);

    query.providerKey = (GUID *)&provider_key;
    query.actionMask = 0xffffffffu;
    query.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    status = FwpmLayerCreateEnumHandle0(engine, NULL, &layer_enumeration);
    if (status != ERROR_SUCCESS) goto error;
    do {
        status = FwpmLayerEnum0(engine, layer_enumeration, 128, &layers, &layer_count);
        if (status != ERROR_SUCCESS) goto error;
        for (UINT32 layer = 0; layer < layer_count; ++layer) {
            query.layerKey = layers[layer]->layerKey;
            status = FwpmFilterCreateEnumHandle0(engine, &query, &enumeration);
            if (status != ERROR_SUCCESS) goto error;
            do {
                status = FwpmFilterEnum0(engine, enumeration, 128, &filters, &count);
                if (status != ERROR_SUCCESS) goto error;
                for (UINT32 i = 0; i < count; ++i) {
                    FWPM_FILTER0 *f = filters[i];
                    const wchar_t *name = f->displayData.description ? f->displayData.description : L"";
                    ++total;
                    wprintf(L"filter id=%llu flags=0x%08lx action=0x%08lx conditions=%lu %ls\n",
                        (unsigned long long)f->filterId, f->flags, f->action.type,
                        f->numFilterConditions, name);
                    if (f->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME)) bad = 1;
                    if (f->action.type != FWP_ACTION_PERMIT) bad = 1;
                    if (!empty && wcscmp(name, description) == 0) {
                        unsigned appids = 0;
                        ++matched;
                        for (UINT32 j = 0; j < f->numFilterConditions; ++j) {
                            FWPM_FILTER_CONDITION0 *c = &f->filterCondition[j];
                            if (!IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_ALE_APP_ID)) continue;
                            ++appids;
                            if (!expected || c->matchType != FWP_MATCH_EQUAL ||
                                c->conditionValue.type != FWP_BYTE_BLOB_TYPE ||
                                !c->conditionValue.byteBlob ||
                                c->conditionValue.byteBlob->size != expected->size ||
                                memcmp(c->conditionValue.byteBlob->data, expected->data, expected->size) != 0)
                                bad = 1;
                        }
                        if (appids != 1 || f->action.type != FWP_ACTION_PERMIT) bad = 1;
                    }
                }
                if (filters) FwpmFreeMemory0((void **)&filters);
            } while (count);
            status = FwpmFilterDestroyEnumHandle0(engine, enumeration);
            if (status != ERROR_SUCCESS) goto error;
            enumeration = NULL;
        }
        if (layers) FwpmFreeMemory0((void **)&layers);
    } while (layer_count);
    wprintf(L"filter_count=%lu callout_count=%lu rule_count=%lu safety_error=%d\n", total, callout_count, matched, bad);
    if (empty) result = (provider || sublayer || total || callout_count) ? 2 : 0;
    else result = (!provider || !sublayer || !total || callout_count || bad || (expected ? matched == 0 : matched != 0)) ? 2 : 0;
    status = FwpmTransactionCommit0(engine);
    if (status != ERROR_SUCCESS) goto error;
    transaction = 0;
    goto cleanup;
error:
    fwprintf(stderr, L"WFP query failed: 0x%08lx\n", status);
    result = 1;
cleanup:
    if (filters) FwpmFreeMemory0((void **)&filters);
    if (callouts) FwpmFreeMemory0((void **)&callouts);
    if (layers) FwpmFreeMemory0((void **)&layers);
    if (enumeration) FwpmFilterDestroyEnumHandle0(engine, enumeration);
    if (layer_enumeration) FwpmLayerDestroyEnumHandle0(engine, layer_enumeration);
    if (callout_enumeration) FwpmCalloutDestroyEnumHandle0(engine, callout_enumeration);
    if (transaction) FwpmTransactionAbort0(engine);
    if (provider) FwpmFreeMemory0((void **)&provider);
    if (sublayer) FwpmFreeMemory0((void **)&sublayer);
    if (expected) FwpmFreeMemory0((void **)&expected);
    if (engine) FwpmEngineClose0(engine);
    return result;
}
