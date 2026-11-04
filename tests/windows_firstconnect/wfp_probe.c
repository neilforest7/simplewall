/* Read-only assertions and a net-event subscriber for the first-connect test. */
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

static const GUID provider_key = {0xb0d553e2,0xc6a0,0x4a9a,{0xae,0xb8,0xc7,0x52,0x48,0x3e,0xd6,0x2f}};
static const GUID sublayer_key = {0x9fee6f59,0xb951,0x4f9a,{0xb5,0x2f,0x13,0x3d,0xcf,0x7a,0x42,0x79}};
static const wchar_t auto_name[] = L"User rule\\ci-first-connect";
static const wchar_t default_name[] = L"Internal\\BlockConnection";

static int same_app(const FWP_BYTE_BLOB *a, const FWP_BYTE_BLOB *b)
{
    return a && b && a->data && b->data && a->size == b->size &&
        memcmp(a->data, b->data, a->size) == 0;
}

static int scoped_allow(const FWPM_FILTER0 *f, const FWP_BYTE_BLOB *app, UINT16 port)
{
    unsigned seen = 0;
    if (!IsEqualGUID(&f->layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
        !IsEqualGUID(&f->subLayerKey, &sublayer_key) ||
        f->action.type != FWP_ACTION_PERMIT || f->weight.type != FWP_UINT8 ||
        f->weight.uint8 != 0x0b || f->numFilterConditions != 3 ||
        (f->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_DISABLED))) return 0;
    for (UINT32 i = 0; i < f->numFilterConditions; ++i) {
        const FWPM_FILTER_CONDITION0 *c = &f->filterCondition[i];
        if (c->matchType != FWP_MATCH_EQUAL) return 0;
        if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_ALE_APP_ID) &&
            c->conditionValue.type == FWP_BYTE_BLOB_TYPE && same_app(c->conditionValue.byteBlob, app)) seen |= 1;
        else if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT) &&
            c->conditionValue.type == FWP_UINT16 && c->conditionValue.uint16 == port) seen |= 2;
        else if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_PROTOCOL) &&
            c->conditionValue.type == FWP_UINT8 && c->conditionValue.uint8 == IPPROTO_TCP) seen |= 4;
        else return 0;
    }
    return seen == 7;
}

static int is_default(const FWPM_FILTER0 *f)
{
    return f->providerKey && IsEqualGUID(f->providerKey, &provider_key) &&
        IsEqualGUID(&f->subLayerKey, &sublayer_key) &&
        IsEqualGUID(&f->layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) &&
        f->displayData.description && !wcscmp(f->displayData.description, default_name) &&
        f->weight.type == FWP_UINT8 && f->weight.uint8 == 0x08 &&
        f->numFilterConditions == 0 &&
        !(f->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_DISABLED)) &&
        (f->action.type == FWP_ACTION_BLOCK ||
         (f->action.type == FWP_ACTION_CALLOUT_TERMINATING &&
          IsEqualGUID(&f->action.calloutKey, &FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4)));
}

static int is_dns(const FWPM_FILTER0 *f, const FWP_BYTE_BLOB *svchost)
{
    unsigned seen = 0;
    if (!f->displayData.description || wcscmp(f->displayData.description, L"System rule\\DNS") ||
        !IsEqualGUID(&f->layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
        !IsEqualGUID(&f->subLayerKey, &sublayer_key) ||
        f->action.type != FWP_ACTION_PERMIT || f->weight.type != FWP_UINT8 || f->weight.uint8 != 0x0a ||
        (f->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_DISABLED))) return 0;
    for (UINT32 i = 0; i < f->numFilterConditions; ++i) {
        const FWPM_FILTER_CONDITION0 *c = &f->filterCondition[i];
        if (c->matchType != FWP_MATCH_EQUAL) continue;
        if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_ALE_APP_ID) &&
            c->conditionValue.type == FWP_BYTE_BLOB_TYPE && same_app(c->conditionValue.byteBlob, svchost)) seen |= 1;
        if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT) &&
            c->conditionValue.type == FWP_UINT16 && c->conditionValue.uint16 == 53) seen |= 2;
        if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_IP_PROTOCOL) &&
            c->conditionValue.type == FWP_UINT8 && c->conditionValue.uint8 == IPPROTO_UDP) seen |= 4;
    }
    return seen == 7;
}

/* Check every provider filter across all layers, including the embedded DNS rule. */
static int snapshot(const wchar_t *path, UINT16 port, int after, UINT64 old_id)
{
    HANDLE engine = NULL, lh = NULL, fh = NULL;
    FWPM_PROVIDER0 *provider = NULL;
    FWPM_SUBLAYER0 *sublayer = NULL;
    FWPM_LAYER0 **layers = NULL;
    FWPM_FILTER0 **filters = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 query = {0};
    FWP_BYTE_BLOB *expected = NULL, *svchost = NULL;
    UINT32 layer_count = 0, count = 0, dns = 0, automatic = 0, target = 0;
    UINT64 default_id = 0;
    DWORD status = ERROR_SUCCESS;
    int result = 1, transaction = 0, invalid = 0;
    wchar_t system_dir[MAX_PATH], svchost_path[MAX_PATH];
    UINT system_length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (!system_length || system_length >= MAX_PATH ||
        swprintf_s(svchost_path, MAX_PATH, L"%ls\\svchost.exe", system_dir) < 0) {
        status = ERROR_INSUFFICIENT_BUFFER;
        goto done;
    }
    status = FwpmGetAppIdFromFileName0(svchost_path, &svchost);
    if (status) goto done;
    status = FwpmGetAppIdFromFileName0(path, &expected);
    if (status) goto done;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (status) goto done;
    status = FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY);
    if (status) goto done;
    transaction = 1;
    status = FwpmProviderGetByKey0(engine, &provider_key, &provider);
    if (status) goto done;
    status = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
    if (status) goto done;
    if ((provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT) ||
        (sublayer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT)) invalid = 1;
    query.providerKey = (GUID *)&provider_key;
    query.actionMask = 0xffffffffu;
    query.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    status = FwpmLayerCreateEnumHandle0(engine, NULL, &lh);
    if (status) goto done;
    do {
        status = FwpmLayerEnum0(engine, lh, 128, &layers, &layer_count);
        if (status) goto done;
        for (UINT32 i = 0; i < layer_count; ++i) {
            query.layerKey = layers[i]->layerKey;
            status = FwpmFilterCreateEnumHandle0(engine, &query, &fh);
            if (status) goto done;
            do {
                status = FwpmFilterEnum0(engine, fh, 256, &filters, &count);
                if (status) goto done;
                for (UINT32 j = 0; j < count; ++j) {
                    FWPM_FILTER0 *f = filters[j];
                    const wchar_t *name = f->displayData.description ? f->displayData.description : L"";
                    if (is_default(f) && f->action.type == FWP_ACTION_BLOCK) default_id = f->filterId;
                    if (is_dns(f, svchost)) ++dns;
                    for (UINT32 k = 0; k < f->numFilterConditions; ++k) {
                        FWPM_FILTER_CONDITION0 *c = &f->filterCondition[k];
                        if (IsEqualGUID(&c->fieldKey, &FWPM_CONDITION_ALE_APP_ID) &&
                            c->conditionValue.type == FWP_BYTE_BLOB_TYPE && same_app(c->conditionValue.byteBlob, expected)) ++target;
                    }
                    if (!wcscmp(name, auto_name)) {
                        ++automatic;
                        if (!scoped_allow(f, expected, port)) invalid = 1;
                    }
                }
                if (filters) FwpmFreeMemory0((void **)&filters);
            } while (count);
            status = FwpmFilterDestroyEnumHandle0(engine, fh);
            if (status) goto done;
            fh = NULL;
        }
        if (layers) FwpmFreeMemory0((void **)&layers);
    } while (layer_count);
    status = FwpmTransactionCommit0(engine);
    if (status) goto done;
    transaction = 0;
    wprintf(L"default=%llu internal_dns=%lu automatic=%lu target_conditions=%lu invalid=%d\n",
        (unsigned long long)default_id, dns, automatic, target, invalid);
    if (invalid || (!after && (automatic || target))) result = 3;
    else if (!default_id || default_id == old_id || !dns || (after && (!automatic || target != automatic))) result = 2;
    else result = 0;
done:
    if (result == 1) fwprintf(stderr, L"WFP snapshot failed: 0x%08lx\n", status);
    if (filters) FwpmFreeMemory0((void **)&filters);
    if (layers) FwpmFreeMemory0((void **)&layers);
    if (fh) FwpmFilterDestroyEnumHandle0(engine, fh);
    if (lh) FwpmLayerDestroyEnumHandle0(engine, lh);
    if (transaction) FwpmTransactionAbort0(engine);
    if (provider) FwpmFreeMemory0((void **)&provider);
    if (sublayer) FwpmFreeMemory0((void **)&sublayer);
    if (expected) FwpmFreeMemory0((void **)&expected);
    if (svchost) FwpmFreeMemory0((void **)&svchost);
    if (engine) FwpmEngineClose0(engine);
    return result;
}

typedef struct WATCH {
    FWP_BYTE_BLOB *app;
    UINT16 port;
    HANDLE ready;
    volatile LONG found;
    UINT64 filter_id;
} WATCH;

static void CALLBACK on_event(void *context, const FWPM_NET_EVENT1 *event)
{
    WATCH *watch = (WATCH *)context;
    const UINT32 required = FWPM_NET_EVENT_FLAG_APP_ID_SET | FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET |
        FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET;
    if (event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || !event->classifyDrop ||
        (event->header.flags & required) != required || event->header.ipProtocol != IPPROTO_TCP ||
        event->header.remotePort != watch->port || !same_app(&event->header.appId, watch->app)) return;
    if (InterlockedCompareExchange(&watch->found, 1, 0) == 0) {
        watch->filter_id = event->classifyDrop->filterId;
        SetEvent(watch->ready);
    }
}

static int watch_drop(const wchar_t *path, UINT16 port)
{
    HANDLE engine = NULL, subscription_handle = NULL;
    FWPM_NET_EVENT_ENUM_TEMPLATE0 query = {0};
    FWPM_NET_EVENT_SUBSCRIPTION0 subscription = {0};
    FWPM_FILTER0 *filter = NULL;
    WATCH watch = {0};
    DWORD status = ERROR_SUCCESS;
    int result = 1;
    watch.port = port;
    watch.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!watch.ready) { status = GetLastError(); goto done; }
    status = FwpmGetAppIdFromFileName0(path, &watch.app);
    if (status) goto done;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (status) goto done;
    subscription.enumTemplate = &query;
    status = FwpmNetEventSubscribe0(engine, &subscription, on_event, &watch, &subscription_handle);
    if (status) goto done;
    puts("READY");
    fflush(stdout);
    if (WaitForSingleObject(watch.ready, 20000) != WAIT_OBJECT_0) {
        fprintf(stderr, "No matching WFP classify-drop event within 20 seconds.\n");
        goto done;
    }
    status = FwpmFilterGetById0(engine, watch.filter_id, &filter);
    if (status) goto done;
    if (!is_default(filter)) {
        fwprintf(stderr, L"Drop came from unexpected filter %llu (%ls).\n",
            (unsigned long long)watch.filter_id,
            filter->displayData.description ? filter->displayData.description : L"");
        goto done;
    }
    printf("default_drop_filter=%llu\n", (unsigned long long)watch.filter_id);
    result = 0;
done:
    if (result) fwprintf(stderr, L"WFP event subscription/check failed: 0x%08lx\n", status);
    if (subscription_handle) FwpmNetEventUnsubscribe0(engine, subscription_handle);
    if (filter) FwpmFreeMemory0((void **)&filter);
    if (watch.app) FwpmFreeMemory0((void **)&watch.app);
    if (watch.ready) CloseHandle(watch.ready);
    if (engine) FwpmEngineClose0(engine);
    return result;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t *end = NULL;
    unsigned long port;
    if (argc < 4) return 1;
    port = wcstoul(argv[3], &end, 10);
    if (*end || !port || port > 65535) return 1;
    if (argc == 4 && !wcscmp(argv[1], L"watch")) return watch_drop(argv[2], (UINT16)port);
    if (argc == 6 && (!wcscmp(argv[1], L"before") || !wcscmp(argv[1], L"after"))) {
        UINT64 old_id = _wcstoui64(argv[4], &end, 10);
        if (*end || wcscmp(argv[5], L"ci-first-connect")) return 1;
        return snapshot(argv[2], (UINT16)port, !wcscmp(argv[1], L"after"), old_id);
    }
    fwprintf(stderr, L"usage: wfp_probe watch PATH PORT | before|after PATH PORT OLD_ID ci-first-connect\n");
    return 1;
}
