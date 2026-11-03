/* Read-only inventory for the simplewall provider and its sublayer. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <rpc.h>
#include <fwpmu.h>
#include <stdio.h>

static const GUID provider_key = {0xb0d553e2,0xc6a0,0x4a9a,{0xae,0xb8,0xc7,0x52,0x48,0x3e,0xd6,0x2f}};
static const GUID sublayer_key = {0x9fee6f59,0xb951,0x4f9a,{0xb5,0x2f,0x13,0x3d,0xcf,0x7a,0x42,0x79}};
int wmain(void)
{
    HANDLE engine = NULL, fh = NULL, ch = NULL, lh = NULL;
    FWPM_PROVIDER0 *provider = NULL;
    FWPM_SUBLAYER0 *sublayer = NULL;
    FWPM_FILTER0 **filters = NULL;
    FWPM_CALLOUT0 **callouts = NULL;
    FWPM_LAYER0 **layers = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 query = {0};
    UINT32 count = 0, layer_count = 0, i, found = 0;
    DWORD status;
    int transaction = 0, result = 1;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (status) goto done;
    status = FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY);
    if (status) goto done;
    transaction = 1;
    status = FwpmProviderGetByKey0(engine, &provider_key, &provider);
    if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND) goto done;
    if (provider) ++found;
    status = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
    if (status != ERROR_SUCCESS && status != FWP_E_SUBLAYER_NOT_FOUND) goto done;
    if (sublayer) ++found;
    query.actionMask = 0xffffffffu;
    query.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    status = FwpmLayerCreateEnumHandle0(engine, NULL, &lh);
    if (status) goto done;
    do {
        status = FwpmLayerEnum0(engine, lh, 128, &layers, &layer_count);
        if (status) goto done;
        for (UINT32 layer = 0; layer < layer_count; ++layer) {
            query.layerKey = layers[layer]->layerKey;
            status = FwpmFilterCreateEnumHandle0(engine, &query, &fh);
            if (status) goto done;
            do {
                status = FwpmFilterEnum0(engine, fh, 256, &filters, &count);
                if (status) goto done;
                for (i = 0; i < count; ++i)
                    if ((filters[i]->providerKey && IsEqualGUID(filters[i]->providerKey, &provider_key)) ||
                        IsEqualGUID(&filters[i]->subLayerKey, &sublayer_key)) ++found;
                if (filters) FwpmFreeMemory0((void **)&filters);
            } while (count);
            status = FwpmFilterDestroyEnumHandle0(engine, fh);
            if (status) goto done;
            fh = NULL;
        }
        if (layers) FwpmFreeMemory0((void **)&layers);
    } while (layer_count);
    status = FwpmCalloutCreateEnumHandle0(engine, NULL, &ch);
    if (status) goto done;
    do {
        status = FwpmCalloutEnum0(engine, ch, 256, &callouts, &count);
        if (status) goto done;
        for (i = 0; i < count; ++i)
            if (callouts[i]->providerKey && IsEqualGUID(callouts[i]->providerKey, &provider_key)) ++found;
        if (callouts) FwpmFreeMemory0((void **)&callouts);
    } while (count);
    status = FwpmTransactionCommit0(engine);
    if (status) goto done;
    transaction = 0;
    wprintf(L"simplewall WFP objects: %u\n", found);
    result = found ? 2 : 0;
done:
    if (result == 1) fwprintf(stderr, L"WFP inventory failed: 0x%08lx\n", status);
    if (filters) FwpmFreeMemory0((void **)&filters);
    if (callouts) FwpmFreeMemory0((void **)&callouts);
    if (layers) FwpmFreeMemory0((void **)&layers);
    if (fh) FwpmFilterDestroyEnumHandle0(engine, fh);
    if (ch) FwpmCalloutDestroyEnumHandle0(engine, ch);
    if (lh) FwpmLayerDestroyEnumHandle0(engine, lh);
    if (transaction) FwpmTransactionAbort0(engine);
    if (provider) FwpmFreeMemory0((void **)&provider);
    if (sublayer) FwpmFreeMemory0((void **)&sublayer);
    if (engine) FwpmEngineClose0(engine);
    return result;
}
