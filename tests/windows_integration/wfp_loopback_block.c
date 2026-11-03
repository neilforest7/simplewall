/* The session lives until stdin closes; BFE then removes its dynamic filter. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <rpc.h>
#include <initguid.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static const GUID sublayer = {0x9fee6f59, 0xb951, 0x4f9a,
    {0xb5, 0x2f, 0x13, 0x3d, 0xcf, 0x7a, 0x42, 0x79}};

int wmain(int argc, wchar_t **argv)
{
    HANDLE engine = NULL;
    FWPM_SESSION0 session = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_FILTER_CONDITION0 conditions[4] = {0};
    UINT64 id = 0;
    DWORD status;
    wchar_t *end;
    unsigned long port;
    if (argc != 3) return 1;
    port = wcstoul(argv[1], &end, 10);
    if (*end || port < 1 || port > 65535) return 1;
    status = UuidFromStringW((RPC_WSTR)argv[2], &filter.filterKey);
    if (status != RPC_S_OK) goto failure;
    session.displayData.name = L"simplewall integration loopback";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    if (status != ERROR_SUCCESS) goto failure;

    conditions[0].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
    conditions[0].conditionValue.type = FWP_UINT32;
    conditions[0].conditionValue.uint32 = 0x7f000001u;
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[1].conditionValue.type = FWP_UINT32;
    conditions[1].conditionValue.uint32 = 0x7f000001u;
    conditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[2].conditionValue.type = FWP_UINT16;
    conditions[2].conditionValue.uint16 = (UINT16)port;
    conditions[3].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[3].conditionValue.type = FWP_UINT8;
    conditions[3].conditionValue.uint8 = IPPROTO_TCP;
    for (unsigned int i = 0; i < 4; ++i) conditions[i].matchType = FWP_MATCH_EQUAL;
    filter.displayData.name = L"simplewall integration loopback block";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = sublayer;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0a; /* Between user permits (0x0b) and default (0x08). */
    filter.action.type = FWP_ACTION_BLOCK;
    filter.filterCondition = conditions;
    filter.numFilterConditions = 4;
    /* No provider: simplewall's rebuild must not delete this test-owned filter. */
    status = FwpmFilterAdd0(engine, &filter, NULL, &id);
    if (status != ERROR_SUCCESS) goto failure;
    printf("READY %llu\n", (unsigned long long)id);
    fflush(stdout);
    (void)getchar();
    status = FwpmEngineClose0(engine);
    if (status != ERROR_SUCCESS) goto failure_no_engine;
    return 0;
failure:
    if (engine) FwpmEngineClose0(engine);
failure_no_engine:
    fprintf(stderr, "WFP loopback block failed: 0x%08lx\n", status);
    return 1;
}
