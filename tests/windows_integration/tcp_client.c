/* Separate executable identities, each restricted to an IPv4 loopback probe. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    WSADATA data;
    SOCKET socket_handle = INVALID_SOCKET;
    struct sockaddr_in local = {0}, remote = {0};
    char *end;
    unsigned long port;
    int result = 1, error;
    DWORD timeout = 3000;
    if (argc != 2) return 1;
    port = strtoul(argv[1], &end, 10);
    if (*end || port < 1 || port > 65535) return 1;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
    socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) goto cleanup;
    setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(socket_handle, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR) {
        fprintf(stderr, "bind error=%d\n", WSAGetLastError());
        goto cleanup;
    }
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote.sin_port = htons((u_short)port);
    if (connect(socket_handle, (struct sockaddr *)&remote, sizeof(remote)) == 0) {
        puts("connected");
        result = 0;
    } else {
        error = WSAGetLastError();
        fprintf(stderr, "connect error=%d\n", error);
        /* A refusal or timeout can also mean the listener failed: do not count it. */
        if (error == WSAEACCES) result = 13;
    }
cleanup:
    if (socket_handle != INVALID_SOCKET) closesocket(socket_handle);
    WSACleanup();
    return result;
}
