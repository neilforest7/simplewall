/* Confirm only the dialog belonging to the test's uninstall process. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static DWORD target;
static int clicked;

static BOOL CALLBACK visit(HWND window, LPARAM ignored)
{
    DWORD pid = 0;
    wchar_t class_name[32];
    DWORD_PTR result;
    (void)ignored;
    GetWindowThreadProcessId(window, &pid);
    if (pid != target || !IsWindowVisible(window) ||
        !GetClassNameW(window, class_name, 32) || wcscmp(class_name, L"#32770") ||
        !GetDlgItem(window, IDYES)) return TRUE;
    /* Never request the optional Windows Firewall state change. */
    if (!SendMessageTimeoutW(window, TDM_CLICK_VERIFICATION, FALSE, FALSE,
                             SMTO_ABORTIFHUNG, 2000, &result)) return TRUE;
    if (!SendMessageTimeoutW(window, TDM_CLICK_BUTTON, IDYES, 0,
                             SMTO_ABORTIFHUNG, 2000, &result)) return TRUE;
    clicked = 1;
    return FALSE;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 2 || !(target = wcstoul(argv[1], NULL, 10))) return 1;
    for (int i = 0; i < 100 && !clicked; ++i) {
        EnumWindows(visit, 0);
        if (!clicked) Sleep(100);
    }
    wprintf(L"uninstall_dialog_confirmed=%d\n", clicked);
    return clicked ? 0 : 1;
}
