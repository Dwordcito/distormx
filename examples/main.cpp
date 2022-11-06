#include "../../include/distormx.h"
#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef void (WINAPI * LdrLoadDll_t)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);

LdrLoadDll_t g_orig_LdrLoadDll = NULL;

__declspec(noinline) __stdcall void LdrLoadDll_hook(PWSTR a, ULONG b, PUNICODE_STRING c, PHANDLE d)
{
    std::cout << "LdrLoadDll_hook "<< std::endl;
    std::wcout << "DLL Load: " << c->Buffer << std::endl;
    g_orig_LdrLoadDll(a, b, c, d);
}

int main()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cout << "failed to get ntdll handle"<< std::endl;
        return 1;
    }

    g_orig_LdrLoadDll = (LdrLoadDll_t)GetProcAddress(ntdll, "LdrLoadDll");
    if (!g_orig_LdrLoadDll) {
        std::cout << "failed to get LdrLoadDll address"<< std::endl;
        return 1;
    }

    if (!distormx_hook((void **)&g_orig_LdrLoadDll, (void *)LdrLoadDll_hook)) {
        std::cout << "failed hooking"<< std::endl;
        return 1;
    } else {
        std::cout << "hooked"<< std::endl;
    }

    // Load a dll
    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    if (!kernel32) {
        std::cout << "failed to load kernel32.dll"<< std::endl;
        return 1;
    }



    distormx_unhook((void *)&g_orig_LdrLoadDll);
    std::cout << "unhooked"<< std::endl;

    distormx_destroy();

    return 0;
}
