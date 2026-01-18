#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <Shlwapi.h>
#include "MinHook.h"
#include "idcrl.h"
#include "winsock.h"
#include "winhttp.h"
#include "ini.h"

#pragma comment(lib, "Shlwapi.lib")


ini_t* g_Config = NULL;
HMODULE g_GfLLmodule = NULL;
bool g_InitializedModule = false;

static DWORD(WINAPI* PathStripPathW_orig)(LPWSTR pszPath);
void WINAPI PathStripPathW_new(LPWSTR pszPath)
{
    PathStripPathW_orig(pszPath);

    /*
        This is a bypass of an anti-tamper measure; xlive.dll supports "protecting" LoadLibrary calls.
        It does this by verifying the signature of the file on-disk when loading a DLL...
        Specifically, *after already having loaded the DLL*. Lol. TOC TOU-AH!

        The process goes something like this:
        - xlive function calls the protected load library function
         - LoadLibraryExW gets called to actually load the DLL
         - PathStripPathW (this) is called to get just the filename of the DLL in case it's in a subdirectory
         - GetModuleHandleW and GetModuleFileNameW are called to get the full file path of the DLL on disk
         - That file is loaded into memory and has its signature checked, either with the catalog file or Microsoft's public key.

        So the attack here is make PathStripPathW return the name of the *original* msidcrl library that we load in idcrl.c.
        This means that despite xlive loading *our* msidcrl40 (unsigned), it'll validate the signature of the original (signed).
    */
    if (wcscmp(pszPath, L"msidcrl40.dll") == 0)
        wcscpy(pszPath, L"msidcrl67.dll");
}



// initializes the patches set up by the gfll DLL
void InitializeGfLL()
{
    // load config because we need it further in msidcrl stuff
    char msidcrl_path[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA("msidcrl40.dll"), msidcrl_path, MAX_PATH);
    PathRemoveFileSpecA(msidcrl_path);
    char config_path[MAX_PATH];
    sprintf_s(config_path, MAX_PATH, "%s/patcher_conf.ini", msidcrl_path);
    g_Config = ini_load(config_path);
    if (!g_Config) {
        // uh-oh!
        MessageBoxA(NULL, "patcher_conf.ini failed to load from msidcrl40 location thus patches ARE NOT applied.", "Config load failure", 0x10);
        return;
    }

    MH_Initialize();
    InitializeWinSock();
    InitializeWinHTTP();
    MH_CreateHookApi(L"shlwapi.dll", "PathStripPathW", (LPVOID)PathStripPathW_new, (LPVOID*)&PathStripPathW_orig);
    MH_EnableHook(MH_ALL_HOOKS);

    g_InitializedModule = true;
}

// checks if the current process is a GfWL game by seeing if it imports xlive.dll
bool IsCurrentProcessGfWL()
{
    // get the handle (pointer) to the game's base module
    HMODULE currentProcess = GetModuleHandleA(NULL);
    if (currentProcess == NULL) return false;
    uint8_t* procPtr = (uint8_t*)currentProcess;

    // get the NT header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)procPtr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(procPtr + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        return false;

    // read and iterate over the DLL import table
    IMAGE_DATA_DIRECTORY importData = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importData.VirtualAddress == NULL)
        return false;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(procPtr + importData.VirtualAddress);
    int numImports = importData.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (int i = 0; i < numImports; i++)
    {
        // check if it's the GfWL runtime
        const char* dll = (const char*)(procPtr + importDesc[i].Name);
        if (_stricmp(dll, "xlive.dll") == 0)
            return true;
    }

    // didn't find it :(
    return false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // make sure we're a GfWL game before doing anything
        g_GfLLmodule = hModule;
        InitializeGfLL();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
