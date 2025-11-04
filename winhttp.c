#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "MinHook.h"

static HINTERNET(WINAPI* WinHttpConnect_orig)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
HINTERNET WINAPI WinHttpConnect_hook(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
{
	// block services.gamesforwindows.com - it resolves but the server behind it never responds
	// meaning the first login in any game will take ~2 minutes to time out. so instead we just block it.
	if (wcscmp(pswzServerName, L"services.gamesforwindows.com") == 0)
	{
		SetLastError(ERROR_WINHTTP_OPERATION_CANCELLED);
		return NULL;
	}
	return WinHttpConnect_orig(hSession, pswzServerName, nServerPort, dwReserved);
}

bool InitializeWinHTTP()
{
	HMODULE original = LoadLibraryA("winhttp.dll");
	if (original == NULL)
		return false;
	MH_CreateHookApi(L"winhttp.dll", "WinHttpConnect", (LPVOID)WinHttpConnect_hook, (LPVOID*)&WinHttpConnect_orig);
}
