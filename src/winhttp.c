#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "MinHook.h"
#include "ini.h"
#include "utils.h"

extern ini_t* g_Config;

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

static HINTERNET(WINAPI* InternetConnectA_orig)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD* dwContext);
HINTERNET WINAPI InternetConnectA_hook(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD* dwContext)
{
	return InternetConnectA_orig(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

static HINTERNET(WINAPI* InternetConnectW_orig)(HINTERNET hInternet, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, LPCWSTR pswzUserName, LPCWSTR pswzPassword, DWORD dwService, DWORD dwFlags, DWORD* dwContext);
HINTERNET WINAPI InternetConnectW_hook(HINTERNET hInternet, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, LPCWSTR pswzUserName, LPCWSTR pswzPassword, DWORD dwService, DWORD dwFlags, DWORD* dwContext)
{
	if(wcscmp(pswzServerName, L"login.live.com") == 0) {
		if (ini_get(g_Config, "server", "login") == NULL) {
			MessageBoxA(NULL, "It seems that your config is either damaged or not full because server.login is not present.", "Config validation error", 0x10);
			return InternetConnectW_orig(hInternet, pswzServerName, nServerPort, pswzUserName, pswzPassword, dwService, dwFlags, dwContext);
		}
		pswzServerName = ascii_to_wide(ini_get(g_Config, "server", "login"));
	}
	return InternetConnectW_orig(hInternet, pswzServerName, nServerPort, pswzUserName, pswzPassword, dwService, dwFlags, dwContext);
}

bool InitializeWinHTTP()
{
	HMODULE original = LoadLibraryA("winhttp.dll");
	if (original == NULL)
		return false;
	original = LoadLibraryA("wininet.dll");
	if (original == NULL)
		return false;
	MH_CreateHookApi(L"winhttp.dll", "WinHttpConnect", (LPVOID)WinHttpConnect_hook, (LPVOID*)&WinHttpConnect_orig);
	//MH_CreateHookApi(L"wininet.dll", "InternetConnectA", (LPVOID)InternetConnectA_hook, (LPVOID*)&InternetConnectA_orig);
	MH_CreateHookApi(L"wininet.dll", "InternetConnectW", (LPVOID)InternetConnectW_hook, (LPVOID*)&InternetConnectW_orig); // here bcuz its only http stuff
}
