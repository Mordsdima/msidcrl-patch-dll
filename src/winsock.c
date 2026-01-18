#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <WinSock2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "MinHook.h"
#include "ini.h"
#pragma comment(lib, "ws2_32.lib")

#define LOOKUP_HANDLE_MAGIC ((HANDLE)0x67676767)

static char g_dnsName[256] = { 0 };
static bool g_inProgress = false;
static bool g_doneResults = false;
static void* g_blobBuffer = NULL;

typedef struct _hostentBLOB_t {
	uint32_t h_name_offset;
	uint32_t h_aliases_offset;
	int16_t h_addrtype;
	int16_t h_length;
	uint32_t h_addr_list_offset;
} hostentBLOB_t;

extern ini_t* g_Config;

hostentBLOB_t* gethostbyname_to_blob(const char* name, int *blob_size)
{
	// WARNING! this won't work on Windows - gethostbyname internally goes through WSALookupServiceBeginA
	//          it'll cause a crash whenever DNS lookup gets attempted.
	//          (also it will probably fail on Wine if they eventually update it to behave like Windows...)
	struct hostent* hent = gethostbyname(name);
	if (hent == NULL)
		return NULL;

	// get the size of the canonical name
	int sz_name = hent->h_name == NULL ? 0 : strlen(hent->h_name) + 1;

	// get the number of addresses and the size of the blob of addresses
	int num_addr = 0;
	int sz_addr = 0;
	if (hent->h_addr_list != NULL) {
		char* current_addr = hent->h_addr_list[0];
		while (current_addr != NULL) {
			sz_addr += 4;
			num_addr++;
			current_addr = hent->h_addr_list[num_addr];
		}
	}

	// get the number of aliases and the size of the blob of aliases
	int num_alias = 0;
	int sz_alias = 0;
	if (hent->h_aliases != NULL) {
		char* current_alias = hent->h_aliases[0];
		while (current_alias != NULL) {
			sz_alias += strlen(current_alias) + 1;
			num_alias++;
			current_alias = hent->h_aliases[num_alias];
		}
	}

	// allocate a blob of the exact size we need
	int blobSize =
		sizeof(hostentBLOB_t) +
		sz_name +
		((num_addr + 1) * 4) +
		sz_addr +
		((num_alias + 1) * 4) +
		sz_alias;
	uint8_t* blobData = (uint8_t*)malloc(blobSize);
	if (blobData == NULL)
		return NULL;
	g_blobBuffer = blobData;
	*blob_size = blobSize;
	memset(blobData, 0, blobSize);

	// prepare the header
	hostentBLOB_t *hdr = (hostentBLOB_t *)blobData;
	hdr->h_name_offset = sizeof(hostentBLOB_t);
	hdr->h_addrtype = hent->h_addrtype;
	hdr->h_length = hent->h_length;
	hdr->h_aliases_offset = sizeof(hostentBLOB_t) + sz_name + ((num_addr + 1) * 4) + sz_addr;
	hdr->h_addr_list_offset = sizeof(hostentBLOB_t) + sz_name;

	// copy the name over
	if (hent->h_name != NULL)
		strcpy(blobData + hdr->h_name_offset, hent->h_name);

	// copy the address list over
	uint32_t* addr_offset_list = (uint32_t*)(blobData + hdr->h_addr_list_offset);
	uint32_t addr_data_offset = hdr->h_addr_list_offset + ((num_addr + 1) * 4);
	uint8_t* addr_data = (uint8_t*)(blobData + addr_data_offset);
	for (int i = 0; i < num_addr; i++)
	{
		addr_offset_list[i] = addr_data_offset;
		memcpy(addr_data, hent->h_addr_list[i], hent->h_length);
		addr_data_offset += hent->h_length;
		addr_data += hent->h_length;
	}

	// copy the aliases list over
	uint32_t* alias_offset_list = (uint32_t*)(blobData + hdr->h_aliases_offset);
	uint32_t alias_data_offset = hdr->h_aliases_offset + ((num_alias + 1) * 4);
	uint8_t* alias_data = (uint8_t*)(blobData + alias_data_offset);
	for (int i = 0; i < num_alias; i++)
	{
		alias_offset_list[i] = alias_data_offset;
		strcpy(alias_data, hent->h_aliases[i]);
		alias_data_offset += strlen(hent->h_aliases[i]) + 1;
		alias_data += strlen(hent->h_aliases[i]) + 1;
	}

	return hdr;
}

static DWORD(WINAPI* WSALookupServiceBeginA_orig)(PWSAQUERYSETA lpqsRestrictions, DWORD dwControlFlags, PHANDLE lphLookup);
DWORD WINAPI WSALookupServiceBeginA_hook(PWSAQUERYSETA lpqsRestrictions, DWORD dwControlFlags, PHANDLE lphLookup)
{
	//DWORD r = 
	
	// TODO: check if it's the gethostbyname GUID. this is fine for now
	/*if (r != 0 && lpqsRestrictions->dwNameSpace == NS_DNS)
	{
		strncpy(g_dnsName, lpqsRestrictions->lpszServiceInstanceName, sizeof(g_dnsName));
		g_inProgress = true;
		g_doneResults = false;
		*lphLookup = LOOKUP_HANDLE_MAGIC;
		return 0;
	} im not sure if we even need this*/

	// gfwl
	if (_stricmp(lpqsRestrictions->lpszServiceInstanceName, "xemacs.xboxlive.com") == 0 || _stricmp(lpqsRestrictions->lpszServiceInstanceName, "xemacs.part.xboxlive.com") == 0) {
		if (!ini_get(g_Config, "server", "macs")) {
			MessageBoxA(NULL, "It seems that your config is either damaged or not full because server.macs is not present.", "Config validation error", 0x10);
		}
		lpqsRestrictions->lpszServiceInstanceName = ini_get(g_Config, "server", "macs");
	}
	else if (_stricmp(lpqsRestrictions->lpszServiceInstanceName, "xeas.xboxlive.com") == 0 || _stricmp(lpqsRestrictions->lpszServiceInstanceName, "xeas.part.xboxlive.com") == 0) {
		if (!ini_get(g_Config, "server", "as")) {
			MessageBoxA(NULL, "It seems that your config is either damaged or not full because server.as is not present.", "Config validation error", 0x10);
		}
		lpqsRestrictions->lpszServiceInstanceName = ini_get(g_Config, "server", "as");
	}
	else if (_stricmp(lpqsRestrictions->lpszServiceInstanceName, "xetgs.xboxlive.com") == 0 || _stricmp(lpqsRestrictions->lpszServiceInstanceName, "xetgs.part.xboxlive.com") == 0) {
		if (!ini_get(g_Config, "server", "tgs")) {
			MessageBoxA(NULL, "It seems that your config is either damaged or not full because server.tgs is not present.", "Config validation error", 0x10);
		}
		lpqsRestrictions->lpszServiceInstanceName = ini_get(g_Config, "server", "tgs");
	}

	return WSALookupServiceBeginA_orig(lpqsRestrictions, dwControlFlags, lphLookup);;
}

static DWORD(WINAPI* WSALookupServiceNextA_orig)(HANDLE hLookup, DWORD dwControlFlags, LPDWORD lpdwBufferLength, LPWSAQUERYSETA lpqsResults);
DWORD WINAPI WSALookupServiceNextA_hook(HANDLE hLookup, DWORD dwControlFlags, LPDWORD lpdwBufferLength, LPWSAQUERYSETA lpqsResults)
{
	if (hLookup == LOOKUP_HANDLE_MAGIC && g_inProgress)
	{
		// allow disabling DNS lookups - this acts as an effective block of LIVE services
		char* disableEnv = getenv("GFLL_LIVEBLOCK");
		if (disableEnv != NULL && (_stricmp(disableEnv, "true") == 0 || _stricmp(disableEnv, "1") == 0))
			g_doneResults = true;

		// if we haven't gotten a result already and we aren't skipping over it, look it up
		if (!g_doneResults)
		{
			int blob_size = 0;
			hostentBLOB_t* blob = gethostbyname_to_blob(g_dnsName, &blob_size);
			if (blob == NULL)
			{
				SetLastError(WSA_E_NO_MORE);
				return SOCKET_ERROR;
			}
			// TODO(Emma): free lpBlob in WSALookupServiceEnd
			lpqsResults->lpBlob = (LPBLOB)malloc(sizeof(BLOB));
			if (lpqsResults->lpBlob == NULL)
			{
				SetLastError(WSA_NOT_ENOUGH_MEMORY);
				return SOCKET_ERROR;
			}
			lpqsResults->lpBlob->cbSize = blob_size;
			lpqsResults->lpBlob->pBlobData = (BYTE*)blob;
			g_doneResults = true;
			return 0;
		}
		SetLastError(WSA_E_NO_MORE);
		return SOCKET_ERROR;
	}
	return WSALookupServiceNextA_orig(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
}

static DWORD(WINAPI* WSALookupServiceEnd_orig)(HANDLE hLookup);
DWORD WINAPI WSALookupServiceEnd_hook(HANDLE hLookup)
{
	if (hLookup == LOOKUP_HANDLE_MAGIC && g_inProgress)
	{
		memset(g_dnsName, 0, sizeof(g_dnsName));
		g_inProgress = false;
		g_doneResults = false;
		if (g_blobBuffer != NULL)
		{
			free(g_blobBuffer);
			g_blobBuffer = NULL;
		}
		return 0;
	}
	return WSALookupServiceEnd_orig(hLookup);
}

static DWORD(WINAPI* WSAIoctl_orig)(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
DWORD WINAPI WSAIoctl_hook(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	DWORD r = WSAIoctl_orig(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
	
	// Wine doesn't support this IOCTL
	// it's not important for anything other than local System Link, so we don't report back if it fails
	if (dwIoControlCode == SIO_MULTIPOINT_LOOPBACK)
	{
		return 0;
	}

	return r;
}

static int(WSAAPI* getaddrinfo_orig)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
int WSAAPI getaddrinfo_hook(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
	if (!pNodeName) {
		return getaddrinfo_orig(pNodeName, pServiceName, pHints, ppResult); // at mercy of original
	}

	return getaddrinfo_orig(pNodeName, pServiceName, pHints, ppResult);
}

bool InitializeWinSock()
{
	MH_CreateHookApi(L"ws2_32.dll", "WSALookupServiceBeginA", (LPVOID)WSALookupServiceBeginA_hook, (LPVOID*)&WSALookupServiceBeginA_orig);
	MH_CreateHookApi(L"ws2_32.dll", "WSALookupServiceNextA", (LPVOID)WSALookupServiceNextA_hook, (LPVOID*)&WSALookupServiceNextA_orig);
	MH_CreateHookApi(L"ws2_32.dll", "WSALookupServiceEnd", (LPVOID)WSALookupServiceEnd_hook, (LPVOID*)&WSALookupServiceEnd_orig);
	MH_CreateHookApi(L"ws2_32.dll", "WSAIoctl", (LPVOID)WSAIoctl_hook, (LPVOID*)&WSAIoctl_orig);
	MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", (LPVOID)getaddrinfo_hook, (LPVOID*)&getaddrinfo_orig);

}
