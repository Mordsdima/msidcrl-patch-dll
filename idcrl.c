#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <Shlwapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "idcrl.h"

#define DLL_FUNC __declspec(dllexport)

#define IDCRL_FUNC(def, func, args) \
	static def (WINAPI *func##Orig) args; \
	DLL_FUNC def WINAPI func args

extern bool g_InitializedModule;

static bool g_HasRequestedService = false;

static IdentityCallback_t g_savedCallback = NULL;
static PVOID g_savedCallbackData = NULL;

IDCRL_FUNC(HRESULT, Uninitialize, ())
{
	return UninitializeOrig();
}

IDCRL_FUNC(HRESULT, PassportFreeMemory, (LPVOID pMemory))
{
	return PassportFreeMemoryOrig(pMemory);
}

IDCRL_FUNC(HRESULT, CreateIdentityHandle, (LPCWSTR wszMemberName, DWORD dwFlags, PHANDLE phIdentity))
{
	return CreateIdentityHandleOrig(wszMemberName, dwFlags, phIdentity);
}

IDCRL_FUNC(HRESULT, SetCredential, (HANDLE hIdentity, LPCWSTR wszCredType, LPCWSTR wszCredValue))
{
	return SetCredentialOrig(hIdentity, wszCredType, wszCredValue);
}

IDCRL_FUNC(HRESULT, CloseIdentityHandle, (HANDLE hIdentity))
{
	return CloseIdentityHandleOrig(hIdentity);
}

IDCRL_FUNC(HRESULT, AuthIdentityToService, (HANDLE hIdentity, LPCWSTR wszServiceTarget, LPCWSTR wszServicePolicy, DWORD dwTokenRequestFlags, LPCWSTR wszToken, DWORD dwResultFlags, PBYTE pbSessionKey, PDWORD pdwSessionKeyLength))
{
	// spoof to always use the cached token (since we request one in LogonIdentityEx)
	// we don't spoof if xlive is already requesting a cached token
	bool spoofed = false;
	if (g_HasRequestedService && dwTokenRequestFlags == 0)
	{
		dwTokenRequestFlags = 0x10000;
		spoofed = true;
	}

	// call through to the original
	HRESULT hr = AuthIdentityToServiceOrig(hIdentity, wszServiceTarget, wszServicePolicy, dwTokenRequestFlags, wszToken, dwResultFlags, pbSessionKey, pdwSessionKeyLength);
	
	// if we got a successful hresult, we spoofed to use the cache so there was no identity callback called, so we should call it
	if (spoofed && hr == 0 && g_savedCallback != NULL)
		g_savedCallback(hIdentity, g_savedCallbackData, 0);

	return hr;
}

IDCRL_FUNC(HRESULT, PersistCredential, (HANDLE hIdentity, LPCWSTR wszCredType))
{
	return PersistCredentialOrig(hIdentity, wszCredType);
}

IDCRL_FUNC(HRESULT, RemovePersistedCredential, (HANDLE hIdentity, LPCWSTR wszCredType))
{
	return RemovePersistedCredentialOrig(hIdentity, wszCredType);
}

IDCRL_FUNC(HRESULT, HasPersistedCredential, (HANDLE hIdentity, LPCWSTR wszCredType, PDWORD pdwHasPersistentCred))
{
	return HasPersistedCredentialOrig(hIdentity, wszCredType, pdwHasPersistentCred);
}

IDCRL_FUNC(HRESULT, SetIdentityCallback, (HANDLE hIdentity, IdentityCallback_t cbFunction, PVOID pData))
{
	g_savedCallback = cbFunction;
	g_savedCallbackData = pData;
	return SetIdentityCallbackOrig(hIdentity, cbFunction, pData);
}

IDCRL_FUNC(HRESULT, InitializeEx, (LPGUID lpAppGuid, DWORD dwPpcrlVersion, DWORD dwFlags, PIDCRL_OPTION pOptions, DWORD dwOptions))
{
	if (!InitializeMSIDCRL())
	{
		// PP_E_CRL_NOT_INITIALIZED
		return 0x80048008;
	}
	return InitializeExOrig(lpAppGuid, dwPpcrlVersion, dwFlags, pOptions, dwOptions);
}

IDCRL_FUNC(HRESULT, LogonIdentityEx, (HANDLE hIdentity, LPCWSTR wszAuthPolicy, DWORD dwAuthFlags, PRST_PARAM pRstParams, DWORD dwRstParamCount))
{
	if (g_InitializedModule)
	{
		// the version of MSIDCRL we're using has an issue under Wine where AuthIdentityToService fails to make a valid request
		// so we request a service token in the initial logon request instead 
		RST_PARAM params[1];
		params[0].cbSize = sizeof(RST_PARAM);
		params[0].dwServiceName = L"http://kdc.xboxlive.com"; //L"marketplace.windowsmobile.com";
		params[0].dwServicePolicy = L"LBI_KEY";
		params[0].dwTokenFlags = 0;
		params[0].dwTokenParams = 0;
		pRstParams = params;
		dwRstParamCount = 1;
		g_HasRequestedService = true;
	}

	return LogonIdentityExOrig(hIdentity, wszAuthPolicy, dwAuthFlags, pRstParams, dwRstParamCount);
}

IDCRL_FUNC(HRESULT, GetAuthStateEx, (HANDLE hIdentity, LPCWSTR wszServiceTarget, PDWORD pdwAuthState, PDWORD dwAuthRequired, PDWORD pdwRequestStatus, LPCWSTR *wszWebFlowUrl))
{
	return GetAuthStateExOrig(hIdentity, wszServiceTarget, pdwAuthState, dwAuthRequired, pdwRequestStatus, wszWebFlowUrl);
}

IDCRL_FUNC(HRESULT, CancelPendingRequest, (HANDLE hIdentity))
{
	return CancelPendingRequestOrig(hIdentity);
}

IDCRL_FUNC(HRESULT, GetIdentityPropertyByName, (HANDLE hIdentity, LPCWSTR wszPropertyName, LPCWSTR wszPropertyValue))
{
	return GetIdentityPropertyByNameOrig(hIdentity, wszPropertyName, wszPropertyValue);
}

IDCRL_FUNC(HRESULT, GetWebAuthUrlEx, (HANDLE hIdentity, DWORD dwWebAuthFlag, LPCWSTR wszTargetServiceName, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR wszWebAuthUrl, LPCWSTR wszPostData))
{
	return GetWebAuthUrlExOrig(hIdentity, dwWebAuthFlag, wszTargetServiceName, wszServicePolicy, wszAdditionalPostParams, wszWebAuthUrl, wszPostData);
}

static void GetIDCRLPath(CHAR* buffer)
{
	DWORD dwType;
	CHAR crlDirPath[MAX_PATH];
	DWORD crlDirLen = sizeof(crlDirPath);
	if (SHRegGetValueA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\IdentityCRL", "TargetDir",
		SRRF_RT_REG_SZ, &dwType, crlDirPath, &crlDirLen) == ERROR_SUCCESS) {
		snprintf(buffer, MAX_PATH, "%s\\msidcrl67.dll", crlDirPath);
	}
	else {
		strncpy(buffer, "msidcrl67.dll", MAX_PATH);
	}
}

bool InitializeMSIDCRL()
{
	CHAR crlDll[MAX_PATH];
	GetIDCRLPath(crlDll);
	HMODULE original = LoadLibraryA(crlDll);
	if (original == NULL) return false;

#define RESOLVE_FUNC(fn) \
	fn##Orig = (void *)GetProcAddress(original, #fn); \
	if (fn##Orig == NULL) return false;

	RESOLVE_FUNC(Uninitialize);
	RESOLVE_FUNC(PassportFreeMemory);
	RESOLVE_FUNC(CreateIdentityHandle);
	RESOLVE_FUNC(SetCredential);
	RESOLVE_FUNC(CloseIdentityHandle);
	RESOLVE_FUNC(AuthIdentityToService);
	RESOLVE_FUNC(PersistCredential);
	RESOLVE_FUNC(RemovePersistedCredential);
	RESOLVE_FUNC(HasPersistedCredential);
	RESOLVE_FUNC(SetIdentityCallback);
	RESOLVE_FUNC(InitializeEx);
	RESOLVE_FUNC(LogonIdentityEx);
	RESOLVE_FUNC(GetAuthStateEx);
	RESOLVE_FUNC(CancelPendingRequest);
	RESOLVE_FUNC(GetIdentityPropertyByName);
	RESOLVE_FUNC(GetWebAuthUrlEx);
#undef RESOLVE_FUNC

	return true;
}
