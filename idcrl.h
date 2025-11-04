#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct _IDCRL_OPTION
{
	DWORD dwId;
	PVOID pValue;
	DWORD cbValue;
} IDCRL_OPTION, * PIDCRL_OPTION;

typedef struct _RST_PARAM
{
	DWORD cbSize;
	LPCWSTR dwServiceName;
	LPCWSTR dwServicePolicy;
	DWORD dwTokenFlags;
	DWORD dwTokenParams;
} RST_PARAM, * PRST_PARAM;

typedef HRESULT(WINAPI* IdentityCallback_t)(HANDLE hIdentity, PVOID pData, BYTE bCanContinue);

bool InitializeMSIDCRL();
