// console_is_required_uac.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

#include "utils.hpp"

#include <ntdll.h>
#pragma comment(lib, "ntdll")

BOOL GetManifestData(__in IMAGE_NT_HEADERS *pNtHeaders, __in LPVOID lpBuffer, __out LPSTR lpszDest, __in SIZE_T cchDest, __out PULONG pReturnLength)
{
	IMAGE_RESOURCE_DIRECTORY *pRootDirectory;
	IMAGE_RESOURCE_DIRECTORY *pDirectory;
	IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry;
	IMAGE_RESOURCE_DATA_ENTRY *pData;

	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == NULL)
	{
		SetLastError(ERROR_INVALID_ACCESS);
		return FALSE;
	}

	pRootDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(PBYTE(lpBuffer) + GetRvaOffset(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, pNtHeaders));
	pEntry = ResourceDirectroyEntry(pRootDirectory, 24); // manifest

	if (pEntry != NULL)
	{
		pDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(PBYTE(pRootDirectory) + pEntry->OffsetToDirectory);
		pEntry = ResourceDirectroyEntry(pDirectory, 1);

		if (pEntry != NULL)
		{
			pDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(PBYTE(pRootDirectory) + pEntry->OffsetToDirectory);
			pEntry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY *>(PBYTE(pDirectory) + sizeof(IMAGE_RESOURCE_DIRECTORY));		
			pData  = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY *>(PBYTE(pRootDirectory) + pEntry->OffsetToData);
			
			if (pReturnLength != NULL)
				*pReturnLength = pData->Size + 1;

			if (cchDest < pData->Size + 1)
			{
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return FALSE;
			}

			memcpy(lpszDest, PBYTE(lpBuffer) + GetRvaOffset(pData->OffsetToData, pNtHeaders), pData->Size);
			lpszDest[pData->Size] = 0;

			return TRUE;
		}		
	}

	SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
	return FALSE;
}

BOOL GetManifestData64(__in IMAGE_NT_HEADERS64 *pNtHeaders, __in LPVOID lpBuffer, __out LPSTR lpszDest, __in SIZE_T cchDest, __out PULONG pReturnLength)
{
	IMAGE_RESOURCE_DIRECTORY *pRootDirectory;
	IMAGE_RESOURCE_DIRECTORY *pDirectory;
	IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry;
	IMAGE_RESOURCE_DATA_ENTRY *pData;

	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == NULL)
	{
		SetLastError(ERROR_INVALID_ACCESS);
		return FALSE;
	}

	pRootDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(PBYTE(lpBuffer) + GetRvaOffset64(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, pNtHeaders));
	pEntry = ResourceDirectroyEntry(pRootDirectory, 24); // manifest

	if (pEntry != NULL)
	{
		pDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(PBYTE(pRootDirectory) + pEntry->OffsetToDirectory);
		pEntry = ResourceDirectroyEntry(pDirectory, 1);

		if (pEntry != NULL)
		{
			pDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(PBYTE(pRootDirectory) + pEntry->OffsetToDirectory);
			pEntry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY *>(PBYTE(pDirectory) + sizeof(IMAGE_RESOURCE_DIRECTORY));
			pData = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY *>(PBYTE(pRootDirectory) + pEntry->OffsetToData);

			if (pReturnLength != NULL)
				*pReturnLength = pData->Size + 1;

			if (cchDest < pData->Size + 1)
			{
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return FALSE;
			}

			memcpy(lpszDest, PBYTE(lpBuffer) + GetRvaOffset64(pData->OffsetToData, pNtHeaders), pData->Size);
			lpszDest[pData->Size] = 0;

			return TRUE;
		}
	}

	SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
	return FALSE;
}

BOOL IsFileRequireAdministrator(__in LPCWSTR lpcszFileName)
{
	IMAGE_NT_HEADERS32 *pNtHeaders;
	LPVOID lpBuffer;
	CHAR*  szData;
	ULONG  uLength;

	lpBuffer = MapFile(lpcszFileName, NULL);
	if (!lpBuffer)
		return FALSE;

	pNtHeaders = ImageNtHeader(lpBuffer);
	if (!pNtHeaders)
	{
		VirtualFree(lpBuffer, 0, MEM_RELEASE);
		return FALSE;
	}

	szData  = (CHAR *)malloc(1024);
	uLength = sizeof(szData);

	if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		// X86
		if (GetManifestData(pNtHeaders, lpBuffer, szData, uLength, &uLength) == FALSE &&
			GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			szData = (CHAR *)realloc(NULL, uLength);
			if (GetManifestData(pNtHeaders, lpBuffer, szData, uLength, NULL) == FALSE)
			{
				free(szData);
				VirtualFree(lpBuffer, 0, MEM_RELEASE);

				return FALSE;
			}
		}
	}
	else
	{
		// X64
		if (GetManifestData64(reinterpret_cast<IMAGE_NT_HEADERS64 *>(pNtHeaders), lpBuffer, szData, uLength, &uLength) == FALSE &&
			GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			szData = (CHAR *)realloc(NULL, uLength);
			if (GetManifestData64(reinterpret_cast<IMAGE_NT_HEADERS64 *>(pNtHeaders), lpBuffer, szData, uLength, NULL) == FALSE)
			{
				free(szData);
				VirtualFree(lpBuffer, 0, MEM_RELEASE);

				return FALSE;
			}
		}
	}

	VirtualFree(lpBuffer, 0, MEM_RELEASE);

	//printf("%s\n", szData);

	if (strstr(szData, "requireAdministrator") != 0)
	{
		free(szData);
		return TRUE;
	}

	free(szData);
	return FALSE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc == 2)
	{
		if (IsFileRequireAdministrator(argv[1]))
		{
			_tprintf(_T("%s is require administrator\n"), argv[1]);
		}
		else
		{
			_tprintf(_T("%s is unrequire administrator\n"), argv[1]);
		}
	}

	return 0;
}

