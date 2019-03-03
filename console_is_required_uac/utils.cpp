#include "stdafx.h"

#include "utils.hpp"

#include <ntdll.h>
#pragma comment(lib, "ntdll")

PIMAGE_SECTION_HEADER WINAPI GetRvaSection(__in DWORD dwRva, __in PIMAGE_NT_HEADERS pNtHeaders)
{
	DWORD dwOptinalHeaderOffset, dwOptinalHeaderSize;
	IMAGE_SECTION_HEADER *pSectionHeader;

	dwOptinalHeaderOffset = reinterpret_cast<DWORD>(&reinterpret_cast<IMAGE_NT_HEADERS *>(0)->OptionalHeader);
	dwOptinalHeaderSize = pNtHeaders->FileHeader.SizeOfOptionalHeader;

	pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<PBYTE>(pNtHeaders)+dwOptinalHeaderOffset + dwOptinalHeaderSize);

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
		if (dwRva >= pSectionHeader->VirtualAddress && dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
			return pSectionHeader;

	return NULL;
}

PIMAGE_SECTION_HEADER WINAPI GetRvaSection64(__in DWORD dwRva, __in PIMAGE_NT_HEADERS64 pNtHeaders)
{
	DWORD dwOptinalHeaderOffset, dwOptinalHeaderSize;
	IMAGE_SECTION_HEADER *pSectionHeader;

	dwOptinalHeaderOffset = reinterpret_cast<DWORD>(&reinterpret_cast<IMAGE_NT_HEADERS64 *>(0)->OptionalHeader);
	dwOptinalHeaderSize = pNtHeaders->FileHeader.SizeOfOptionalHeader;

	pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<PBYTE>(pNtHeaders)+dwOptinalHeaderOffset + dwOptinalHeaderSize);

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
		if (dwRva >= pSectionHeader->VirtualAddress && dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
			return pSectionHeader;

	return NULL;
}

DWORD WINAPI GetRvaOffset(__in DWORD dwRva, __in PIMAGE_NT_HEADERS pNtHeaders)
{
	IMAGE_SECTION_HEADER *pSectionHeader = GetRvaSection(dwRva, pNtHeaders);
	return (pSectionHeader != NULL ? (dwRva + (pSectionHeader->PointerToRawData - pSectionHeader->VirtualAddress)) : 0);
}

DWORD WINAPI GetRvaOffset64(__in DWORD dwRva, __in PIMAGE_NT_HEADERS64 pNtHeaders)
{
	IMAGE_SECTION_HEADER *pSectionHeader = GetRvaSection64(dwRva, pNtHeaders);
	return (pSectionHeader != NULL ? (dwRva + (pSectionHeader->PointerToRawData - pSectionHeader->VirtualAddress)) : 0);
}

PIMAGE_DOS_HEADER WINAPI ImageDosHeader(__in PVOID pBase)
{
	PIMAGE_DOS_HEADER pImageDosHeader;

	pImageDosHeader = PIMAGE_DOS_HEADER(pBase);

	if (pImageDosHeader != NULL && pImageDosHeader != INVALID_HANDLE_VALUE)
	{
		if (pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			return pImageDosHeader;
		}
	}

	return NULL;
}

PIMAGE_NT_HEADERS WINAPI ImageNtHeader(__in PVOID pBase)
{
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	LONG e_lfanew;

	pImageDosHeader = ImageDosHeader(pBase);

	if (pImageDosHeader != NULL)
	{
		e_lfanew = pImageDosHeader->e_lfanew;

		if (e_lfanew >= 0 && e_lfanew < 0x10000000)
		{
			pImageNtHeaders = PIMAGE_NT_HEADERS(reinterpret_cast<PBYTE>(pImageDosHeader)+e_lfanew);
			if (pImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
			{
				return pImageNtHeaders;
			}
		}
	}

	return NULL;
}

PIMAGE_RESOURCE_DIRECTORY_ENTRY WINAPI ResourceDirectroyEntry(__in PIMAGE_RESOURCE_DIRECTORY pRootDirectory, __in WORD wId)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry;

	pEntry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(PBYTE(pRootDirectory) + sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (INT i = 0; i < pRootDirectory->NumberOfIdEntries + pRootDirectory->NumberOfNamedEntries; i++)
	{
		if (!pEntry[i].NameIsString)
		{
			if (pEntry[i].Id == wId)
			{
				return &pEntry[i];
			}
		}
	}

	return NULL;
}

LPVOID WINAPI MapFile(__in LPCWSTR lpcwszFileName, __out_opt LPDWORD lpdwFileSize)
{
	HANDLE hFile;
	DWORD  dwFileSize;
	LPVOID lpBuffer;
	IO_STATUS_BLOCK IoStatusBlock;

	hFile = CreateFile(lpcwszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;

	dwFileSize = GetFileSize(hFile, NULL);

	lpBuffer = VirtualAlloc(NULL, dwFileSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpBuffer)
	{
		CloseHandle(hFile);
		return NULL;
	}

	VirtualAlloc(lpBuffer, dwFileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(NtReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, lpBuffer, dwFileSize, NULL, NULL)))
	{
		CloseHandle(hFile);
		VirtualFree(lpBuffer, 0, MEM_RELEASE);
		return NULL;
	}

	if (lpdwFileSize != NULL)
		*lpdwFileSize = dwFileSize;

	CloseHandle(hFile);
	return lpBuffer;
}