#pragma once

PIMAGE_SECTION_HEADER WINAPI GetRvaSection(__in DWORD dwRva, __in PIMAGE_NT_HEADERS pNtHeaders);

PIMAGE_SECTION_HEADER WINAPI GetRvaSection64(__in DWORD dwRva, __in PIMAGE_NT_HEADERS64 pNtHeaders);

DWORD WINAPI GetRvaOffset(__in DWORD dwRva, __in PIMAGE_NT_HEADERS pNtHeaders);

DWORD WINAPI GetRvaOffset64(__in DWORD dwRva, __in PIMAGE_NT_HEADERS64 pNtHeaders);

PIMAGE_DOS_HEADER WINAPI ImageDosHeader(__in PVOID pBase);

PIMAGE_NT_HEADERS WINAPI ImageNtHeader(__in PVOID pBase); 

PIMAGE_RESOURCE_DIRECTORY_ENTRY WINAPI ResourceDirectroyEntry(__in PIMAGE_RESOURCE_DIRECTORY pRootDirectory, __in WORD wId);

LPVOID WINAPI MapFile(__in LPCWSTR lpcwszFileName, __out_opt LPDWORD lpdwFileSize);