#pragma once

// Note that all wincrypt aliases are essentially the same as standard because Windows C is fvcking dumb.
WINBASEAPI int WINAPI MSVCRT$strcmp(const char* dest, const char* source);
WINBASEAPI void* WINAPI MSVCRT$strcat(const char* dest, const char* source);
WINBASEAPI void* WINAPI MSVCRT$sprintf(char* __stream, const char* __format, ...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
//WINBASEAPI void* WINAPI MEMORY$memset(void* __dst, int __val, size_t __n);
//WINBASEAPI void* WINAPI STRING$memset(void* __dst, int __val, size_t __n);
WINBASEAPI void* WINAPI MSVCRT$memset(void* __dst, int __val, size_t __n);
WINBASEAPI HANDLE __stdcall KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD __stdcall KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI void __cdecl MSVCRT$exit(int);
__declspec(dllimport) BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
__declspec(dllimport) BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
__declspec(dllimport) BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
__declspec(dllimport) BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH hHash, CONST BYTE* pbData, DWORD dwDataLen, DWORD dwFlags);
__declspec(dllimport) BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH hHash);
__declspec(dllimport) BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags);
