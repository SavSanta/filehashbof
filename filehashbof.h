#pragma once
#define IsDir(a) ((a)&FILE_ATTRIBUTE_DIRECTORY)
void OutHead(formatp*);
LPSTR DerefAMask(DWORD, LPTSTR);
void Touch(WCHAR[]);
void AuthUser(WCHAR[], WCHAR[]);

// WINBOOL IS FINICKY AF in VS 2019

WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
WINBASEAPI void* WINAPI MSVCRT$strcat(const char* dest, const char* source);
WINBASEAPI void* WINAPI MSVCRT$strcpy(const char* dest, const char* source);
WINBASEAPI int WINAPI MSVCRT$strcmp(const char* dest, const char* source);
WINBASEAPI HANDLE __stdcall KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI DWORD __stdcall KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL __stdcall KERNEL32$FileTimeToSystemTime(CONST FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI BOOL __stdcall KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL __stdcall KERNEL32$FindClose(HANDLE hFindFile);
WINBASEAPI void   __cdecl MSVCRT$exit(int);
// orig string header defs
// WINBASEAPI size_t __cdecl strlen(const char* _Str);
// char * __cdecl strcat(char * __restrict__ _Dest,const char * __restrict__ _Source);
