#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
//#define _UNICODE
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Wincrypt.h>

#pragma comment (lib, "Crypt32")

int ReadToBuf(HANDLE, ULONG_PTR, ULONG_PTR);
HANDLE LoadTargetFile(CHAR* path);

char * buffer;
HCRYPTPROV hCryptProv = 0;
HCRYPTHASH hHash = 0;


void main()
{
    //--------------------------------------------------------------------
    //  Declare variables.
    DWORD      dwStatus = 0;
    DWORD      dwParam = 0;
    BYTE       pbData[16];
    DWORD      pdwDataLen = sizeof(DWORD);
    DWORD      cbHash = 0;
    HANDLE     hFile = NULL;
    
    //Load The File
    hFile = LoadTargetFile("C:\\Users\\Administrator\\source\\repos\\filehashbof\\x64\\Release\\vc142.pdb");

    //--------------------------------------------------------------------
    // Get a handle to a cryptography provider context.

    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        printf(L"CryptAcquireContext complete. \n");
    }
    else
    {
        printf(L"Acquisition of context failed.\n");
        CloseHandle(hFile);
        exit(1);
    }
    //--------------------------------------------------------------------
    // Acquire a hash object handle.

    if (CryptCreateHash(
        hCryptProv,
        CALG_MD5,
        0,
        0,
        &hHash))
    {
        printf("An empty hash object has been created. \n");
    }
    else
    {
        printf("Error during CryptBeginHash!\n");
        CloseHandle(hFile);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }

    // Read To Buffer
    //ReadToBuf(hFile, hCryptProv, hHash);
    /***SnuffleDelete*****/
    
    //DWORD dwStatus = 0;
    BOOL bResult = 0;
    DWORD cbRead = 0;
    DWORD cbReadCnt = 0;
    BYTE rgbFile[1024];

    while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        // Error Might be Here. Need to ensure the pointers are whatever for the hHash and that the data is persisting
        // Outside this local function
        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hCryptProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            exit(dwStatus);
        }

        cbReadCnt++;
        printf("BYTES in amount of cbRead is %i \n", cbRead);
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hCryptProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        exit(dwStatus);
    }

    printf("Iterations of for cbRead is %i \n", cbReadCnt);
    
    /***SnuffleDelete*****/




    
    if (CryptHashData(hHash, (BYTE *) buffer, 0, CRYPT_USERDATA))
    {
        printf("Crypt Hash Data for the buffer was successfuls.\n ");
    }
    else
    {
        printf("Error during CryptGetHashData!\n");
        exit(1);
    }


    //if ( CryptGetHashParam(hHash, HP_HASHVAL, pbData, 16, 0))
    if ((CryptGetHashParam(hHash, HP_HASHVAL, pbData, &cbHash, 0)))
    {
        printf("Got some success.\n");
        printf("Hash is %s\n", pbData);
        //printf("Hash is %i", pbData);       
    }
    else 
    {
        dwStatus = GetLastError();
        CloseHandle(hFile);
        printf("Error during CryptGetHashParam! with at %d\n", dwStatus);
        exit(1);
    }

    //--------------------------------------------------------------------
    // After processing, hCryptProv and hHash must be released.

    if (hHash) {
        CryptDestroyHash(hHash);
    }

    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
    }

}

HANDLE LoadTargetFile(CHAR * path) 
{
    HANDLE hFile = NULL;
    DWORD dwStatus = 0;

    WCHAR * path2 = L"C:\\Windows\\System32\\cmd.exe";
    hFile = CreateFileW(path2,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        printf("Error on attmepts to open file %ls \nError: %d\n", path2, dwStatus);
        exit(2);
    }

    return hFile;
}

int ReadToBuf(HANDLE hFile, HCRYPTPROV hProv, HCRYPTHASH hHash)
{
    DWORD dwStatus = 0;
    BOOL bResult = 0;
    DWORD cbRead = 0;
    DWORD cbReadCnt = 0;
    BYTE rgbFile[1024];

    while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        // Error Might be Here. Need to ensure the pointers are whatever for the hHash and that the data is persisting
        // Outside this local function
        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }

        cbReadCnt++;
        printf("BYTES in amount of cbRead is %i \n", cbRead);
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    printf("Iterations of for cbRead is %i \n", cbReadCnt);
    return 0;

}
