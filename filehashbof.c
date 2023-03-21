#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>

#define BUFSIZE 1024

// Internal State Size Bits
#define MD5LEN 16
#define SHA256 32
#define SHA512 64

DWORD main()
{
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    DWORD cbRead = 0;
    DWORD cbHash = 0;
    BYTE rgbFile[BUFSIZE];
    CHAR rgbDigits[] = "0123456789abcdef";
    LPCWSTR file = L"C:\\Users\\Administrator\\source\\repos\\filehashbof\\x64\\Release\\vc142.pdb";
    
    //Switch Case for alternative implementations goes here
    BYTE rgbHash[SHA512];
    cbHash = SHA512;

    // Logic to check usage goes here

    hFile = CreateFile(file,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        printf("Error opening file %s\nError: %d\n", file, dwStatus);
        exit(dwStatus);
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        exit(dwStatus);
    }

    // Supportable WIN32 ALGS
    // CALG_MD5
    // CALG_SHA_256
    // CALG_SHA_512

    if (!CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        exit(dwStatus);
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            exit(dwStatus);
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile call failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        exit(dwStatus);
    }


    // Original hashstring calculation regards usage of cbhash for correct bits length
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        printf("Hash of file %s is: ", file);
        for (DWORD i = 0; i < cbHash; i++)
        {
            printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        }
        printf("\n");
    }
    else
    {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
        exit(dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    exit(dwStatus);
}