#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>
#include "beacon.h"
#include "filehashbof.h"

// Internal State Size Bits
#define MD5LEN 16
#define SHA256 32
#define SHA512 64
#define BUFSIZE 1024

void go(char* args, int alen)
{
    datap parser;
    DWORD dwStatus = 0;
    HANDLE hFile = NULL;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD cbRead = 0;
    DWORD cbHash = 0;
    BYTE rgbFile[BUFSIZE];
    CHAR rgbDigits[] = "0123456789ABCDEF";
    PCHAR file = NULL;
    PCHAR alg = NULL;
    UINT algid = 0;

    // Switch Case should ideally go here for alternative HASHING implementations 
    // However with testing leaving this SHA512 seems to be fine in ignoring cap
    // Could also preallocate with char null-terms but for minimum viability will leave as so.
    BYTE rgbHash[SHA512];
    cbHash = SHA512;

    BeaconDataParse(&parser, args, alen);
    file = BeaconDataExtract(&parser, NULL);
    alg = BeaconDataExtract(&parser, NULL);

    if (file == NULL || alg == NULL)
    {
        // Syntax match filehashass.exe
        BeaconPrintf(CALLBACK_ERROR, "Syntax Error: filehashbof.o <filepath> <algorithm>");
        return;
    }

    // Attempt to grab handle to file 
    hFile = KERNEL32$CreateFileA(file,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Error opening file %s\nError: %d\n", file, dwStatus);
        return;
    }

    // Grabs ctx CSP Provider using the best suited for our current supported hashs
    // DefaultW
    if (!ADVAPI32$CryptAcquireContextA(&hProv,
        NULL,
        NULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "CryptAcquireContext failure with code: %d\n", dwStatus);
        KERNEL32$CloseHandle(hFile);
        return;
    }

    // Key hashing supportable WIN32 HASHING ALGS
    // CALG_MD5
    // CALG_SHA_256
    // CALG_SHA_512

    if (MSVCRT$strcmp(alg, "md5") == 0)
    {
        algid = CALG_MD5;
    }
    else if (MSVCRT$strcmp(alg, "sha256") == 0)
    {
        algid = CALG_SHA_256;
    }
    else if (MSVCRT$strcmp(alg, "sha512") == 0)
    {
        algid = CALG_SHA_512;
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Error: Algorithm does not appear to be supported.");
        return;
    }

    if (!ADVAPI32$CryptCreateHash(hProv, algid, 0, 0, &hHash))
    {
        dwStatus = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "CryptCreateHash failure with code: %d\n", dwStatus);
        KERNEL32$CloseHandle(hFile);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }

    // Read the file contents for the hasher
    while (bResult = KERNEL32$ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!ADVAPI32$CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "CryptHashData failure with code: %d\n", dwStatus);
            ADVAPI32$CryptReleaseContext(hProv, 0);
            ADVAPI32$CryptDestroyHash(hHash);
            KERNEL32$CloseHandle(hFile);
            return;
        }
    }

    if (!bResult)
    {
        dwStatus = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "ReadFile call failure with code: %d\n", dwStatus);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        ADVAPI32$CryptDestroyHash(hHash);
        KERNEL32$CloseHandle(hFile);
        return;
    }

    // Original hashstring calculation regards usage of cbhash for correct bits length
    if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        //cbHash internal bit count is automatically calculated by the API so no need for manual defines
        //Maybe swap out for cats?
        for (DWORD i = 0; i < cbHash; i++)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\t %s-hash\t %s", alg, file);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
    else
    {
        dwStatus = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$CryptGetHashParam failure with code: %d\n", dwStatus);
        return;
    }

    ADVAPI32$CryptDestroyHash(hHash);
    ADVAPI32$CryptReleaseContext(hProv, 0);
    KERNEL32$CloseHandle(hFile);
    return;
}