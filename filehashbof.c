#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>

#pragma comment (lib, "Crypt32")

void main()
{
    //--------------------------------------------------------------------
    //  Declare variables.
    DWORD dwStatus;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;

    //--------------------------------------------------------------------
    // Get a handle to a cryptography provider context.


    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        printf("CryptAcquireContext complete. \n");
    }
    else
    {
        printf("Acquisition of context failed.\n");
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
        exit(1);
    }

    // Test File Area

    FILE* pFile;
    long lSize;
    char* buffer;
    size_t result;

    pFile = fopen("vc142.pdb", "rb");
    if (pFile == NULL)
    {
        fputs("File error", stderr);
        exit(1);
    }

    // obtain file size:
    fseek(pFile, 0, SEEK_END);
    lSize = ftell(pFile);
    rewind(pFile);

    // Allocate char ptr memory buffer for entire file:
    buffer = (char*)malloc(sizeof(char) * lSize);
    if (buffer == NULL)
    {
        fputs("Memory error", stderr);
        exit(2);
    }

    printf("Size of bytes of data read of data was %i\n", lSize);
    // Copy the file into the buffer:
    result = fread(buffer, 1, lSize, pFile);
    if (result != lSize)
    {
        fputs("Reading error", stderr);
        exit(3);
    }
    
    // Expected whole file loaded into membuffer.


    if (CryptHashData(hHash, (BYTE *) buffer, 0, CRYPT_USERDATA))
    {
        printf("Crypt Hash Data for the buffer was successfuls.\n ");
    
    }
    else
    {

        printf("Error during CryptGetHashData!\n");
        exit(1);
    }
    
    DWORD      dwParam = CALG_MD5;
    BYTE       pbData[16];
    DWORD*     pdwDataLen = sizeof(DWORD);
    DWORD cbHash = 0;
    BYTE rgbHash[16];

    //if ( CryptGetHashParam(hHash, HP_HASHVAL, pbData, 16, 0))
    if ((CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)))
    {
        printf("Got some success.");
        printf("Hash is %s", pbData);
        //printf("Hash is %i", pbData);       
    }
    else 
    {
        dwStatus = GetLastError();
        printf("Error during CryptGetHashParam! with at %d\n", dwStatus);
        fclose(pFile);
        free(buffer);
        exit(1);
    }
  
    // Free up the Test FIle 
    // Clean up
    fclose(pFile);
    free(buffer);

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
    HFILE hFile;
    DWORD dwStatus;

    hFile = CreateFile(path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        printf("Error on attmepts to open file %s\nError: %d\n", path, dwStatus);
        exit(2);
    }

    return hFile;
}