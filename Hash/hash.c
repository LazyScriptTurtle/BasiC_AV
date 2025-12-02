#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "hash.h"
#include "..\Logger\logger.h"



void calculate_file_hash(char* filepath, char* output_hash) {
    //log_info("Starting hash calculation");
    FILE* file = fopen(filepath, "rb");
    if (file == NULL){
        log_warning("File cant be opened");
        return;
    }
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(filesize);
    if (buffer == NULL){
        log_error("Allocation Memory problem");
        fclose(file);
        return;
    }
    fread(buffer, 1, filesize, file);
    fclose(file);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    log_error("CryptAcquireContext failed");
    free(buffer);
    return;
}
    //log_info("CryptAcquireContext ok");

if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    log_error("CryptCreateHash failed");
    CryptReleaseContext(hProv, 0);
    free(buffer);
    return;
}
    //log_info("CryptCreateHash ok");

if (!CryptHashData(hHash, buffer, filesize, 0)) {
    log_error("CryptHashData failed");
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    free(buffer);
    return;
}
    //log_info("CryptHashData ok");

DWORD hashLen = 32;
BYTE hashBytes[32];

if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
    log_error("CryptGetHashParam failed");
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    free(buffer);
    return;
}
    //log_info("CryptGetHashParam ok");

output_hash[0] = '\0';
for (int i = 0; i < hashLen; i++) {
    sprintf(output_hash + (i * 2), "%02x", hashBytes[i]);
}

CryptDestroyHash(hHash);
CryptReleaseContext(hProv, 0);
free(buffer);

}