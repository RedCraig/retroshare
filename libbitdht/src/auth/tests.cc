#include "PasswordAuth.h"
#include <assert.h>

#define KEY_LEN 16
#define PGP_PUB_KEY_LEN 2048
#define PGP_KEY_LEN PGP_PUB_KEY_LEN+2048
#define FKS_ENCRYPTED_DATA_LEN 1024*3

void test_readWriteArray()
{
    // Test write and read array work together.
    // char* writeArray(const char* const data, const unsigned int dataLen,
    //              char* const outbuf, unsigned int usedOutBufLen)
    // const char* readArray(const char* const data,
    //                       char* const outbuf,
    //                       unsigned int &usedOutBufLen)

    // write two arrays to outbuf
    char data1[256] = "hello i am a data buffer, please treat me carefully.\0";
    char data2[256] = "i am the second data buffer.\0";
    char outbuf[1024];
    char* outbufPtr = outbuf;
    memset(outbuf, '\0', 1024);
    unsigned int usedOutbufLen = 0;
    outbufPtr = writeArray(data1, strlen(data1)+1, outbufPtr, usedOutbufLen);
    outbufPtr = writeArray(data2, strlen(data2)+1, outbufPtr, usedOutbufLen);

    // now read both arrays back and compare
    const char* readOutbufPtr = outbuf;
    char readData1[256];
    char readData2[256];
    unsigned int usedReadLen = 0;
    readOutbufPtr = readArray(readOutbufPtr, readData1, usedReadLen);
    readOutbufPtr = readArray(readOutbufPtr, readData2, usedReadLen);

    assert(strcmp(data1, readData1) == 0);
    assert(strcmp(data2, readData2) == 0);
}

// void test_packUnpackMetadata()
// {

// }



// TODO: move this to a test file, had issues doing this first time
//       with imports of libretroshare/src/util/rsaes.h
void test_crypto()
{
    char Kx1[PGP_PUB_KEY_LEN] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\
Version: OpenPGP:SDK v0.9\
\
xsBNBFMYXjUBCACdmfb/fC5u3/oIsbnpKXCqZk3OCx0YSiWAg2SeuyLPj1DES06W\
Yx2eHs0ci7noO6aXbLf0f9+Y4sSJUiTdkZZjHBA5FcTy9FbZmlu0zi/Qqs7EXNJT\
tT1BM3JRvIIEBOSlgEKYzJxb0onX4v7856/sQSi1lZUmy0O6svCNmqFg/Kt9Aa3S\
gNaOeaPDr+hAoYpfyp7m5zYsA5r6Rex6O8qRzTqkTYEAtTq5jAms01YrtluD5GNB\
RZuhiX333fosBueYSuK5KlpOJczn8qViUSEPnybbodcZDZpmcdliyQoIqtJiVFGH\
5gMWn08vLkpX9gzz04gNLJvzHN7GWiiP7/G1ABEBAAHNJVJlZENyYWlnIChHZW5l\
cmF0ZWQgYnkgUmV0cm9TaGFyZSkgPD7CwF8EEwECABMFAlMYXjUJEP3jPOYQGt7o\
AhkBAACn6Af9GP/qezpV6+8uO7dcMCen4GwWcKR1OA3haL3KUc8II68aFOoct7qr\
FsFOw6Cn378w3IC3gAGObUKpWYGU/7b6Gh1i6W6whYl7tWFLevhcSkU4fZF9X3PR\
mgs8Ai22nubevDGGH6M0YBBAnTdsrUtsm4HRDBMLpitt2SQCYc5gnAUuaCRY63Fg\
Ax+P/Kldeso15+dlrpjGr5xZMDWEubWH2GpELJJSOb1CCC3rANcnxUT18kLFBB2K\
jKSTD9ndswUv4mCH9DIaccfMHO0r2XjevAox7gJRGQpbr0wj79Wkb5JDb8z0PFcK\
FwSK6LclF4xv61JR42mYGMEYbPSu4el1Sw==\
=2kN4\
-----END PGP PUBLIC KEY BLOCK-----\
--SSLID--tt0c5f8493c238f2btt4aa6715fa2338;--LOCATION--the_universe;\
--LOCAL--192.168.1.104:2191;--EXT--12.34.56.789:2191;\
\0";
    // printf("--1. Kx1:\n[%s]\n", Kx1);

    char KKS[KEY_LEN];
    memset(KKS, '\0', KEY_LEN);
    generateKey(KKS, KEY_LEN);

    char encryptedData[FKS_ENCRYPTED_DATA_LEN];
    memset(encryptedData, '\0', FKS_ENCRYPTED_DATA_LEN);
    unsigned int encryptedDataLen = FKS_ENCRYPTED_DATA_LEN + 17 + 1;
    encrypt(KKS,
            Kx1, PGP_PUB_KEY_LEN,
            encryptedData, encryptedDataLen);
    // printf("--2. Kx1 encrypted into encryptedData(%d):\n[%s]\n", encryptedDataLen, encryptedData);

    // RsAES::AES_BLOCK_SIZE = 17
    unsigned int decryptedDataLen = FKS_ENCRYPTED_DATA_LEN + 17 + 1 + 17 + 1;;
    char decryptedData[decryptedDataLen];
    memset(decryptedData, '\0', FKS_ENCRYPTED_DATA_LEN);
    decrypt(KKS,
            encryptedData, encryptedDataLen,
            decryptedData, decryptedDataLen);
    // printf("--3. decryptedData(%d):\n[%s]\n", decryptedDataLen, decryptedData);

    assert(strcmp(Kx1, decryptedData) == 0);
}
