#include <string.h>
#include <stdio.h>

// TODO: FUGLY HACK. Can't import auth.cc because it's using a relative import
//       to get the rsaes.h, and the relative import doesn't work from here.
//       The build settings of auth (i.e. libbitdht) don't include
//       libretroshare because that would be a circular dep. Hrmmmmmmm.
//#include "auth.cc"
#include "../../../../libretroshare/src/util/rsaes.h"

#define FKS_ENCRYPTED_DATA_LEN 2048
#define PGP_PUB_KEY_LEN 2048
#define KEY_LEN 16



void encrypt(char* key,
             char* const dataToEncrypt,
             const unsigned int dataToEncryptLen,
             char* const encryptedData,
             unsigned int encryptedDataLen)
{
    aes_crypt_8_16(reinterpret_cast<unsigned char*>(dataToEncrypt),
                          dataToEncryptLen,
                          reinterpret_cast<unsigned char*>(key),
                          NULL,
                          reinterpret_cast<unsigned char*>(encryptedData),
                          encryptedDataLen);
}

void decrypt(char* key,
             char* const dataToEncrypt,
             const unsigned int dataToEncryptLen,
             char* const encryptedData,
             unsigned int encryptedDataLen)
{
    RsAES::aes_decrypt_8_16(reinterpret_cast<unsigned char*>(dataToEncrypt),
                            dataToEncryptLen,
                            reinterpret_cast<unsigned char*>(key),
                            NULL,
                            reinterpret_cast<unsigned char*>(encryptedData),
                            encryptedDataLen);
}

int test_crypto()
{
    char Kx1[PGP_PUB_KEY_LEN] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\
Version: OpenPGP:SDK v0.9\
\
xsBNBFMYXjUBCACdmfb/fC5u3/oIsbnpKXCqZk3OCx0YSiWAg2SeuyLPj1DES06W\
Yx2eHs0ci7noO6aXbLf0f9+Y4sSJUiTdkZZjHBA5FcTy9FbZmlu0zi/Qqs7EXNJT\
tT1BM3JRvIIEBOSlgEKYzJxb0onX4vQ1J1/sQSi1lZUmy0O6svCNmqFg/Kt9Aa3S\
gNaOeaPDr+hAoYpfyp7m5zYsA5r6Rex6O8qRzTqkTYEAtTq5jAms01YrtluD5GNB\
RZuhiXNobfosBueYSuK5KlpOJczn8qViUSEPnybbodcZDZpmcdliyQoIqtJiVRny\
5gMWn08vLkpX9gzz04gNLJvzHN7GWiiP7/G1ABEBAAHNJVJlZENyYWlnIChHZW5l\
cmF0ZWQgYnkgUmV0cm9TaGFyZSkgPD7CwF8EEwECABMFAlMYXjUJEP3jPOYQGt7o\
AhkBAACn6Af9GP/qezpV6+8uO7dcMCen4GwWcKR1OA3haL3KUc8II68aFOoct7qr\
FsFOw6Cn378w3IC3gAGObUKpWYGU/7b6Gh1i6W6whYl7tWFLevhcSkU4fZF9X3PR\
mgs8AiofnubevDGGH6M0YBBAnTdsrUtsm4HRDBMLpitt2SQCYc5gnAUuaCRY63Fg\
Ax+P/Kldeso15+dlrpjGr5xZMDWEubWH2GpELJJSOb1CCC3rANcnxUT18kLFBB2K\
jKSTD9ndswUv4mCH9DIaccfMHO0r2XjevAox7gJRGQpbr0wj79Wkb5JDb8z0PFcK\
FwSK6LclF4xv61JR42mYGMEYbPSu4el1Sw==\
=2kN4\
-----END PGP PUBLIC KEY BLOCK-----\
--SSLID--660c5d8193c238f2b661aa6715da2338;--LOCATION--laptop;\
--LOCAL--192.168.1.104:2191;--EXT--87.198.30.166:2191;\
\0";

    char KKS[KEY_LEN];
    memset(KKS, '\0', KEY_LEN);

    char FKS[FKS_ENCRYPTED_DATA_LEN];
    memset(FKS, '\0', FKS_ENCRYPTED_DATA_LEN);
    printf("--1. Kx1:\n[%s]\n", Kx1);

    encrypt(KKS,
            Kx1, PGP_PUB_KEY_LEN,
            FKS, FKS_ENCRYPTED_DATA_LEN);
    printf("--2. Kx1 encrypted into FKS:\n[%s]\n", FKS);

    decrypt(KKS,
            Kx1, PGP_PUB_KEY_LEN,
            FKS, FKS_ENCRYPTED_DATA_LEN);
    printf("--3. decrypted FKS:\n[%s]\n", FKS);

}
