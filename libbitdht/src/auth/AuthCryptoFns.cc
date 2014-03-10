/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * Contains generic somewhat crypto related fns for auth.
*/
#include "AuthCryptoFns.h"


void generateKey(char *key, int keylen)
{
    // TODO: not cross platform, unix only
    ifstream random("/dev/urandom", ios_base::in);
    random.read(reinterpret_cast<char*>(key), keylen);
    random.close();
}

void encrypt(char* key,
             char* const dataToEncrypt,
             const unsigned int dataToEncryptLen,
             char* const encryptedData,
             unsigned int &encryptedDataLen)
{
    // static bool   aes_crypt_8_16(const uint8_t *input_data,
    //                              uint32_t input_data_length,
    //                              uint8_t key[16],
    //                              uint8_t salt[8],
    //                              uint8_t *output_data,
    //                              uint32_t& output_data_length);
    // static bool aes_decrypt_8_16(const uint8_t *input_data,
    //                              uint32_t input_data_length,
    //                              uint8_t key[16],
    //                              uint8_t salt[8],
    //                              uint8_t *output_data,
    //                              uint32_t& output_data_length);

    // Encrypt concatenated data [salt||encrypt(KLI, (fKS||KKS||KW))] using
    // using symmetric key KLI (aes encrypt/decrypt).
    RsAES::aes_crypt_8_16(reinterpret_cast<unsigned char*>(dataToEncrypt),
                          dataToEncryptLen,
                          reinterpret_cast<unsigned char*>(key),
                          NULL,
                          reinterpret_cast<unsigned char*>(encryptedData),
                          encryptedDataLen);
}

void decrypt(char* key,
             char* const dataToDecrypt,
             const unsigned int dataToDecryptLen,
             char* const decryptedData,
             unsigned int decryptedDataLen)
{
    // static bool   aes_crypt_8_16(const uint8_t *input_data,
    //                              uint32_t input_data_length,
    //                              uint8_t key[16],
    //                              uint8_t salt[8],
    //                              uint8_t *output_data,
    //                              uint32_t& output_data_length);
    // static bool aes_decrypt_8_16(const uint8_t *input_data,
    //                              uint32_t input_data_length,
    //                              uint8_t key[16],
    //                              uint8_t salt[8],
    //                              uint8_t *output_data,
    //                              uint32_t& output_data_length);

    // Decrypt concatenated data [salt||Decrypt(KLI, (fKS||KKS||KW))] using
    // using symmetric key KLI (aes Decrypt/decrypt).
    RsAES::aes_decrypt_8_16(reinterpret_cast<unsigned char*>(dataToDecrypt),
                            dataToDecryptLen,
                            reinterpret_cast<unsigned char*>(key),
                            NULL,
                            reinterpret_cast<unsigned char*>(decryptedData),
                            decryptedDataLen);
}

unsigned int generateSalt()
{
    // TODO: not cross platform, unix only
    ifstream random("/dev/urandom", ios_base::in);
    unsigned int salt;
    random.read(reinterpret_cast<char*>(&salt), sizeof(salt));
    random.close();
    return salt;
}

void keyDerivationFunction(unsigned int salt, char* password, int passwordLen,
                           unsigned char* key, int keylen)
{
    // Object to hold the current state of the hash
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    // Hash each piece of data as it comes in:
    SHA1_Update(&ctx, (char*)&salt, sizeof(salt));
    // SHA1_Update(&ctx, "hell", 4);
    SHA1_Update(&ctx, password, passwordLen);
    // unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(key, &ctx);
}


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

    assert(Kx1 == decryptedData);
}
