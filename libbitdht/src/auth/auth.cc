// DHT lookup uname, returns f[LI] (metadata filename)
// DHT lookup f[LI], returns F[LI] (metadata file)
// in file F[LI] get the filename f[KS] of the file F[KS], which is the PGP keystore file
// NOTE: DHT should set the filename itself, so that it can retry in case of a
//       file already existing with the same name.

// TODO:
//      when writing to metadata file, i'm using hardcoded lengths. This code will
//      also have to use these lengths, magically - OR we can change the code
//      here to write the length of each string/buffer first, followed by the
//      buffer so that this code can correctly deserialize them when reading the
//      file back from the DHT and the lengths are unknown.

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include "auth.h"
#include <openssl/sha.h>
#include "../../libretroshare/src/util/rsaes.h"

using namespace std;

#define PASSWORD_LEN 32
#define KEY_LEN 16
#define PGP_PUB_KEY_LEN 2048
#define FKS_ENCRYPTED_DATA_LEN 1024*3
#define FILE_NAME_LEN 32
#define METADATA_SIZE 1024*5

int auth()
{
    // variables that this function will expect
    //char uname[32] = "my name";
    char password[32] = "my password";
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
    // 3: KKS ← generateKey()
    //    KKS used to encrypt FKS, the encrypted file with PGP data
    char KKS[KEY_LEN];
    memset(KKS, '\0', KEY_LEN);
    generateKey(KKS, KEY_LEN);
    printf("3: KKS ← generateKey()\n");

    // 4: FKS ← encryptKKS (Kx1||Kx2|| . . .)
    //    encrypt PGP auth data into FKS

    char FKS[FKS_ENCRYPTED_DATA_LEN];
    memset(FKS, '\0', FKS_ENCRYPTED_DATA_LEN);
    unsigned int FKSEncryptedLen = FKS_ENCRYPTED_DATA_LEN;
    encrypt(KKS,
            Kx1, PGP_PUB_KEY_LEN,
            FKS, FKSEncryptedLen);
    printf("4: FKS ← encryptKKS (Kx1||Kx2|| . . .)\n");

    // 5: fKS ← Storage.create(FKS)
    //    write FKS (encrypted PGP auth data) into storage
    char filenameFKS[FILE_NAME_LEN];
    memset(filenameFKS, '\0', FILE_NAME_LEN);
    writeFKSFile(FKS, FKSEncryptedLen, filenameFKS, FILE_NAME_LEN);
    cout << "5: fKS ← Storage.create(FKS)" << filenameFKS << endl;

    // 6: salt ← generateSalt()
    unsigned int salt = generateSalt();
    cout << "6. Salt: " << salt << endl;

    // 7: devmap ← createMap()
    // 8: KLI ← KDF(salt,passwd)
    //    keyDerivationFunction() uses SHA1 to generate KLI from salt and password
    unsigned char KLI[SHA_DIGEST_LENGTH];
    memset(KLI, '\0', SHA_DIGEST_LENGTH);
    keyDerivationFunction(salt, password, PASSWORD_LEN, KLI, SHA_DIGEST_LENGTH);
    cout << "8: KLI ← KDF(salt,passwd)" << KLI << endl;

    // 9: KW ← generateKey() // suitable for the storage system
    char KW[KEY_LEN];
    memset(KW, '\0', KEY_LEN);
    generateKey(KW, KEY_LEN);
    cout << "9: KW ← generateKey()" << endl;

    // 10: FLI ← salt||encrypt(KLI) (fKS||KKS||KW ||devmap)
    //     Encrypt data in local file: (fKS, KKS, KW) using symmetric key KLI.
    //     concatenate the data for the metadata file
    //     encrypt the data
    //     prefix the salt
    char metadataBuff[METADATA_SIZE];
    memset(metadataBuff, '\0', METADATA_SIZE);
    unsigned int metadataLen = METADATA_SIZE;
    // TODO: Could make a class for the metadata file, which handled (de)serialise
    //       It could also have a DHT write fn.
    assembleMedataDataFile(salt,
                           KLI, SHA_DIGEST_LENGTH,
                           filenameFKS, FILE_NAME_LEN,
                           KKS, KEY_LEN,
                           KW, KEY_LEN,
                           metadataBuff, metadataLen);
    // metadataLen is now the length of the metadata buffer

    // 11: fLI ← Storage.create(FLI)
    //     using KW, write the fLI file to disk/storage/DHT
    char metadataFilename[FILE_NAME_LEN];
    memset(metadataFilename, '\0', FILE_NAME_LEN);
    writeMetadataFile(metadataBuff, METADATA_SIZE,
                      metadataFilename, FILE_NAME_LEN);


    // 12: while DHT.put(uname, fLI) fails
    // 13: uname ← User.input(“Choose new username:”)
    // 14: end while

    printf("end!\n");

    return 1;
}

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
    // TODO: should this really be in it's own function?

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

    // TODO: reinterpret_cast for this call might be borking the data that I'm
    //       passing in. Double check intput/output match expected values.
    // Encrypt concatenated data [salt||encrypt(KLI, (fKS||KKS||KW))] using
    // using symmetric key KLI (aes encrypt/decrypt).
    // TODO: we're not using a salt so that this is repeatable(?)
    //       test that data we encrypt, can be decrypted with the same key
    RsAES::aes_crypt_8_16(reinterpret_cast<unsigned char*>(dataToEncrypt),
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
    // TODO: should this really be in it's own function?

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

    // TODO: reinterpret_cast for this call might be borking the data that I'm
    //       passing in. Double check intput/output match expected values.
    // Encrypt concatenated data [salt||encrypt(KLI, (fKS||KKS||KW))] using
    // using symmetric key KLI (aes encrypt/decrypt).
    // TODO: we're not using a salt so that this is repeatable(?)
    //       test that data we encrypt, can be decrypted with the same key
    RsAES::aes_decrypt_8_16(reinterpret_cast<unsigned char*>(dataToEncrypt),
                            dataToEncryptLen,
                            reinterpret_cast<unsigned char*>(key),
                            NULL,
                            reinterpret_cast<unsigned char*>(encryptedData),
                            encryptedDataLen);
}

void writeFKSFile(char* data, int dataLen, char* filename, int filenameLen)
{
    snprintf(filename, filenameLen, "dht_filename_for_FKS.txt");
    writeFileToDisk(data, dataLen, filename, filenameLen);
}
void writeFileToDisk(char* data, int dataLen, char* filename, int filenameLen)
{

    ofstream dhtfile;
    dhtfile.open(filename);
    dhtfile.write(data, dataLen);
    dhtfile.close();
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

void assembleMedataDataFile(unsigned int salt,
                            unsigned char* KLI, unsigned int KLILen,
                            char* filenameFKS, unsigned int filenameLen,
                            char* KKS, unsigned int KKSLen,
                            char* KW, unsigned int KWLen,
                            char* outbuf, unsigned int &outbufLen)
{
    // prefix the salt
    // concatenate the data for the metadata file
    // encrypt the data

    // prefix the salt
    memcpy(outbuf, &salt, sizeof(salt));

    // concatenate the data for the metadata file
    char temp[outbufLen];

    memcpy(temp, filenameFKS, filenameLen);
    unsigned int usedBufLen = filenameLen;

    memcpy(temp+usedBufLen, KKS, KKSLen);
    usedBufLen += KKSLen;

    memcpy(temp+usedBufLen, KW, KWLen);
    usedBufLen += KWLen;

    // temp[usedBufLen]
    memcpy( outbuf+sizeof(salt), temp, outbufLen);
    unsigned int metadatalen = outbufLen-sizeof(salt);
    encrypt((char*)KLI, temp, usedBufLen,
            outbuf+sizeof(salt), metadatalen);

    outbufLen = metadatalen;
}

void writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                       char* filename, int filenameLen)
{
    snprintf(filename, filenameLen, "metadata.txt");
    writeFileToDisk(metadataBuf, metadataLen, filename, filenameLen);
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
    printf("--1. Kx1:\n[%s]\n", Kx1);

    char KKS[KEY_LEN];
    memset(KKS, '\0', KEY_LEN);
    generateKey(KKS, KEY_LEN);

    char encryptedData[FKS_ENCRYPTED_DATA_LEN];
    memset(encryptedData, '\0', FKS_ENCRYPTED_DATA_LEN);
    unsigned int encryptedDataLen = FKS_ENCRYPTED_DATA_LEN + 17 + 1;
    encrypt(KKS,
            Kx1, PGP_PUB_KEY_LEN,
            encryptedData, encryptedDataLen);
    printf("--2. Kx1 encrypted into encryptedData(%d):\n[%s]\n", encryptedDataLen, encryptedData);

    // RsAES::AES_BLOCK_SIZE = 17
    unsigned int decryptedDataLen = FKS_ENCRYPTED_DATA_LEN + 17 + 1 + 17 + 1;;
    char decryptedData[decryptedDataLen];
    memset(decryptedData, '\0', FKS_ENCRYPTED_DATA_LEN);
    decrypt(KKS,
            encryptedData, encryptedDataLen,
            decryptedData, decryptedDataLen);
    printf("--3. decryptedData(%d):\n[%s]\n", decryptedDataLen, decryptedData);

    //assert(Kx1 == decryptedData)
}
