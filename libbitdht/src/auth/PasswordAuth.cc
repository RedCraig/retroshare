/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * Passwords paper implementation:
 * http://dx.doi.org/10.1109/P2P.2012.6335797
*/

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

#include "PasswordAuth.h"
#include "Storage.cc"
#include "AuthCryptoFns.cc"

#define USERNAME_LEN 64
#define PASSWORD_LEN 64
#define KEY_LEN 16
#define PGP_PUB_KEY_LEN 2048
#define PGP_KEY_LEN PGP_PUB_KEY_LEN+2048
#define FKS_ENCRYPTED_DATA_LEN 1024*3
#define FILE_NAME_LEN 32
#define METADATA_SIZE 1024*5


bool auth()
{
    test_crypto();
    test_readWriteArray();

    char username[USERNAME_LEN] = "my name";
    char password[PASSWORD_LEN] = "my password";
    // TODO: add private part of pgp key here?
    char pgpkey[PGP_PUB_KEY_LEN] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\
Version: OpenPGP:SDK v0.9\
\
xsBNBFMYXjUBCACdmfb/fC5u3/oIsbnpKXCqZk3OCx0YSiWAg2SeuyLPj1DES06W\
Yx2eHs0ci7noO6aXbLf0f9+JIUSJUiTdkZZjHBA5FcTy9FbZmlu0zi/Qqs7EXNJT\
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
--LOCAL--192.168.1.104:2191;--EXT--12.34.56.789:2191;\
\0";

    registerAccount(username, USERNAME_LEN,
                    password, PASSWORD_LEN,
                    pgpkey, PGP_KEY_LEN);

    return true;
}

void registerAccount(char* username, unsigned int usernameLen,
                     char* password, unsigned int passwordLen,
                     char* pgpkey, unsigned int pgpkeyLen)
{
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
            pgpkey, PGP_PUB_KEY_LEN,
            FKS, FKSEncryptedLen);
    printf("4: FKS ← encryptKKS (Kx1||Kx2|| . . .)\n");

    // 5: fKS ← Storage.create(FKS)
    //    write FKS (encrypted PGP auth data) into storage
    char filenameFKS[FILE_NAME_LEN];
    memset(filenameFKS, '\0', FILE_NAME_LEN);
    writeFKSFile(FKS, FKSEncryptedLen, filenameFKS, FILE_NAME_LEN);
    std::cout << "5: fKS ← Storage.create(FKS)" << filenameFKS << std::endl;

    // 6: salt ← generateSalt()
    unsigned int salt = generateSalt();
    std::cout << "6. Salt: " << salt << std::endl;

    // 7: devmap ← createMap()
    // 8: KLI ← KDF(salt,passwd)
    //    keyDerivationFunction() uses SHA1 to generate KLI from salt and password
    char KLI[SHA_DIGEST_LENGTH];
    memset(KLI, '\0', SHA_DIGEST_LENGTH);
    keyDerivationFunction(salt, password, PASSWORD_LEN, KLI, SHA_DIGEST_LENGTH);
    std::cout << "8: KLI ← KDF(salt,passwd)" << KLI << std::endl;

    // 9: KW ← generateKey() // suitable for the storage system
    char KW[KEY_LEN];
    memset(KW, '\0', KEY_LEN);
    generateKey(KW, KEY_LEN);
    std::cout << "9: KW ← generateKey()" << std::endl;

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
    packMedataDataFile(salt,
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
    writeMetadataFile(metadataBuff, metadataLen,
                      metadataFilename, FILE_NAME_LEN);


    // 12: while DHT.put(uname, fLI) fails
    // 13: uname ← User.input(“Choose new username:”)
    // 14: end while

    printf("end!\n");
}

void packMedataDataFile(unsigned int salt,
                        char* KLI, unsigned int KLILen,
                        char* filenameFKS, unsigned int filenameLen,
                        char* KKS, unsigned int KKSLen,
                        char* KW, unsigned int KWLen,
                        char* outbuf, unsigned int &outbufLen)
{
    // prefix the salt
    // concatenate the data for the metadata file
    // encrypt the data

    // concatenate the data for the metadata file into dataBuffer
    char dataBuffer[outbufLen];
    char* dataBuffPtr = dataBuffer;
    unsigned int usedDataBuffLen = 0;

    // prefix the salt
    unsigned int usedOutBuffLen = 0;
    memcpy(outbuf, &salt, sizeof(salt));
    usedOutBuffLen += sizeof(salt);

    // write the arrays to the databuffer
    dataBuffPtr = writeArray(filenameFKS, filenameLen, dataBuffPtr, usedDataBuffLen);
    dataBuffPtr = writeArray(KKS, KKSLen, dataBuffPtr, usedDataBuffLen);
    dataBuffPtr = writeArray(KW, KWLen, dataBuffPtr, usedDataBuffLen);

    // encrypt the databuffer straight into outbuf
    encrypt((char*)KLI, dataBuffer, usedDataBuffLen,
            outbuf+sizeof(salt), outbufLen);
    usedOutBuffLen += outbufLen;
}

void unpackMetaDataFile(const char* const password, const unsigned int passwordLen,
                        const char* const data, const unsigned int dataLen,
                        unsigned int &salt,
                        char* FKS, unsigned int &FKSLen,
                        char* KKS, unsigned int &KKSLen,
                        char* KW, unsigned int &KWLen)
{
    // prefix the salt
    // concatenate the data for the metadata file
    // encrypt the data

    const char* dataPtr = data;
    unsigned int readData = 0;

    // read salt
    memcpy(&salt, data, sizeof(salt));
    readData += sizeof(salt);
    dataPtr += sizeof(salt);

    // read the encrypted array
    // TODO: Fix this, encArry will be less than METADATA_SIZE,
    //       but the ideal(?) might be reading the length,
    //       then allocating a buffer to read the rest of the data into.
    char encArray[METADATA_SIZE];
    unsigned int encArrayLen = 0;
    readArray(dataPtr, encArray, encArrayLen);

    // Using the password and the salt which we just read,
    // get the key.
    char KLI[SHA_DIGEST_LENGTH];
    memset(KLI, '\0', SHA_DIGEST_LENGTH);
    keyDerivationFunction(salt, password, passwordLen, KLI, SHA_DIGEST_LENGTH);

    // Use the key to decrypt the encoded buffer
    // TODO: Fix this, encArry will be less than METADATA_SIZE,
    //       but the ideal(?) might be reading the length,
    //       then allocating a buffer to read the rest of the data into.
    char decArray[METADATA_SIZE];
    unsigned int decArrayLen = 0;
    decrypt(KLI, encArray, encArrayLen, decArray, decArrayLen);

    // now read FKS, KKS and KW from the decrypted array decArrayLen
    const char* decArrayPtr = decArray;
    decArrayPtr = readArray(decArrayPtr, FKS, FKSLen);
    decArrayPtr = readArray(decArrayPtr, KKS, KKSLen);
    decArrayPtr = readArray(decArrayPtr, KW, KWLen);
}

char* writeArray(const char* const data, const unsigned int dataLen,
                 char* const outbuf, unsigned int usedOutBufLen)
{
    char* outbufPtr = outbuf;

    // write int: length of buffer
    memcpy(outbufPtr, &dataLen, sizeof(dataLen));
    outbufPtr += sizeof(dataLen);
    usedOutBufLen += sizeof(dataLen);

    // write char*: the buffer
    memcpy(outbufPtr, data, dataLen);
    outbufPtr += dataLen;
    usedOutBufLen += dataLen;

    return outbufPtr;
}

const char* readArray(const char* const data,
                      char* const outbuf,
                      unsigned int &usedOutBufLen)
{
    const char* dataPtr = &(*data);

    // read int: length of buffer
    unsigned int arrayLen = 0;
    memcpy(&arrayLen, data, sizeof(arrayLen));
    dataPtr += sizeof(arrayLen);

    // read the char array into outbuf
    memcpy(outbuf, dataPtr, arrayLen);
    usedOutBufLen = arrayLen;
    dataPtr += arrayLen;

    return dataPtr;
}

/*
Algorithm 2 Login
1: fDL, KDL ← Device.readLocalStore()
2: if fDL "= NULL then // non-interactive login
3: FDL ← Storage.read(fDL)
4: fKS, KKS ← decryptKDL(FDL)
5: saveLoginLocally ← False
6-15: interactiveLogin()
16: FKS ← Storage.read(fKS)
17: Kx1, Kx2,... ← decryptKKS (FKS)
18: if saveLoginLocally then
19: KDL ← generateKey()
20: FDL ← encryptKDL(fKS||KKS)
21: fDL ← Storage.create(FDL)
22: Device.writeLocalStore(fDL||KDL)
23: devmap.append(Device.ID, fDL||KDL)
24: FLI ← salt||encryptKLI (fKS||KKS||KW||devmap)
25: Storage.write(fLI,FLI) // using KW
26: end if
*/
void interactiveLogin(char* username,
                      char* password, unsigned int passwordLen)
{
    // 10:   fLI ← DHT.get(uname)
    // fLI = storage.get(filename);
    // fLI is the metadata file name
    char metadataFileName[FILE_NAME_LEN];
    memset(metadataFileName, '\0', FILE_NAME_LEN);
    unsigned int filenameLen = FILE_NAME_LEN;
    readFileFromDisk(username, metadataFileName, filenameLen);

    // 11:   FLI ← Storage.read(fLI)
    // FLI = storage.get(fLI);
    // FLI is the metadata file
    char metadataFile[METADATA_SIZE];
    memset(metadataFile, '\0', METADATA_SIZE);
    unsigned int metadataFileLen = METADATA_SIZE;
    readFileFromDisk(metadataFileName, metadataFile, metadataFileLen);


    unsigned int salt = 0;
    char FKS[FKS_ENCRYPTED_DATA_LEN];
    unsigned int FKSLen = 0;
    char KKS[KEY_LEN];
    unsigned int KKSLen = 0;
    char KW[KEY_LEN];
    unsigned int KWLen = 0;
    unpackMetaDataFile(password, passwordLen,
                       metadataFile, metadataFileLen,
                       salt,
                       FKS, FKSLen,
                       KKS, KKSLen,
                       KW, KWLen);

    // 12:   salt ← FLI.salt // stored in plaintext
    // salt = getSalt(FLI);
    // 13:   KLI ← KDF(salt, passwd)
    // KLI = KDF(salt, passwd);
    // 14:   fKS, KKS, KW, devmap ← decryptKLI (FLI)
    // decryptKLI (FLI, fKS, KKS, KW);
}

// Algorithm 2 Login
// 1: fDL, KDL ← Device.readLocalStore()
// 2:    if fDL "= NULL then // non-interactive login
// 3:    FDL ← Storage.read(fDL)
// 4:    fKS, KKS ← decryptKDL(FDL)
// 5:    saveLoginLocally ← False

// 16: FKS ← Storage.read(fKS)
// 17: Kx1, Kx2,... ← decryptKKS (FKS)
// 18: if saveLoginLocally then
// 19:   KDL ← generateKey()
// 20:   FDL ← encryptKDL(fKS||KKS)
// 21:   fDL ← Storage.create(FDL)
// 22:   Device.writeLocalStore(fDL||KDL)
// 23:   devmap.append(Device.ID, fDL||KDL)
// 24:   FLI ← salt||encryptKLI (fKS||KKS||KW||devmap)
// 25:   Storage.write(fLI,FLI) // using KW
// 26: end if


void test_readWriteArray()
{
    // test write and read array work together.
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
