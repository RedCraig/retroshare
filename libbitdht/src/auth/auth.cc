// DHT lookup uname, returns f[LI] (metadata filename)
// DHT lookup f[LI], returns F[LI] (metadata file)
// in file F[LI] get the filename f[KS] of the file F[KS], which is the PGP keystore file
// NOTE: DHT should set the filename itself,

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include "auth.h"
#include <openssl/sha.h>

using namespace std;


/*
Algorithm 1 Account Registration
1: uname ← User.input(“Choose username:”)
2: passwd ← User.input(“Choose strong password:”)
3: KK S ← generateKey()
4: FKS ← encryptKKS (Kx1||Kx2|| . . .)
5: fK S ← Storage.create(FK S )
6: salt ← generateSalt()
7: devmap ← createMap()
8: KLI ← KDF(salt,passwd)
9: KW ← generateKey() // suitable for the storage system
10: FLI ← salt||encryptKLI (fKS||KKS||KW ||devmap)
11: fLI ← Storage.create(FLI ) // using KW
12: while DHT.put(uname,fLI ) fails
13: uname ← User.input(“Choose new username:”)
14: end while
*/

#define PASSWORD_LEN 32
#define KKS_LEN 32
#define PGP_PUB_KEY_LEN 2048
#define FKS_ENCRYPTED_DATA_LEN 2048
#define FILE_NAME_LEN 32


int auth()
{
    // variables that this function will expect
    char uname[32] = "my name";
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

    char kks[KKS_LEN];
    generateKey(kks, KKS_LEN);
    printf("3: KKS ← generateKey()\n");

    // 4: FKS ← encryptKKS (Kx1||Kx2|| . . .)
    char FKS[FKS_ENCRYPTED_DATA_LEN];
    encrypt(kks,
            Kx1, PGP_PUB_KEY_LEN,
            FKS, FKS_ENCRYPTED_DATA_LEN);
    printf("4: FKS ← encryptKKS (Kx1||Kx2|| . . .)\n");

    // 5: fKS ← Storage.create(FKS)
    char filenameFKS[FILE_NAME_LEN];
    writeFile(FKS, FKS_ENCRYPTED_DATA_LEN, filenameFKS, FILE_NAME_LEN);
    printf("5: fKS ← Storage.create(FKS)\n");

    // 6: salt ← generateSalt()
    unsigned int salt = generateSalt();
    cout << "6. Salt: " << salt << endl;

    // 7: devmap ← createMap()
    // 8: KLI ← KDF(salt,passwd)
    unsigned char KLI[SHA_DIGEST_LENGTH];
    keyDerivationFunction(salt, password, PASSWORD_LEN, KLI, SHA_DIGEST_LENGTH);
    cout << "8: KLI ← KDF(salt,passwd)" << KLI << endl;

    // 9: KW ← generateKey() // suitable for the storage system
    char KW[KKS_LEN];
    generateKey(KW, KKS_LEN);
    cout << "9: KW ← generateKey()" << KW << endl;

    // 10: FLI ← salt||encrypt(KLI) (fKS||KKS||KW ||devmap)
    //     concatenate the data for the metadata file
    //     encrypt the data
    //     prefix the salt
    assembleMedataDataFile(salt, filenameFKS);

    // 11: fLI ← Storage.create(FLI) // using KW
    //     write the fLI file to disk/storage/DHT
    writeMedataDataFile();

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
             char* dataToEncrypt, int dataToEncryptLen,
             char* enctyptedData, int enctyptedDataLen)
{
    // TODO: THIS ACTUALLY NEEDS TO ENCRYPT
    // symmetric key encrypt 'data' with key, output to encryptedData
    // aes?

    //assert(dataToEncryptLen <= enctyptedDataLen)
    // dest, src, dest len
    memcpy(enctyptedData, dataToEncrypt, enctyptedDataLen);
}

void writeFile(char* data, int dataLen, char* filename, int filenameLen)
{
    snprintf(filename, filenameLen, "dht_filename_for_fks.txt");

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

void assembleMedataDataFile(salt, filenameFKS)
{

}

/*
paper notes:
- distributed storage allows for brute forcing
- why is the salt in plaintext, makes it easier to hack/brute force
*/