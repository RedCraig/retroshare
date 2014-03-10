
int auth();

// Account Registration process
void generateKey(char *key, int keylen);
void encrypt(char* key,
             char* const dataToEncrypt,
             const unsigned int dataToEncryptLen,
             char* const encryptedData,
             unsigned int encryptedDataLen);
void writeFileToDisk(char* data, int dataLen, char* filename, int filenameLen);
void writeFKSFile(char* data, int dataLen, char* filename, int filenameLen);
unsigned int generateSalt();
void keyDerivationFunction(unsigned int salt, char* password, int passwordLen,
                           unsigned char* key, int keylen);
void assembleMedataDataFile(unsigned int salt,
                            unsigned char* KLI, unsigned int KLILen,
                            char* filenameFKS, unsigned int filenameLen,
                            char* KKS, unsigned int KKSLen,
                            char* KW, unsigned int KWLen,
                            char* outbuf, unsigned int outbufLen);
void writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                       char* filename, int filenameLen);

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

/*
Algorithm 2 Login
1: fDL, KDL ← Device.readLocalStore()
2: if fDL "= NULL then // non-interactive login
3: FDL ← Storage.read(fDL)
4: fKS, KKS ← decryptKDL(FDL)
5: saveLoginLocally ← False
6: else // interactive login
7: uname ← User.input(“Enter username:”)
8: passwd ← User.input(“Enter password:”)
9: saveLoginLocally ← User.input(“Remember?”)
10: fLI ← DHT.get(uname)
11: FLI ← Storage.read(fLI)
12: salt ← FLI.salt // stored in plaintext
13: KLI ← KDF(salt,passwd)
14: fKS, KKS, KW, devmap ← decryptKLI (FLI)
15: end if
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
