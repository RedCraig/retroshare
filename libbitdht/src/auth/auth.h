int auth();
void generateKey(char *key, int keylen);
void encrypt(char* key,
             char* dataToEncrypt, int dataToEncryptLen,
             char* enctyptedData, int enctyptedDataLen);
void writeFile(char* data, int dataLen, char* filename, int filenameLen);
unsigned int generateSalt();
void keyDerivationFunction(unsigned int salt, char* password, int passwordLen,
                           unsigned char* key, int keylen);