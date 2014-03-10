/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * Contains generic somewhat crypto related fns for auth.
*/

// Account Registration process functions
void generateKey(char *key, int keylen);

// Encrypts dataToEncrypt into the encryptedData buffer, using
// libretroshare::RsAES::aes_crypt_8_16.
// encryptedDataLen should be set to the encryptedData buffer size when the fn
// is called.
// encryptedDataLen is updated in this fn to the final size that the encrypted
// data occupies in encryptedData buffer.
void encrypt(char* key,
             char* const dataToEncrypt,
             const unsigned int dataToEncryptLen,
             char* const encryptedData,
             unsigned int &encryptedDataLen);

// Decrypts dataToEncrypt into the encryptedData buffer, using
// libretroshare::RsAES::aes_decrypt_8_16.
// decryptedDataLen should be set to the decryptedData buffer size when the fn
// is called.
// decryptedDataLen is updated in this fn to the final size that the decrypted
// data occupies in decryptedDataLen buffer.
void decrypt(char* key,
             char* const dataToDecrypt,
             const unsigned int dataToDecryptLen,
             char* const decryptedData,
             unsigned int decryptedDataLen);

unsigned int generateSalt();

void keyDerivationFunction(unsigned int salt, char* password, int passwordLen,
                           unsigned char* key, int keylen);

void test_crypto();