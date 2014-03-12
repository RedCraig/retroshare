/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * IO fns for auth.
 * TODO: Currently writes to disk, update to use DHT.
*/

#ifndef STORAGE_H
#define STORAGE_H

// write data to disk.
void writeFileToDisk(char* data, int dataLen, char* filename);

// Specifically writes the key store file (FKS)to disk. FKS is the encrypted
// PGP file.
// This function gives the FKS file a filename, and sets the
// char* filename to that value.
void writeFKSFile(char* data,
                  int dataLen,
                  char* filename,
                  unsigned int &filenameLen);

// Specifically writes the Metadata file (FLI) to disk.
// This function gives the FKS file a filename, and sets the
// char* filename to that value.
void writeMetadataFile(char* metadataBuf,
                       const unsigned int metadataLen,
                       char* const filename,
                       unsigned int &filenameLen);

// bufLen[in] the length of buf that can be used
// bufLen[out] the length of the data that was written to buf
void readFileFromDisk(char* filename, char* buf, unsigned int &bufLen);

#endif //STORAGE_H
