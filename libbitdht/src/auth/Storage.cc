/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * IO fns for auth.
*/
#include <fstream>      // std::ifstream, std::ofstream
#include "storage.h"


void writeFKSFile(char* data, int dataLen, char* filename, int filenameLen)
{
    snprintf(filename, filenameLen, "dht_filename_for_FKS.txt");
    writeFileToDisk(data, dataLen, filename, filenameLen);
}

void writeFileToDisk(char* data, int dataLen, char* filename, int filenameLen)
{

    std::ofstream outfile;
    outfile.open(filename);
    outfile.write(data, dataLen);
    outfile.close();
}

void writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                       char* filename, int filenameLen)
{
    snprintf(filename, filenameLen, "password_auth_metadata.txt");
    writeFileToDisk(metadataBuf, metadataLen, filename, filenameLen);
}
