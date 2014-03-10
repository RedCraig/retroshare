/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * IO fns for auth.
*/

#include <storage.h>

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

void writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                       char* filename, int filenameLen)
{
    snprintf(filename, filenameLen, "metadata.txt");
    writeFileToDisk(metadataBuf, metadataLen, filename, filenameLen);
}
