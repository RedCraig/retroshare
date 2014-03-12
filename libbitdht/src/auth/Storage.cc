/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * IO fns for auth.
*/
#include <fstream>      // std::ifstream, std::ofstream
#include <iostream>     // cout, endl
#include <string.h>     // strlen
#include "Storage.h"


void writeFKSFile(char* data, int dataLen, char* filename,
                  unsigned int &filenameLen)
{
    // storage engine determines filename
    filenameLen = 24;
    memcpy(filename, "dht_filename_for_FKS.txt", filenameLen);
    filename[filenameLen] = '\0';
    writeFileToDisk(data, dataLen, filename);
}

void writeFileToDisk(char* data, int dataLen, char* filename)
{
    std::ofstream outfile;
    outfile.open(filename);
    outfile.write(data, dataLen);
    outfile.close();
}

void writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                       char* const filename, unsigned int &filenameLen)
{
    // storage engine determines filename
    filenameLen = 26;
    memcpy(filename, "password_auth_metadata.txt", filenameLen);
    filename[filenameLen] = '\0';
    writeFileToDisk(metadataBuf, metadataLen, filename);
}

void readFileFromDisk(char* filename, char* buf, unsigned int &bufLen)
{
    unsigned int position = 0;
    std::ifstream infile(filename);
    if(infile.is_open())
    {
        while(!infile.eof() && position < bufLen)
        {
            infile.get(buf[position]);
            position++;
        }
        buf[position-1] = '\0';
        bufLen = position;
    }
    else
    {
        std::cout << "File" << filename << "could not be opened." << std::endl;
    }
}
