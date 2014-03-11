/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * IO fns for auth.
*/
#include <fstream>      // std::ifstream, std::ofstream
#include "Storage.h"


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

void readFile(char* filename, char* buf, const unsigned int bufLen)
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
    }
    else
    {
        std::cout << "File" << filename << "could not be opened." << std::endl;
    }
}
