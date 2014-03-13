/*
 * Author: Craig McInnes
 * Date: 10/03/2014
 *
 * IO fns for auth.
*/
#include <fstream>      // std::ifstream, std::ofstream
#include <iostream>     // cout, endl
#include <cstring>      // strlen
#include "Storage.h"
#include <libbitdht/src/bitdht/bdiface.h>


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
    outfile.open(filename, std::ios_base::trunc);
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

void readFileFromDisk(const char* const filename,
                      char* buf, unsigned int &bufLen)
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
        bufLen = position-1;
    }
    else
    {
        std::cout << "File" << filename << "could not be opened." << std::endl;
    }
}

// TODO: getHash
void getHash(const unsigned char *const info_hash)
{
    // TODO: look at where bdNode.cc:: send_query() is called, and how the
    //       bdId and bdNodeId is formed for that call.
    // bdId and bdNodeId are defined in <libbitdht/src/bitdht/bdiface.h>
    bdId id;

    bdNodeId id;
    memcpy(id.data, info_hash, BITDHT_KEY_LEN);

    // bdNode::send_get_hash_query(bdId *id, bdNodeId *const info_hash);
    send_get_hash_query(bdId *id, id);
}

// TODO: getHashCallback
void getHashCallback(std::list<std::string> &values)
{
    std::cerr << " hash peers:";
    std::list<std::string>::iterator it;
    for(it = values.begin(); it != values.end(); it++)
    {
        std::cerr << " hash content here";
        // bdPrintCompactPeerId(std::cerr, *it);
    }
    std::cerr << std::endl;
}
