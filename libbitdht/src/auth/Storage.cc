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
#include "bitdht/bdiface.h"

Storage::Storage(BitDhtHandler *bitdhtHandler, UdpBitDht *bitdht)
{
    mBitdhtHandler = bitdhtHandler;
    mBitdht = bitdht;
}

void Storage::writeFKSFile(char* data, int dataLen, char* filename,
                           unsigned int &filenameLen)
{
    // storage engine determines filename
    filenameLen = 24;
    memcpy(filename, "dht_filename_for_FKS.txt", filenameLen);
    filename[filenameLen] = '\0';
    writeFileToDisk(data, dataLen, filename);
}

void Storage::writeFileToDisk(char* data, int dataLen, char* filename)
{
    std::ofstream outfile;
    outfile.open(filename, std::ios_base::trunc);
    outfile.write(data, dataLen);
    outfile.close();
}

void Storage::writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                                char* const filename, unsigned int &filenameLen)
{
    // storage engine determines filename
    filenameLen = 26;
    memcpy(filename, "password_auth_metadata.txt", filenameLen);
    filename[filenameLen] = '\0';
    writeFileToDisk(metadataBuf, metadataLen, filename);
}

void Storage::readFileFromDisk(const char* const filename,
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

bool Storage::postDHTValue(bdId &targetNode,
                           bdNodeId key,
                           std::string hash,
                           std::string secret)
{
    mBitdht->postHash(targetNode, key, hash, secret);

    // check for results
    while(false == mBitdhtHandler->m_postHashGotResult)
    {
        sleep(10);
    }

    return mBitdhtHandler->m_postHashSuccess;
}


bool Storage::getDHTValue(bdId &targetNode,
                          bdNodeId key,
                          std::string &value)
{
    mBitdht->getHash(targetNode, key);

    // check for results
    while(false == mBitdhtHandler->m_gotHashResult)
    {
        sleep(10);
    }

    value = mBitdhtHandler->m_getHashValue;
    return true;
}


// void Storage::getHash(bdNode &node, const unsigned char *const key)
// {
//     // TODO: do we call find_node here (and wait for it to finish)
//     //   so that we have a bdId to make the request against?
//     //   Or do we make this fn expect a bdId targetNode, and perform the
//     //   find_node search outside of here.
//     bdId id;

//     bdNodeId nodeId;
//     memcpy(nodeId.data, key, BITDHT_KEY_LEN);

//     node.send_get_hash_query(id, nodeId);
// }

// // TODO: getHashCallback
// void Storage::getHashCallback(std::list<std::string> &values)
// {
//     std::cerr << " hash peers:";
//     std::list<std::string>::iterator it;
//     for(it = values.begin(); it != values.end(); it++)
//     {
//         std::cerr << " hash content here";
//         // bdPrintCompactPeerId(std::cerr, *it);
//     }
//     std::cerr << std::endl;
// }
