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


Storage::Storage(bool useDHT,
                 BitDhtHandler *const bitdhtHandler,
                 UdpBitDht *const bitdht,
                 bdId *const targetNode)
{
    mUseDHT = useDHT;
    if(mUseDHT == true)
    {
        mBitdhtHandler = bitdhtHandler;
        mBitdht = bitdht;
        mTargetNode = targetNode;
    }
}

bool Storage::writeFKSFile(char* data, int dataLen, char* filename,
                           unsigned int &filenameLen)
{
    // storage engine determines filename
    filenameLen = 24;
    memcpy(filename, "dht_filename_for_FKS.txt", filenameLen);
    filename[filenameLen] = '\0';
    return writeFile(data, dataLen, filename);
}

bool Storage::writeFile(char* data, int dataLen, char* filename)
{
    if(mUseDHT == true)
    {
        bdNodeId key;
        memcpy(key.data, filename, BITDHT_KEY_LEN);

        std::string value (data);

        // no secret for now, blank string
        std::string secret;

        return postDHTValue(*mTargetNode, key, value, secret);
    }
    return writeFileToDisk(data, dataLen, filename);
}

bool Storage::writeFileToDisk(char* data, int dataLen, char* filename)
{
    std::ofstream outfile;
    outfile.open(filename, std::ios_base::trunc);
    outfile.write(data, dataLen);
    outfile.close();
    return true;
}

bool Storage::writeMetadataFile(char* metadataBuf, const unsigned int metadataLen,
                                char* const filename, unsigned int &filenameLen)
{
    // storage engine determines filename
    filenameLen = 26;
    memcpy(filename, "password_auth_metadata.txt", filenameLen);
    filename[filenameLen] = '\0';
    return writeFile(metadataBuf, metadataLen, filename);
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
