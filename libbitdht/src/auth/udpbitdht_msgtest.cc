/*
 * bitdht/udpbitdht_nettest.cc
 *
 * BitDHT: An Flexible DHT library.
 *
 * Copyright 2010 by Robert Fernie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License Version 3 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 *
 * Please report all bugs and problems to "bitdht@lunamutt.com".
 *
 */


#include "udp/udpbitdht.h"
#include "udp/udpstack.h"
#include "bitdht/bdstddht.h"
#include "bitdht/bdmanager.h"
#include "bitdht/bdiface.h"
#include "bdHandler.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

/*******************************************************************
 * DHT test program.
 *
 * This should create two nodemanagers(?) which can send each other messages.
 * Wish me luck.
 */

#define MAX_MESSAGE_LEN 10240
#define DEF_PORT    7500
#define MIN_DEF_PORT    1001
#define MAX_DEF_PORT    16000
#define DEF_BOOTFILE    "localboot.txt"


bool findNode(BitDhtHandler &bitdhtHandler,
              UdpBitDht *udpBitDht,
              const std::string findPeerName,
              bdId &resultId)
{
    /* install search node */
    bdNodeId searchId;
    if (!bdStdLoadNodeId(&searchId, findPeerName))
    {
        std::cerr << "findNode(): Invalid findPeerName: " << findPeerName;
        return false;
    }

    std::cerr << "searching for Id: ";
    bdStdPrintNodeId(std::cerr, &searchId);
    std::cerr << std::endl;

    // bool BitDhtHandler::FindNode(UdpBitDht &udpBitDht, bdNodeId *peerId)
    bitdhtHandler.FindNode(udpBitDht, &searchId);

    // bdId resultId;
    uint32_t status;
    resultId.id = searchId;

    while(false == bitdhtHandler.SearchResult(&resultId, status))
    {
        sleep(10);
    }

    std::cerr << "findNode(): Found Result:" << std::endl;
    std::cerr << "\tId: ";
    bdStdPrintId(std::cerr, &resultId);
    std::cerr << std::endl;

    return true;
}

std::string getHash(BitDhtHandler &bitdhtHandler,
                    UdpBitDht *bitdht,
                    bdId &targetNode,
                    bdNodeId key)
{
    bitdht->getHash(targetNode, key);

    // check for results
    while(false == bitdhtHandler.m_gotHashResult)
    {
        sleep(10);
    }

    return bitdhtHandler.m_getHashValue;
}


bool postHash(BitDhtHandler &bitdhtHandler,
              UdpBitDht *bitdht,
              bdId &targetNode,
              bdNodeId key,
              std::string hash,
              std::string secret)
{
    bitdht->postHash(targetNode, key, hash, secret);

    // check for results
    while(false == bitdhtHandler.m_postHashGotResult)
    {
        sleep(10);
    }

    return bitdhtHandler.m_postHashSuccess;
}

int args(char *name)
{
    std::cerr << "Usage: " << name;
    std::cerr << " -p <port> ";
    std::cerr << " -b </path/to/bootfile> ";
    std::cerr << " -u <uid> ";
    std::cerr << " -q <num_queries>";
    std::cerr << " -r  (do dht restarts) ";
    std::cerr << " -j  (do join test) ";
    std::cerr << " -f do find_host before get_hash? <true|false>";
    std::cerr << " -t <target bdNodeId to perform find_host for, e.g., b8033e8acab57e170b612372727b38a60f28b76e>";
    std::cerr << std::endl;
    return 1;
}

int main(int argc, char **argv)
{
    int c;
    int port = DEF_PORT;
    std::string bootfile = DEF_BOOTFILE;
    std::string uid;
    bool setUid = false;
    bool doRandomQueries = false;
    bool doRestart = false;
    bool doThreadJoin = false;
    int noQueries = 0;
    bool doFindNode = false;
    std::string findPeerName;

    while((c = getopt(argc, argv,"rjfp:b:u:q:t:")) != -1)
    {
        switch (c)
        {
            case 'r':
                doRestart = true;
                break;
            case 'j':
                doThreadJoin = true;
                break;
            case 'p':
            {
                int tmp_port = atoi(optarg);
                if ((tmp_port > MIN_DEF_PORT) && (tmp_port < MAX_DEF_PORT))
                {
                    port = tmp_port;
                    std::cerr << "Port: " << port;
                    std::cerr << std::endl;
                }
                else
                {
                    std::cerr << "Invalid Port";
                    std::cerr << std::endl;
                    args(argv[0]);
                    return 1;
                }

            }
            break;
            case 'b':
            {
                bootfile = optarg;
                std::cerr << "Bootfile: " << bootfile;
                std::cerr << std::endl;
            }
            break;
            case 'u':
            {
                setUid = true;
                uid = optarg;
                std::cerr << "UID: " << uid;
                std::cerr << std::endl;
            }
            break;
            case 'q':
            {
                doRandomQueries = true;
                noQueries = atoi(optarg);
                std::cerr << "Doing Random Queries";
                std::cerr << std::endl;
            }
            break;
            case 'f':
            {
                doFindNode = true;
                std::cerr << "doFindNode: " << doFindNode << std::endl;
            }
            break;
            case 't':
            {
                findPeerName = optarg;
                std::cerr << "findPeerName: " << findPeerName;
                std::cerr << std::endl;
            }
            break;
            default:
            {
                std::cerr << "default = fail?" << std::endl;

                args(argv[0]);
                return 1;
            }
            break;
        }
    }
    if(findPeerName.length() == 0)
    {
        args(argv[0]);
        return 1;
    }


    bdDhtFunctions *fns = new bdStdDht();

    bdNodeId id;
    /* start off with a random id! */
    bdStdRandomNodeId(&id);
    if (setUid)
    {
        int len = uid.size();
        if (len > 20)
        {
            len = 20;
        }

        for(int i = 0; i < len; i++)
        {
            id.data[i] = uid[i];
        }
    }
    std::cerr << "Using NodeId: ";
    fns->bdPrintNodeId(std::cerr, &id);
    std::cerr << std::endl;

    // bdHashSpace test
    {
        // write an entry to the hash space
        uint32_t modFlags = BITDHT_HASH_ENTRY_ADD;
        std::string strKey("key");
        std::string strValue("value");
        std::string strSecret("secret");
        time_t lifetime = 0;
        time_t store = 0;

        bdHashSpace testHashSpace;
        bdHashEntry entry(strValue, strSecret, lifetime, store);

        testHashSpace.modify(&id, strKey, &entry, modFlags);

        testHashSpace.printHashSpace(std::cerr);

        // now find the entry using key lookup
        std::list<bdHashEntry> foundEntries;
        testHashSpace.search(&id, strKey, 0x7FFFFFFF, foundEntries);

        std::list<bdHashEntry>::iterator it;
        for(it = foundEntries.begin(); it != foundEntries.end(); it++)
        {
            assert(it->mValue == strValue);
            // std::cerr << "Found hash:";
            // std::cerr << it->mValue << std::endl;
        }
    }

    /* setup the udp port */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = 0;
    local.sin_port = htons(port);

    UdpStack *udpstack = new UdpStack(local);

    /* create bitdht component */
    // 99 is the application version number
    std::string dhtVersion = "db99ST";
    UdpBitDht *bitdht = new UdpBitDht(udpstack, &id, dhtVersion,
                                      bootfile, fns);

    /* add in the stack */
    udpstack->addReceiver(bitdht);


    // make our callback handler class (which also makes the query)
    BitDhtHandler bitdhtHandler;
    /* register callback display */
    // BitDhtHandler *bitDhtHandler = new BitDhtHandler();
    bitdht->addCallback(&bitdhtHandler);

    /* startup threads */
    //udpstack->start();
    bitdht->start();


    /* setup best mode for quick search */
    uint32_t dhtFlags = BITDHT_MODE_TRAFFIC_HIGH | BITDHT_MODE_RELAYSERVERS_IGNORED;
    bitdht->setDhtMode(dhtFlags);
    bitdht->setAttachMode(false);


    int count = 0;
    int running = 1;

    std::cerr << "Starting Dht: ";
    std::cerr << std::endl;
    bitdht->startDht();

    if (doRandomQueries)
    {
        for(int i = 0; i < noQueries; i++)
        {
            bdNodeId rndId;
            bdStdRandomNodeId(&rndId);

            std::cerr << "BitDht Launching Random Search: ";
            bdStdPrintNodeId(std::cerr, &rndId);
            std::cerr << std::endl;

            bitdht->addFindNode(&rndId, BITDHT_QFLAGS_DO_IDLE);
        }
    }

    bool foundNode = false;
    bool sentGetHash = false;
    bool sentPostHash = false;
    while(1)
    {
        sleep(10);

        std::cerr << "BitDht State: ";
        std::cerr << bitdht->stateDht();
        std::cerr << std::endl;
        if(bitdht->stateDht() == BITDHT_MGR_STATE_ACTIVE)
        {

            std::cerr << "BITDHT_MGR_STATE_ACTIVE" << std::endl;
            bitdht->printDht();

            bdId resultId;
            if(doFindNode && foundNode == false)
            {
                findNode(bitdhtHandler, bitdht, findPeerName, resultId);

                std::cerr << "bdSingleShotFindPeer(): Found Result:" << std::endl;
                std::cerr << "\tId: ";
                bdStdPrintId(std::cerr, &resultId);
                std::cerr << std::endl;
                std::cerr << "Answer: ";
                std::cerr << std::endl;
                std::cerr << "\tPeer IpAddress: " << bdnet_inet_ntoa(resultId.addr.sin_addr);
                std::cerr << std::endl;
                std::cerr << "\tPeer Port: " << ntohs(resultId.addr.sin_port);
                std::cerr << std::endl;

                foundNode = true;
            }

            // post_hash
            if(!sentPostHash)
            {
                bdId targetNode;
                if(!doFindNode)
                {
                    bdNodeId targetID;
                    memcpy(targetID.data, findPeerName.data(), BITDHT_KEY_LEN);
                    struct sockaddr_in target_addr;
                    memset(&target_addr, 0, sizeof(target_addr));
                    target_addr.sin_family = AF_INET;
                    char *ip = {"127.0.0.1"};
                    target_addr.sin_addr.s_addr = inet_addr(ip);
                    target_addr.sin_port = htons(3074);
                    bdId hardTargetNode(targetID, target_addr);
                    targetNode = hardTargetNode;
                }
                else
                {
                    // If we've done the find_node request, then use it's
                    // result as the targetNode.
                    targetNode = resultId;
                }

                bdNodeId key;
                memcpy(key.data, "test key", 8);
                std::string value = "I AM A HASH VALUE";
                std::string secret = "i am a secret";
                // When this finishes, the hash will be present in:
                // bitdhtHandler.m_getHashValue.

                // bool postHash(BitDhtHandler &bitdhtHandler,
                //               UdpBitDht *bitdht,
                //               bdId &targetNode,
                //               bdNodeId key,
                //               std::string value,
                //               std::string secret)
                // bitdhtHandler.m_postHashSuccess;

                postHash(bitdhtHandler, bitdht, targetNode, key, value, secret);
                sentPostHash = true;
            }

            // get_hash
            if(!sentGetHash)
            {
                bdId targetNode;
                if(!doFindNode)
                {
                    bdNodeId targetID;
                    memcpy(targetID.data, findPeerName.data(), BITDHT_KEY_LEN);
                    struct sockaddr_in target_addr;
                    memset(&target_addr, 0, sizeof(target_addr));
                    target_addr.sin_family = AF_INET;
                    char *ip = {"127.0.0.1"};
                    target_addr.sin_addr.s_addr = inet_addr(ip);
                    target_addr.sin_port = htons(3074);
                    bdId hardTargetNode(targetID, target_addr);
                    targetNode = hardTargetNode;
                }
                else
                {
                    // If we've done the find_node request, then use it's
                    // result as the targetNode.
                    targetNode = resultId;
                }

                bdNodeId key;
                memcpy(key.data, "test key", 8);
                // When this finishes, the hash will be present in:
                // bitdhtHandler.m_getHashValue.
                std::string hash = getHash(bitdhtHandler, bitdht,
                                           targetNode, key);
                sentGetHash = true;
            }

        }

        std::cerr << "Dht Network Size: ";
        std::cerr << bitdht->statsNetworkSize();
        std::cerr << std::endl;

        std::cerr << "BitDht Network Size: ";
        std::cerr << bitdht->statsBDVersionSize();
        std::cerr << std::endl;


        if (doThreadJoin)
        {
            /* change address */
            if (count % 2 == 0)
            {
                std::cerr << "Resetting UdpStack: ";
                std::cerr << std::endl;

                udpstack->resetAddress(local);
            }
        }
        if (doRestart)
        {
            if (count % 2 == 1)
            {
                if (running)
                {
                    std::cerr << "Stopping Dht: ";
                    std::cerr << std::endl;

                    bitdht->stopDht();
                    running = 0;
                }
                else
                {
                    std::cerr << "Starting Dht: ";
                    std::cerr << std::endl;

                    bitdht->startDht();
                    running = 1;
                }
            }
        }
    }

    return 1;
}
