#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "MyTag.h"
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "crypto++/aes.h" 
#include "crypto++/sha.h"
#include "crypto++/modes.h"
#include "crypto++/integer.h"
#include "crypto++/osrng.h"
#include "crypto++/nbtheory.h"
#include <stdexcept>
#include "crypto++/dh.h"
#include "crypto++/secblock.h"
#include <crypto++/hex.h>
#include <crypto++/filters.h>
#include <map>
#include <sstream>
#include <iomanip>

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::ModularExponentiation;
using std::runtime_error;
using CryptoPP::DH;
using CryptoPP::SecByteBlock;
using CryptoPP::StringSink;
using CryptoPP::HexEncoder;
using std::map;
using std::pair;
using namespace ns3;
using namespace CryptoPP;

Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
		"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
		"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
		"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
		"DF1FB2BC2E4A4371");

Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
		"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
		"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
		"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
		"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
		"855E6EEB22B3B2E5");

Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

TypeId tid;
Ipv4InterfaceContainer i;
NodeContainer c;

int rounds = 0;
int MessageLength = 0;
double waitTime = 0;
std::stringstream sharedMessage;
int sender = 0;
std::string Message = "1011111";
std::string phyMode ("DsssRate1Mbps");
double distance = 500;  // m
uint32_t packetSize = 1000; // bytes
uint32_t numPackets = 20;
int numNodes = 3;  // by default, 5x5
uint32_t sinkNode = 0;
uint32_t sourceNode = 2;
double interval = 1.0; // seconds
double keyExchangeInterval = 5.0; // seconds
bool verbose = false;
bool tracing = true;
int messageLen=0;	

int aesKeyLength = SHA256::DIGESTSIZE;
AutoSeededRandomPool rnd;
byte iv[AES::BLOCKSIZE];	
SecByteBlock key(SHA256::DIGESTSIZE);
static std::string msgs[20];

class ApplicationUtil
{	
private:
 static bool instanceFlag;
int dhAgreedLength;
static ApplicationUtil *appUtil;
ApplicationUtil()
{
 //private constructor
}

	map<int,SecByteBlock> publicKeyMap;
	map<int,SecByteBlock> privateKeyMap;
	map<int,SecByteBlock> dhSecretKeyMapSub;
	map<int,map<int,SecByteBlock> > dhSecretKeyMapGlobal;
	map<int,int> dhSecretBitMapSub;
	map<int,map<int,int> > dhSecretBitMapGlobal;
	map<Ptr<Node>,int> nodeMap;
public:
	//static int publicKeyPairCount;
	int getDhAgreedLength()
	{
		return dhAgreedLength;
	}	
	void setDhAgreedLength(int len)
	{
		dhAgreedLength = len;
	}
	SecByteBlock getPublicKeyFromMap(int nodeId);
	void putPublicKeyInMap(int nodeId, SecByteBlock key);
	SecByteBlock getPrivateKeyFromMap(int nodeId);
	void putPrivateKeyInMap(int nodeId, SecByteBlock key);
	SecByteBlock getSecretKeyFromGlobalMap(int nodeId,int destNodeId);
	void putSecretKeyInGlobalMap(int nodeId, int destNodeId, SecByteBlock key);

	int getSecretBitFromGlobalMap(int nodeId,int destNodeId);
	void putSecretBitInGlobalMap(int nodeId, int destNodeId, int value);
	map<int,int> getSecretBitSubMap(int nodeId);

	void putNodeInMap(Ptr<Node> node,int index);
	int getNodeFromMap(Ptr<Node> node);
	static ApplicationUtil* getInstance();	

        ~ApplicationUtil()
        {
	  instanceFlag = false;
        }
};
bool ApplicationUtil::instanceFlag = false;
ApplicationUtil* ApplicationUtil::appUtil = NULL;

ApplicationUtil* ApplicationUtil::getInstance()
{
	if(!instanceFlag)
        {		
		//publicKeyPairCount = 0;
		appUtil = new ApplicationUtil();
		instanceFlag = true;
	}
        return appUtil;
    
}		
void ApplicationUtil::putNodeInMap(Ptr<Node> node,int index)
{
	nodeMap.insert(pair<Ptr<Node>,int>(node,index));
}

int ApplicationUtil::getNodeFromMap(Ptr<Node> node)
{
	map<Ptr<Node>,int>::iterator p;
	p = nodeMap.find(node);
	if(p != nodeMap.end())
		return p->second;
	else 
		return -1;	
}
SecByteBlock ApplicationUtil::getPublicKeyFromMap(int nodeId)
{
	map<int,SecByteBlock>::iterator p;
	p = publicKeyMap.find(nodeId);
	if(p != publicKeyMap.end())
		return p->second;
	else 
		return SecByteBlock(0);
}

void ApplicationUtil::putPublicKeyInMap(int nodeId, SecByteBlock key)
{
	publicKeyMap.insert(pair<int,SecByteBlock>(nodeId,key));
}

SecByteBlock ApplicationUtil::getPrivateKeyFromMap(int nodeId)
{
	map<int,SecByteBlock>::iterator p;
	p = privateKeyMap.find(nodeId);
	if(p != privateKeyMap.end())
		return p->second;
	else 
		return SecByteBlock(0);
}

void ApplicationUtil::putPrivateKeyInMap(int nodeId, SecByteBlock key)
{
	privateKeyMap.insert(pair<int,SecByteBlock>(nodeId,key));
}	

SecByteBlock ApplicationUtil::getSecretKeyFromGlobalMap(int nodeId, int destNodeId)
{

	map<int,map<int,SecByteBlock> >::iterator p;
	p = dhSecretKeyMapGlobal.find(nodeId);

	if(p != dhSecretKeyMapGlobal.end())
	{
		map<int,SecByteBlock>::iterator p1;
		p1 = p->second.find(destNodeId);
		if(p1 != dhSecretKeyMapSub.end())
			return p1->second;
		else 
		{
			std::cout<<"hello";
			return SecByteBlock(0);
		}
	}
	else 
		{
			std::cout<<"hello1";
			return SecByteBlock(0);
		}	
}

void ApplicationUtil::putSecretKeyInGlobalMap(int nodeId, int destNodeId, SecByteBlock key)
{

	map<int,map<int,SecByteBlock> >::iterator p;
	p = dhSecretKeyMapGlobal.find(nodeId);
	if(p != dhSecretKeyMapGlobal.end())
	{
		p->second.insert(pair<int,SecByteBlock>(destNodeId,key));

	}
	else
	{	
		map<int,SecByteBlock> tempMap;	
		tempMap.insert(pair<int,SecByteBlock>(destNodeId,key));
		dhSecretKeyMapGlobal.insert(pair<int,map<int,SecByteBlock> >(nodeId,tempMap));
	}	

}	

int ApplicationUtil::getSecretBitFromGlobalMap(int nodeId, int destNodeId)
{

	map<int,map<int,int> >::iterator p;
	p = dhSecretBitMapGlobal.find(nodeId);

	if(p != dhSecretBitMapGlobal.end())
	{
		map<int,int>::iterator p1;
		p1 = p->second.find(destNodeId);
		if(p1 != dhSecretBitMapSub.end())
			return p1->second;
		else 
		{
			std::cout<<"hello";
			return -99;
		}
	}
	else 
		{
			std::cout<<"hello1";
			return -99;
		}	
}

void ApplicationUtil::putSecretBitInGlobalMap(int nodeId, int destNodeId, int value)
{

	map<int,map<int,int> >::iterator p;
	p = dhSecretBitMapGlobal.find(nodeId);
	if(p != dhSecretBitMapGlobal.end())
	{
		p->second.insert(pair<int,int>(destNodeId,value));

	}
	else
	{	
		map<int,int> tempMap;	
		tempMap.insert(pair<int,int>(destNodeId,value));
		dhSecretBitMapGlobal.insert(pair<int,map<int,int> >(nodeId,tempMap));
	}	

}					

map<int,int> ApplicationUtil::getSecretBitSubMap(int nodeId)
{
	map<int,map<int,int> >::iterator p;
	p = dhSecretBitMapGlobal.find(nodeId);

	return p->second;
}
