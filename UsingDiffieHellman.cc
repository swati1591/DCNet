#include <iostream>
#include <exception>
#include "bits/basic_string.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/uan-helper.h"
#include "ns3/uan-prop-model-ideal.h"
#include "ns3/uan-channel.h"
#include "ns3/uan-mac-cw.h"
#include "ns3/uan-phy-gen.h"
#include "ns3/uan-transducer-hd.h"
#include "ns3/object.h"
#include "ns3/constant-position-mobility-model.h"
#include "ns3/uan-noise-model-default.h"
#include "ns3/nstime.h"
#include "ns3/command-line.h"
#include "crypto++/aes.h" 
#include "crypto++/modes.h"
#include "crypto++/integer.h"


using namespace ns3;
using namespace CryptoPP;
using namespace std;
using std::cout;
using std::cerr;
using std::endl;
#include <string>
using std::string;
#include <stdexcept>
using std::runtime_error;

#include "crypto++/osrng.h"
using CryptoPP::AutoSeededRandomPool;


#include "crypto++/nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "crypto++/dh.h"
using CryptoPP::DH;

#include "crypto++/secblock.h"
using CryptoPP::SecByteBlock;

#include <crypto++/hex.h>
using CryptoPP::HexEncoder;

#include <crypto++/filters.h>
using CryptoPP::StringSink;


class Experiment{

public:

    NodeContainer m_nodes;
    NetDeviceContainer devices;
    double hello_send_time, hello_rec_time, ack_send_time, ack_rec_time, total_time;
    Vector send_hello_pos, rec_hello_pos, send_ack_pos, rec_ack_pos;

    static int i;

    UanAddress neighbor[], first_neighbor_subset[];
    double m_procDelay;


    Experiment(){
        m_nodes.Create(6);
        UanHelper helper;
           helper.SetMac ("ns3::UanMacCw");
        helper.SetPhy("ns3::UanPhyGen");
        helper.SetTransducer("ns3::UanTransducerHd");
        Ptr<UanPropModelIdeal> prop = CreateObjectWithAttributes<UanPropModelIdeal> ();
        Ptr<UanNoiseModelDefault> noise = CreateObjectWithAttributes<UanNoiseModelDefault> ();
        Ptr<UanChannel> channel = CreateObject<UanChannel>();
        channel->SetPropagationModel(prop);
        channel->SetNoiseModel(noise);
        devices = helper.Install(m_nodes,channel);

        devices.Get(0)->SetReceiveCallback(MakeCallback(&Experiment::receiveAck, this));

    }

    /*
     * \brief receive the broadcasted hello packet
     *
     * \param device who received hello
     *
     * \param packet packet send
     *
     * \param protocol protocol in use
     *
     * \param address sender of the packet
     */
    bool receiveHello(Ptr<NetDevice> device, Ptr<const Packet> packet,uint16_t protocol, const Address& address) {

            hello_rec_time = Simulator::Now().GetSeconds();

            std::cout << "In receiveHello: Hello packet received at node: " << device->GetNode()->GetId() << " at time " << hello_rec_time << std::endl;

            Ptr<MobilityModel> mob2 = device->GetNode()->GetObject<MobilityModel>();
            rec_hello_pos = mob2->GetPosition ();

            m_procDelay = hello_rec_time + MilliSeconds(10.0).ToDouble(Time::S);            //added processing delay
            Simulator::Schedule (Seconds(m_procDelay), &Experiment::sendAck, this, device, address);

            return true;
        }

    /*
     * \brief if hello message is received then send the ack
     *
     * \param device who received hello
     *
     * \param address who send hello
     *
     */
    bool sendAck (Ptr<NetDevice> device, const Address& address)
        {
            Ptr<Packet> ack = Create<Packet>();
            Ptr<MobilityModel> mob3 = device->GetNode()->GetObject<MobilityModel>();
            send_ack_pos = mob3->GetPosition ();
            ack_send_time = Simulator::Now().GetSeconds();

            std::cout << "In sendAck: Ack packet send at time: " << ack_send_time
                      << " from node " << device->GetNode()->GetId() << " to node " << address << std::endl;

            device->Send(ack, address, 0);

            return true;
        }

    /*
     * \brief receive the ack packet
     *
     * \param device who received ack
     *
     * \param packet packet send
     *
     * \param protocol protocol in use
     *
     * \param address sender of the packet
     */
    bool receiveAck(Ptr<NetDevice> device, Ptr<const Packet> packet,uint16_t protocol, const Address& address) {

            std::cout << "Now entering function ReceiveAck" << std::endl;

            ack_rec_time = Simulator::Now().GetSeconds();
            std::cout << "In receiveAck: Ack packet received at: " << ack_rec_time << std::endl;

            Ptr<MobilityModel> mob4 = device->GetNode()->GetObject<MobilityModel>();
            rec_ack_pos = mob4->GetPosition ();
            UanAddress addr=UanAddress::ConvertFrom(address);
            std::cout << "ACK received at node " << device->GetNode()->GetId() << " from " << address << std::endl;
            neighbor[i] = addr;

            i++;
            std::cout << "Now exiting function wela::ReceiveAck" << std::endl;

            return true;
        }


    /*
     * \brief broadcast a hello packet to the first hop neighbours
     */
    void broadcast(){

        double x=1, y=1;
        uint32_t n=1, m=0;

        for(NetDeviceContainer::Iterator i = devices.Begin(); i != (devices.End() - 1); i++, n++) {    //skipped the 1st device, that is source
        devices.Get(n)->SetReceiveCallback(MakeCallback(&Experiment::receiveHello, this));
        }

        for(NetDeviceContainer::Iterator i = devices.Begin(); i != devices.End(); i++) {
            Ptr<ConstantPositionMobilityModel> mobility = CreateObject<ConstantPositionMobilityModel>();
            Vector v(x,y,1);
            mobility->SetPosition(v);
            m_nodes.Get(m)->AggregateObject(mobility);
            x++; y++; m++;
        }
        Ptr<Packet> hello = Create<Packet>();
        Ptr<MobilityModel> mob1 = m_nodes.Get(0)->GetObject<MobilityModel>();
        send_hello_pos = mob1->GetPosition ();
        hello_send_time = Simulator::Now().GetSeconds();
        std::cout << "In Broadcast: Hello packet send at time: " << hello_send_time << std::endl;


        m_nodes.Get(0)->GetDevice(0)->Send(hello, m_nodes.Get(0)->GetDevice(0)->GetBroadcast(), 0);

    }


int dh_agree()
{
	try
	{
		// RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
		// http://tools.ietf.org/html/rfc5114#section-2.1
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

		// Schnorr Group primes are of the form p = rq + 1, p and q prime. They
		// provide a subgroup order. In the case of 1024-bit MODP Group, the
		// security level is 80 bits (based on the 160-bit prime order subgroup).		

		// For a compare/contrast of using the maximum security level, see
		// dh-agree.zip. Also see http://www.cryptopp.com/wiki/Diffie-Hellman
		// and http://www.cryptopp.com/wiki/Security_level .

		DH dhA, dhB;
		AutoSeededRandomPool rndA, rndB;

		dhA.AccessGroupParameters().Initialize(p, q, g);
		dhB.AccessGroupParameters().Initialize(p, q, g);

		if(!dhA.GetGroupParameters().ValidateGroup(rndA, 3) ||
		   !dhB.GetGroupParameters().ValidateGroup(rndB, 3))
			throw runtime_error("Failed to validate prime and generator");

		size_t count = 0;

		p = dhA.GetGroupParameters().GetModulus();
		q = dhA.GetGroupParameters().GetSubgroupOrder();
		g = dhA.GetGroupParameters().GetGenerator();

		// http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
		Integer v = ModularExponentiation(g, q, p);
		if(v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");

		//////////////////////////////////////////////////////////////

		SecByteBlock privA(dhA.PrivateKeyLength());
		SecByteBlock pubA(dhA.PublicKeyLength());
		dhA.GenerateKeyPair(rndA, privA, pubA);

		SecByteBlock privB(dhB.PrivateKeyLength());
		SecByteBlock pubB(dhB.PublicKeyLength());
		dhB.GenerateKeyPair(rndB, privB, pubB);

		//////////////////////////////////////////////////////////////

		if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
			throw runtime_error("Shared secret size mismatch");

		SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

		if(!dhA.Agree(sharedA, privA, pubB))
			throw runtime_error("Failed to reach shared secret (1A)");

		if(!dhB.Agree(sharedB, privB, pubA))
			throw runtime_error("Failed to reach shared secret (B)");

		count = std::min(dhA.AgreedValueLength(), dhB.AgreedValueLength());
		if(!count || 0 != memcmp(sharedA.BytePtr(), sharedB.BytePtr(), count))
			throw runtime_error("Failed to reach shared secret");

		//////////////////////////////////////////////////////////////

		Integer a, b;

		a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
		cout << "Shared secret (A): " << std::hex << a << endl;

		b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
		cout << "Shared secret (B): " << std::hex << b << endl;
	}

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(const std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}
return 0;
}
};

int Experiment::i;
int main(int argc, char * argv[]){

    std::cout<<"In Experiment::main"<<std::endl;
  CryptoPP::Integer i(10L);

  cout << "i: " << i << endl;
    Experiment exp;
    //exp.broadcast();
	exp.dh_agree();
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
