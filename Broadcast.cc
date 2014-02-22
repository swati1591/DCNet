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
};


int Experiment::i;
int main(int argc, char * argv[]){

    std::cout<<"In Experiment::main"<<std::endl;
  CryptoPP::Integer i(10L);

  cout << "i: " << i << endl;
    Experiment exp;
    exp.broadcast();
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
