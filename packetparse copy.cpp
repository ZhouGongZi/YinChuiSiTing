#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
using namespace std;

static int numTCP = 0;
static int numUDP = 0;
static int numOther = 0;


/*         
=> metaInfo:init_numPk, resp_numPk,  
            init_numBt, resp_numBt, init_Dup, resp_Dup, 
            closed 
*/
static int connNum = 1;


unordered_map<string, vector<int> > metaInfo;
//(init + resp + connNum) => (meta information)

unordered_map<string, map<int, pair<bool, string> > > init;
unordered_map<string, map<int, pair<bool, string> > > resp;
//(init + resp + connNum) => (seq -> (ACKed, payload))

unordered_map<string, int> curSession;
//






struct tcp_pseudo /*the tcp pseudo header*/
{
   uint32_t src_addr;
   uint32_t dst_addr;
   uint8_t zero;
   uint8_t proto;
   uint16_t length;
};

uint16_t getChecksum (const uint16_t * addr, unsigned len, uint16_t cm) {
   int sum;
   const uint16_t * word;
   sum = (int) cm;
   word = addr;
   while (len >= 2) {
      sum += *(word++);
      len -= 2;
   }
   if (len > 0) {
      uint16_t tmp;
      *(uint8_t *)(&tmp) = *(uint8_t *)word;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   return ((uint16_t)~sum);
}

string getMacAdress(const struct ether_header * etherHead, string type){
   char * s_addr = 0;
   struct ether_addr Ad;
   if(type == "source") memcpy(&Ad, etherHead -> ether_shost, sizeof(Ad));
   else if(type == "dest") memcpy(&Ad, etherHead -> ether_dhost, sizeof(Ad));
   else cerr << "type error: source / dest" << endl;
   s_addr = ether_ntoa(&Ad);
   string s_address = string(s_addr);
   return s_address;
}

void handler_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
   const struct ether_header* etherHead;
   const struct ip* ipHead;
   const struct tcphdr* tcpHead;
   const struct udphdr* udpHead;
   char sourceIp[INET_ADDRSTRLEN];
   char destIp[INET_ADDRSTRLEN];
   u_int sourcePort, destPort;
   u_char *payload = 0;
   int Length = 0;
   string dataStr = "";
   cout << "======= Packet " << numTCP + numUDP + numOther << " Information =======" << endl;

   string s_address = getMacAdress(etherHead, "source");
   string d_address = getMacAdress(etherHead, "dest");

   etherHead = (struct ether_header*) packet;
   if(ntohs(etherHead -> ether_type) == ETHERTYPE_IP){
      //cout << "entering IP" << endl;
      ipHead = (struct ip*)(packet + sizeof(struct ether_header));
      inet_ntop(AF_INET, &(ipHead->ip_src), sourceIp, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ipHead->ip_dst), destIp, INET_ADDRSTRLEN);
      if(ipHead -> ip_p == IPPROTO_TCP){
         numTCP ++;
         tcpHead = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
         sourcePort = ntohs(tcpHead->th_sport);
         destPort = ntohs(tcpHead->th_dport);
         payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
         //Length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
         unsigned ipPayLen = ntohs(ipHead -> ip_len) - 4 * (ipHead -> ip_hl);
         Length = ipPayLen - 4 * (int(tcpHead -> th_off));

         
         for(int i = 0; i < Length; i++) {
            if((payload[i] >= 32 && payload[i] <= 126) || payload[i] == 10 || payload[i] == 11 || payload[i] == 13) {
               dataStr += (char)payload[i];
            }else {
               dataStr += ".";
            }
         }

         cout << "Packet Type: TCP" << endl;
         cout << "Source MAC address: " << s_address << endl;
         cout << "Destination MAC address: " << d_address << endl;
         cout << "Source IP address and port: " << sourceIp << ":"<< sourcePort << endl;
         cout << "Dest IP address and port: " << destIp << ":"<< destPort << endl;
         cout << "TCP checksum: " << ntohs(tcpHead -> th_sum) << endl;

         /* ======= calculate the TCP checksum ======= */

         struct tcp_pseudo ps;
         ps.src_addr = ipHead -> ip_src.s_addr;
         ps.dst_addr = ipHead -> ip_dst.s_addr;
         ps.zero = 0;
         ps.proto = IPPROTO_TCP;
         ps.length = htons(ipPayLen);
         uint16_t summa = getChecksum((unsigned short*) &ps, (unsigned)sizeof(ps), 0);
         summa = getChecksum((unsigned short*)tcpHead, ipPayLen, (unsigned short) (~summa));

         if(summa == 0) cout << "the TCP checksum valid" << endl;
         else cout << "the TCP checksum invalid" << endl;


         /* ======= fininshd calculation ======= */
         cout << "payload size is: " << pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)) << endl;
         cout << "another calculation for payload: " << Length << endl;
         if (Length > 0) {
            cout << dataStr << endl;
         }
         bool hasTT = *args;
         cout << "The tcp connection analyze: " << endl;
         cout << "-------------------------------" << endl;
         if(hasTT){

            cout << "th_seq: " << ntohl(tcpHead -> th_seq) << endl;
            cout << "th_ack: " << ntohl(tcpHead -> th_ack) << endl;
            cout << "th_flag FIN: " << ((tcpHead -> th_flags) & 0x01) << endl;
            cout << "th_flag ACK: " << ((tcpHead -> th_flags) & 0x10)<< endl;
            cout << "th_flag SYN: " << ((tcpHead -> th_flags) & 0x02) << endl;
            cout << "th_win: " << ntohs(tcpHead -> th_win) << endl;
            cout << "th_urp: " << ntohs(tcpHead -> th_urp) << endl;
            
            unsigned long th_seq = ntohl(tcpHead -> th_seq);
            unsigned long th_ack = ntohl(tcpHead -> th_ack);
            string InitStr = s_address + to_string(sourcePort);
            string respStr = d_address + to_string(destPort);
            int packetSize = int(pkthdr->len);


            cout << "oackey size is ddd : " << (pkthdr -> len) << endl;
            cout << "oackey size is isi : " << packetSize << endl;

 
            /* ======== Medadata ========= */


            if(((tcpHead -> th_flags) & 0x02)){
               //starts a connection
            }

         }

      }
      else if(ipHead -> ip_p == IPPROTO_UDP){
         numUDP ++;
         udpHead = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
         sourcePort = ntohs(udpHead->uh_sport);
         destPort = ntohs(udpHead->uh_dport);
         payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
         Length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

         
         for(int i = 0; i < Length; i++) {
            if((payload[i] >= 32 && payload[i] <= 126) || payload[i] == 10 || payload[i] == 11 || payload[i] == 13) {
               dataStr += (char)payload[i];
            }else {
               dataStr += " ";
            }
         }

         cout << "Packet Type: UDP" << endl;
         cout << "Source MAC address: " << s_address << endl;
         cout << "Dest MAC address: " << d_address << endl;
         cout << "Source IP address and port: " << sourceIp << ":"<< sourcePort << endl;
         cout << "Dest IP address and port: " << destIp << ":"<< destPort << endl;
         cout << "payload size is: " << Length << endl;
         if (Length > 0) {
            cout << dataStr << endl;
         }
      }
      else{
         numOther ++;
         cout << "Packet Type: Other" << endl;
         cout << "Source MAC address: " << s_address << endl;
         cout << "Dest MAC address: " << d_address << endl;
         cout << "Source IP address and port: " << sourceIp << ":"<< sourcePort << endl;
         cout << "Dest IP address and port: " << destIp << ":"<< destPort << endl;
         cout << "payload size is: " << ipHead -> ip_len - sizeof(struct ip) << endl;

      }
   }
   else {
      cout << "Not an ip packet" << endl;
      cout << "Source MAC address: " << s_address << endl;
      cout << "Dest MAC address: " << d_address << endl;
      //cout << "payload size is: " << ipHead -> ip_len - sizeof(struct ip) << endl;
   }
   cout << endl;
   cout << endl;

}

int main(int argc, char *argv[]){

   bool hasT = 0;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *pf;
   struct bpf_program fp;
   char select_mail[] = ""; 
   /* char select_mail[] = "port 80"; */
   struct pcap_pkthdr h;
   const u_char *p;

   for(int i=0; i<argc; ++i){
      if(strcmp(argv[i], "-t\0") == 0){
         hasT = 1;
      }
   }

   if((argc != 2 && !hasT) || (argc != 3 && hasT)){
      fprintf( stderr, "Usage: %s {pcap-file}\n", argv[0] );
      return 2;
   }

   if( (pf = pcap_open_offline( argv[1], errbuf )) == NULL ){
      fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
      return 2;
   }

   bool* arg = &hasT;
   if(pcap_loop(pf, 0, handler_callback, (u_char*) arg) < 0){
      fprintf( stderr, "pcap_loop cannot excute");
      return 2;
   }

   cout << "======= meta information =======" << endl; 
   cout << "Number of TCP packets: " << numTCP << endl;
   cout << "Number of UDP packets: " << numUDP << endl;
   cout << "Number of Other packets: " << numOther << endl;
   cout << "Number of Total packets: " << numTCP + numUDP + numOther << endl;
   return 0;
}




