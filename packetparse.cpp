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
#include <sstream>
using namespace std;

static int numTCP = 0;
static int numUDP = 0;
static int numOther = 0;

static int connNum = 1;
/*         
=> metaInfo:init_numPk, resp_numPk,  
            init_numBt, resp_numBt, 
            init_Dup, resp_Dup: need to be initialize later 
            
            closed: if == 2 then closed
*/
unordered_map<string, vector<int> > metaInfo;
//(init + resp + connNum) => (meta information)

unordered_map<string, map<unsigned long, pair<unsigned long, string> > > init;
unordered_map<string, map<unsigned long, pair<unsigned long, string> > > resp;
//(init + resp + connNum) => (seq -> (ACKed number(size + seq), 0, if acked; payload))

unordered_map<string, unordered_set<unsigned long> > init_packetACK;
unordered_map<string, unordered_set<unsigned long> > resp_packetACK;
//used to detect how many dup, if already in, then +1 to metaInfo

//(init + resp + connNum) => (seq, ack)
// ------------------------(seq, ack means the ack it need, ie: ack + size)

unordered_map<string, int> curSession;
//use for knowing which session it is currently in
//also can know whether some 

int sameSession(string s1, string s2){
   if(s1 == s2) return 1;
   string s11 = "";
   string s12 = "";
   string s13 = "";
   string s21 = "";
   string s22 = "";
   string s23 = "";
   stringstream istr1(s1);
   stringstream istr2(s2);
   getline(istr1, s11, '#');
   getline(istr1, s12, '#');
   getline(istr1, s13, '#');
   getline(istr2, s21, '#');
   getline(istr2, s22, '#');
   getline(istr2, s23, '#');
   if(s12 == s21 && s11 == s22 && s13 == s23) return 2;
   return 0;
}

string convertToInitResp(string ss){
   //convert the resp_init string to init_resp form
   string s11 = "";
   string s12 = "";
   string s13 = "";
   stringstream istr1(ss); 
   getline(istr1, s11, '#');
   getline(istr1, s12, '#');
   getline(istr1, s13, '#');
   return (s12 + "#" + s11 + "#" + s13);

}

struct tcp_pseudo 
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
   char * s_addr = NULL;
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
   u_int sourcePort = 0;
   u_int destPort = 0;
   u_char *payload = NULL;
   int Length = 0;
   string dataStr = "";
   cout << "======= Packet " << numTCP + numUDP + numOther + 1 << " Information =======" << endl;

   etherHead = (struct ether_header*) packet;
   string s_address = getMacAdress(etherHead, "source");
   string d_address = getMacAdress(etherHead, "dest");

   if(ntohs(etherHead -> ether_type) == ETHERTYPE_IP){
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
         cout << "payload size is: " << Length << endl;
         if (Length > 0) {
            //cout << dataStr << endl;
         }
         bool hasTT = *args;
         cout << "The tcp connection analyze: " << endl;
         cout << "-------------------------------" << endl;
         if(hasTT){

            cout << "th_seq: " << ntohl(tcpHead -> th_seq) << endl;
            cout << "th_ack: " << ntohl(tcpHead -> th_ack) << endl;
            cout << "th_flag FIN: " << ((tcpHead -> th_flags) & 0x01) << endl;
            cout << "th_flag ACK: " << ((tcpHead -> th_flags) & 0x10) << endl;
            cout << "th_flag SYN: " << ((tcpHead -> th_flags) & 0x02) << endl;
            cout << "th_flag RST: " << ((tcpHead -> th_flags) & 0x04) << endl;
            cout << "th_flag PUSH: " << ((tcpHead -> th_flags) & 0x08) << endl;
            cout << "th_flag ECE: " << ((tcpHead -> th_flags) & 0x40) << endl;

            //cout << "th_win: " << ntohs(tcpHead -> th_win) << endl;
            //cout << "th_urp: " << ntohs(tcpHead -> th_urp) << endl;

            unsigned long th_seq = ntohl(tcpHead -> th_seq);
            unsigned long th_ack = ntohl(tcpHead -> th_ack);
            string srcStr = string(sourceIp) + ":" + to_string(sourcePort);
            string destStr = string(destIp) + ":" + to_string(destPort);
            int packetSize = int(pkthdr->len);

            cout << "The packet size is: " << packetSize << endl;
            cout << srcStr << endl;
            cout << destStr << endl;

            /* ======== Medadata ========= */

            if( ((tcpHead -> th_flags) & 0x02) && ((tcpHead -> th_flags) & 0x10) == 0 ){
               string init_rsp = srcStr + "#" + destStr + "#" + to_string(connNum);
               string rsp_init = destStr + "#" + srcStr + "#" + to_string(connNum);
               //starts a connection from init

               metaInfo[init_rsp].push_back(1);
               metaInfo[init_rsp].push_back(0);
               metaInfo[init_rsp].push_back(packetSize);
               metaInfo[init_rsp].push_back(0);
               metaInfo[init_rsp].push_back(0);
               metaInfo[init_rsp].push_back(0);
               metaInfo[init_rsp].push_back(0);

               init[init_rsp][th_seq] = {th_seq + 1, dataStr};

               if(curSession[srcStr + "#" + destStr]){
                  metaInfo[init_rsp][6] = 1;
               }

               curSession[srcStr + "#" + destStr] = connNum;
               connNum ++;
            }
            else if( ((tcpHead -> th_flags) & 0x02) && ((tcpHead -> th_flags) & 0x10) ){
               //the connection handshake from resp (ACK and SYN)
               int tempNum = curSession[destStr + "#" + srcStr];

               string rsp_init = srcStr + "#" + destStr + "#" + to_string(tempNum);
               string init_rsp = destStr + "#" + srcStr + "#" + to_string(tempNum);

               metaInfo[init_rsp][1] ++;
               metaInfo[init_rsp][3] += packetSize;

               resp[rsp_init][th_seq] = {0, dataStr};
               //set the first packet of handshake
               for(auto it = init[init_rsp].begin(); it != init[init_rsp].end(); ++it){
                  if((it -> second).first == th_ack){
                     (it -> second).first = 0;
                     break;
                  }
               }
               /* maybe need to do something with resp_ack */

            }
            else if((tcpHead -> th_flags) & 0x01){
               //FIN flag, the connection finishes, from init
               if(curSession[srcStr + "#" + destStr] != 0){
                  //FIN from init
                  int tempNum = curSession[srcStr + "#" + destStr];

                  string init_rsp = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string rsp_init = destStr + "#" + srcStr + "#" + to_string(tempNum);

                  if(metaInfo.find(init_rsp) != metaInfo.end()){
                     metaInfo[init_rsp][1] ++;
                     metaInfo[init_rsp][3] += packetSize;
                  }                  

                  init[init_rsp][th_seq] = {th_seq, dataStr};

                  metaInfo[init_rsp][6] ++;
               }
               else{
                  //FIN from resp
                  int tempNum = curSession[destStr + "#" + srcStr];

                  string rsp_init = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string init_rsp = destStr + "#" + srcStr + "#" + to_string(tempNum);

                  if(metaInfo.find(init_rsp) != metaInfo.end()){
                     metaInfo[init_rsp][0] ++;
                     metaInfo[init_rsp][2] += packetSize;
                  }                  

                  resp[rsp_init][th_seq] = {th_seq, dataStr};

                  metaInfo[init_rsp][6] ++;
               }

            }
            else if((tcpHead -> th_flags) & 0x10){
               //Normal packets (with ACK)
               //first decide where is comes from
               if(curSession[srcStr + "#" + destStr] != 0){
                  //from init
                  int tempNum = curSession[srcStr + "#" + destStr];
                  string init_rsp = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string rsp_init = destStr + "#" + srcStr + "#" + to_string(tempNum);   
                  metaInfo[init_rsp][0] ++;
                  metaInfo[init_rsp][2] += packetSize;
                  if(Length != 0){
                     //the packet itself, not ACK
                     //detect whether dup
                     if(init[init_rsp].find(th_seq) != init[init_rsp].end()){
                        metaInfo[init_rsp][4] ++;
                     }
                     init[init_rsp][th_seq] = {th_seq + Length, dataStr};
                  }
                  //ACK
                  for(auto it = resp[rsp_init].begin(); it != resp[rsp_init].end(); ++it){
                     if((it -> second).first == th_ack){
                        (it -> second).first = 0;
                        break;
                     }
                  }
               }
               else{
                  //from resp
                  int tempNum = curSession[destStr + "#" + srcStr];
                  string rsp_init = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string init_rsp = destStr + "#" + srcStr + "#" + to_string(tempNum);   
                  metaInfo[init_rsp][1] ++;
                  metaInfo[init_rsp][3] += packetSize;
                  if(Length != 0){
                     //the packet is not ACK
                     //detect whether dup
                     if(resp[rsp_init].find(th_seq) != resp[rsp_init].end()){
                        metaInfo[init_rsp][5] ++;
                     }
                     resp[rsp_init][th_seq] = {th_seq + Length, dataStr};
                  }
                     //ACK
                  for(auto it = init[init_rsp].begin(); it != init[init_rsp].end(); ++it){
                     if((it -> second).first == th_ack){
                        (it -> second).first = 0;
                        break;
                     }
                  }
               }
            }
            else{
               if(curSession[srcStr + "#" + destStr] != 0){
                  //from init
                  int tempNum = curSession[srcStr + "#" + destStr];
                  string init_rsp = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string rsp_init = destStr + "#" + srcStr + "#" + to_string(tempNum);   
                  metaInfo[init_rsp][0] ++;
                  metaInfo[init_rsp][2] += packetSize;
               }
               else{
                  int tempNum = curSession[destStr + "#" + srcStr];
                  string rsp_init = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string init_rsp = destStr + "#" + srcStr + "#" + to_string(tempNum);   
                  metaInfo[init_rsp][1] ++;
                  metaInfo[init_rsp][3] += packetSize;
               }
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
            //cout << dataStr << endl;
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
   }
   cout << endl;
   cout << endl;

}

int main(int argc, char *argv[]){

   bool hasT = 0;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *pf = NULL;
   struct bpf_program fp;
   char select_mail[] = ""; 
   struct pcap_pkthdr h;

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

   bool* arg = NULL;
   arg = &hasT;
   if(pcap_loop(pf, 0, handler_callback, (u_char*) arg) < 0){
      fprintf( stderr, "pcap_loop cannot excute");
      return 2;
   }

   cout << "======= meta information =======" << endl; 
   cout << "Number of TCP packets: " << numTCP << endl;
   cout << "Number of UDP packets: " << numUDP << endl;
   cout << "Number of Other packets: " << numOther << endl;
   cout << "Number of Total packets: " << numTCP + numUDP + numOther << endl;

   //initialize the dup in each dir in metaInfo

   for(auto it = init.begin(); it != init.end(); ++it){
      int tempInt = 0;
      for(auto i : (it -> second)){
         if(i.second.first != 0){
            cout << "dup is : " << i.first << "________" << i.second.first << endl;
            tempInt ++;
         } 
      }
      metaInfo[it -> first][4] += tempInt;
   }

   for(auto it2 = resp.begin(); it2 != resp.end(); ++it2){
      int tempInt = 0;
      for(auto i2 : (it2 -> second)){
         if(i2.second.first != 0){
            tempInt ++;
         } 
      }
      metaInfo[convertToInitResp(it2 -> first)][5] += tempInt;
   }

   for(auto it = metaInfo.begin(); it != metaInfo.end(); ++it){
      cout << (it -> first) << endl;
      cout << (it -> second)[0] <<endl;
      cout << (it -> second)[1] <<endl;
      cout << (it -> second)[2] <<endl;
      cout << (it -> second)[3] <<endl;
      cout << (it -> second)[4] <<endl;
      cout << (it -> second)[5] <<endl;
      cout << (it -> second)[6] <<endl;
   }

   for(auto it = init.begin(); it != init.end(); ++it){
      cout << (it -> first) << endl;
      cout << (it -> second).size() <<endl;
   }

   for(auto it = resp.begin(); it != resp.end(); ++it){
      cout << (it -> first) << endl;
      cout << (it -> second).size() <<endl;
   }


   return 0;
}