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
#include <fstream>
using namespace std;

static int numTCP = 0;
static int numUDP = 0;
static int numOther = 0;

static int connNum = 1;
/*         
=> metaInfo:init_numPk, resp_numPk,  
            init_numBt, resp_numBt, 
            init_Dup, resp_Dup: need to be initialize later 
            
            closed: if == 0 then closed
*/
unordered_map<string, vector<int> > metaInfo;
//(init + resp + connNum) => (meta information)

unordered_map<string, map<unsigned long, pair<unsigned long, string> > > init;
unordered_map<string, map<unsigned long, pair<unsigned long, string> > > resp;
//(init + resp + connNum) => (seq -> (ACKed number(size + seq), 0, if acked; payload))

//(init + resp + connNum) => (seq, ack)
// ------------------------(seq, ack means the ack it need, ie: ack + size)

unordered_map<string, int> curSession;
//use for knowing which session it is currently in
//also can know whether some 
unordered_map<string, unsigned long> initFIN_ACK;
unordered_map<string, unsigned long> respFIN_ACK;


int getSemiPos(string src){
   for(int i=0; i<src.length(); ++i){
      if(src[i] == ':'){
         return i;
      }
   }
   return -1;
}

string getRespondCode(string str){
   return str.substr(0, 3);
}

string allCapitalize(string str){
   for(int i=0; i<str.length(); ++i){
      if(str[i] >= 'a' && str[i] <= 'z')
         str[i] = 'A' + str[i] - 'a';
   }
   return str;
}

string extractMailAddress(string str){
   string addrRes = "";
   bool hasLeft = 0;
   for(int i=0; i<str.length(); ++i){
      if(str[i] == '<') hasLeft = 1;
      else if(str[i] == '>') hasLeft = 0;
      else if(hasLeft) addrRes += str[i];
   }
   return addrRes;

}

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

string getSesseionNum(string str){
   stringstream istr1(str);
   string res = "";
   getline(istr1, res, '#');
   getline(istr1, res, '#');
   getline(istr1, res, '#');
   return res;
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
         int hasTT = *args;
         cout << "The tcp connection analyze: hasTT = " << hasTT << endl;
         cout << "-------------------------------" << endl;
         if(1){

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
                  init[init_rsp][th_seq] = {th_seq + 1, dataStr};
                  //metaInfo[init_rsp][6] --;
                  initFIN_ACK[init_rsp] = th_seq;
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
                  resp[rsp_init][th_seq] = {th_seq + 1, dataStr};
                  respFIN_ACK[rsp_init] = th_seq;
                  //metaInfo[init_rsp][6] --;
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

                     vector<unsigned long> toDelete; 
                     for(auto it = init[init_rsp].begin(); it != init[init_rsp].end(); ++it){
                        if(it -> first >= th_seq){
                           toDelete.push_back(it -> first);
                        }
                     }
                     metaInfo[init_rsp][4] += toDelete.size();
                     for(int i=0; i < toDelete.size(); ++i){
                        init[init_rsp].erase(toDelete[i]);
                     }
                     init[init_rsp][th_seq] = {th_seq + Length, dataStr};
                  }
                  //ACK

                  if(((tcpHead -> th_flags) & 0x04) == 0){
                     for(auto it = resp[rsp_init].begin(); it != resp[rsp_init].end(); ++it){
                        if((it -> second).first == th_ack){
                           (it -> second).first = 0;
                           break;
                        }
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
                     vector<unsigned long> toDelete;
                     for(auto it = resp[rsp_init].begin(); it != resp[rsp_init].end(); ++it){
                        if(it -> first >= th_seq) toDelete.push_back(it -> first);
                     }
                     metaInfo[init_rsp][5] += toDelete.size();
                     for(int i=0; i < toDelete.size(); ++i){
                        resp[rsp_init].erase(toDelete[i]);
                     }

                     resp[rsp_init][th_seq] = {th_seq + Length, dataStr};
                  }
                  //ACK
                  if(((tcpHead -> th_flags) & 0x04) == 0){
                     for(auto it = init[init_rsp].begin(); it != init[init_rsp].end(); ++it){
                        if((it -> second).first == th_ack){
                           (it -> second).first = 0;
                           break;
                        }
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
                  //if(((tcpHead -> th_flags) & 0x04) && (metaInfo[init_rsp][6] != 0)) metaInfo[init_rsp][6] = 0;
               }
               else{
                  int tempNum = curSession[destStr + "#" + srcStr];
                  string rsp_init = srcStr + "#" + destStr + "#" + to_string(tempNum);
                  string init_rsp = destStr + "#" + srcStr + "#" + to_string(tempNum);   
                  metaInfo[init_rsp][1] ++;
                  metaInfo[init_rsp][3] += packetSize;
                  //if(((tcpHead -> th_flags) & 0x04) && (metaInfo[init_rsp][6] != 0)) metaInfo[init_rsp][6] = 0;
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

   int hasT = 0;
   bool hasC = 0;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *pf = NULL;
   struct bpf_program fp;
   char select_mail[] = ""; 
   struct pcap_pkthdr h;

   for(int i=0; i<argc; ++i){
      if(strcmp(argv[i], "-t\0") == 0){
         hasT += 1;
      }
      else if(strcmp(argv[i], "-m\0") == 0){
         hasT += 2;
      }
      else if(strcmp(argv[i], "-c\0") == 0){
         hasC = 1;
      }
   }
/*
   if((argc != 2 && !hasT) || (argc != 3 && hasT)){
      fprintf( stderr, "Usage: %s {pcap-file}\n", argv[0] );
      return 2;
   }
*/

   if( (pf = pcap_open_offline( argv[1], errbuf )) == NULL ){
      fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
      return 2;
   }

   int* arg = NULL;
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

   //initialize the EOF in metaInfo
   for(auto i : initFIN_ACK){
      string init_key = i.first;
      if(initFIN_ACK[init_key] && respFIN_ACK[convertToInitResp(init_key)]){ //means the FIN sent out
         unsigned long init_seq = initFIN_ACK[init_key];
         unsigned long resp_seq = respFIN_ACK[convertToInitResp(init_key)];
         if(init[init_key][init_seq].first == 0 && resp[convertToInitResp(init_key)][resp_seq].first == 0){// means the FIN ACKed
            if(metaInfo.find(init_key) != metaInfo.end()) metaInfo[init_key][6] = 1;
         }

      }
   }

   if(hasT % 2){
      for(auto it = metaInfo.begin(); it != metaInfo.end(); ++it){
         string conn = getSesseionNum(it -> first);
         string filename = conn + ".meta";
         ofstream myfile (filename, ios::out | ios::app | ios::binary);
         stringstream istr(it -> first);

         string initIP;
         string respIP;
         getline(istr, initIP, '#');
         getline(istr, respIP, '#');
         myfile << "The initiator IP and port: " << initIP << endl;
         myfile << "The responder IP and port: " << respIP << endl;
         myfile << "initiator packet number: "<< (it -> second)[0] <<endl;
         myfile << "responder packet number: "<< (it -> second)[1] <<endl;
         myfile << "initiator Bytes sent: " << (it -> second)[2] <<endl;
         myfile << "responder Bytes sent: " << (it -> second)[3] <<endl;
         myfile << "initiator num of Duplicates: " << (it -> second)[4] <<endl;
         myfile << "responder num of Duplicates: " << (it -> second)[5] <<endl;
         if((it -> second)[6] == 1){
            myfile << "conection closed properly " << endl;
         }
         else{
            myfile << "connection closed before two FIN acked" << endl;
         }
      }

      //init payload data
      for(auto it = init.begin(); it != init.end(); ++it){
         string conn = getSesseionNum(it -> first);
         string filename = conn + ".initiator";
         ofstream myInit (filename, ios::out | ios::app | ios::binary);
         for(auto i : (it -> second)){
            if(i.second.first == 0){
               myInit << i.second.second << endl << "=========================================================" << endl;
            }
         }
      }

      //resp payload data
      for(auto it = resp.begin(); it != resp.end(); ++it){
         string conn = getSesseionNum(it -> first);
         string filename = conn + ".responder";
         ofstream myResp (filename, ios::out | ios::app | ios::binary);
         for(auto i : (it -> second)){
            if(i.second.first == 0){
               myResp  << i.second.second << endl << "=========================================================" << endl;
            }
         }
      }
   }

   if(hasT / 2){
      //has -m option
      for(auto it = init.begin(); it != init.end(); ++it){
         string init_key = it -> first;
         string resp_key = convertToInitResp(init_key);

         if(resp.find(resp_key) == resp.end()) continue;

         stringstream iStr(init_key);
         string initStr = "";
         string respStr = "";
         string connNum = ""; //specified for creating file
         getline(iStr, initStr, '#');
         getline(iStr, respStr, '#');
         getline(iStr, connNum, '#');

         string respPort = ""; //used to 
         stringstream istrResp(respStr);
         getline(istrResp, respPort, ':');
         getline(istrResp, respPort, ':');

         if(respPort != "25" && respPort != "587") continue; //not smtp service

         // ========== whether it is accpted: ========== //
         bool acpted = 0;
         bool hasStart = 0;

         for(auto i : resp[resp_key]){
            string respondCode = getRespondCode(i.second.second);
            if(hasStart && (respondCode == "250")){
               acpted = 1;
               break;
            }
            else if(respondCode == "354") hasStart = 1;
         }
         // ========== initialize the sender and receiver ==========//
         string sender = "";
         string receiver = "";
         for(auto i : init[init_key]){
            string cmd = (i.second.second).substr(0, 4);
            if(cmd == allCapitalize("MAIL")){
               sender = extractMailAddress(i.second.second);
            }
            else if(cmd == allCapitalize("RCPT")){
               receiver = extractMailAddress(i.second.second);
            }
         }  

         // ========== start to write to the file ========== //
         string filename = connNum + ".mail";
         ofstream myMail (filename, ios::out | ios::app | ios::binary);

         myMail << "IP address of initiator: " << initStr << endl;
         myMail << "IP address of responder: " << respStr << endl;

         myMail << endl;

         if(acpted) myMail << "the message is accepted" << endl;
         else myMail << "the message is rejected" << endl;

         myMail << endl;

         myMail << "sender address: " << sender << endl;
         myMail << "receiver address: " << receiver << endl;
         myMail << endl;

         // ========== write the true message content to file ========== //

         myMail << "header and message: " << endl;
         bool hasData = 0;
         for(auto i : init[init_key]){
            string payload = i.second.second;
            string line = "";
            stringstream payloadStr(payload);
            bool breakOut = 0;
            while(getline(payloadStr, line)){
               int leng = line.length();

               if(line.substr(0, leng - 1) == allCapitalize("DATA")){
                  hasData = 1;
               }
               else if(line.substr(0, leng - 1) == "."){
                  breakOut = 1;
                  break;
               }
               else if(hasData){
                  myMail << line << endl;
               }
            }
            if(breakOut) break;
         }
      }
   }
   if(hasC){
      for(auto it = resp.begin(); it != resp.end(); ++it){
         string resp_key = it -> first;

         stringstream iStr(resp_key);
         string initStr = "";
         string respStr = "";
         string connNum = ""; //specified for creating file
         getline(iStr, respStr, '#');
         getline(iStr, initStr, '#');
         getline(iStr, connNum, '#');

         string filename = connNum + ".cookie";
         ofstream myCookie (filename, ios::out | ios::app | ios::binary);
         myCookie << "cookie: " << endl;

         for(auto i : resp[resp_key]){
            string payload = i.second.second;
            string line;
            stringstream istrPayload(payload);
            while(getline(istrPayload, line)){
               stringstream temp(line);
               string first = "";
               temp >> first;
               if(first == "Set-Cookie:"){
                  string latter = line.substr(first.length() + 1);
                  stringstream last(latter);
                  string trueCookiePiece = "";
                  getline(last, trueCookiePiece, ';');
                  myCookie << trueCookiePiece << ";" << endl;
               }
            }
         }
      }
   }

   return 0;
}









