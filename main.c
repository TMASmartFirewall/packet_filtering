#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include "PacketFilter.h"
#include <setjmp.h>

#define TRY do{ jmp_buf ex_buf__; if( !setjmp(ex_buf__) ){
  #define CATCH } else {
    #define ETRY } }while(0)
    #define THROW longjmp(ex_buf__, 1)

    // DNS (avoid resolving domains) | HTTP (header Host: facebook.com | HTTPS (Only if SNI extension is present)).
    struct session_data sessData = { .tcp = 0, .udp = 0 , .dns = 0, .http = 0, .https=0 };
    FILE *fd;


    void printSessionData(struct session_data sessData) {
      fprintf(fd, "Session Data:\n UDP: %lld\n  DNS:%lld\n TCP: %lld\n",sessData.udp, sessData.dns ,sessData.tcp );
    }


    void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
      printf("Packet capture length: %d\n", packet_header.caplen);
      printf("Packet total length %d\n", packet_header.len);
    }

    void my_packet_handler(
      u_char *userData,
      const struct pcap_pkthdr* pkthdr,
      const u_char* packet
    )
    {
      const struct ether_header* eth_header;
      const struct ip* ip_header;
      const struct tcphdr* tcp_header;
      const struct udphdr* udp_header;
      // Wanted fields
      char ip_src[INET_ADDRSTRLEN];
      char ip_dst[INET_ADDRSTRLEN];

      u_int sourcePort, dstPort;
      u_char* data;
      int data_length;

      eth_header = (const struct ether_header*) packet;
      ip_header = (struct ip*)(packet + sizeof(struct ether_header));

      if (ip_header->ip_p != IPPROTO_TCP){
        sessData.tcp += 1;
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(tcp_header->source);
        dstPort = ntohs(tcp_header->dest);
      } else if (ip_header->ip_p != IPPROTO_UDP){
        sessData.udp += 1;
        udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(udp_header->source);
        dstPort = ntohs(udp_header->dest);
      }


      //http PORT 443 or 80
      if (sourcePort == 80) {
        // processHttpResponse(sourcePort, packet, pkthdr);
      } else if (sourcePort == 443 || dstPort == 80 || dstPort == 443) {
        // processHttpRequest(dstPort, packet, pkthdr);
      }
      // DNS PORT 53
      else if(dstPort == 53 ) {
        struct dns_request* dnsRequest;
        dnsRequest = processDnsRequest(packet, pkthdr);
        if(dnsRequest != NULL) {
          sessData.dns += 1;
          freeDnsPaquet(dnsRequest);
        }
      }
    }

    int main(int argc, char *argv[]){
      char error_buffer[PCAP_ERRBUF_SIZE];
      if(argc != 2){
        fprintf(stderr, "Usage: \n\t%s <file_name>\n",argv[0] );
        exit(-1);
      }
      const char* path = argv[1];
      fd = fopen("./logs.json", "w");
      // check if we can read and acces the file
      if (access(path, F_OK|R_OK)){
        printf("No access to file %s\n", path);
        return 1;
      }

      FILE *packetProcessed = fopen("./pakcets.json", "w");
      fprintf(packetProcessed, "[\n");
      fclose(packetProcessed);
      pcap_t* handle = pcap_open_offline(path, error_buffer);
      pcap_loop(handle, 0, my_packet_handler, NULL);
      pcap_close(handle);
      printSessionData(sessData);
      packetProcessed = fopen("./pakcets.json", "a");
      fprintf(packetProcessed, "]");
      fclose(packetProcessed);
    }
