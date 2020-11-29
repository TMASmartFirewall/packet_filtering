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

// DNS (avoid resolving domains) | HTTP (header Host: facebook.com | HTTPS (Only if SNI extension is present)).





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
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(tcp_header->source);
        dstPort = ntohs(tcp_header->dest);
    } else {
      udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
      sourcePort = ntohs(udp_header->source);
      dstPort = ntohs(udp_header->dest);
    }


    //http PORT 443 or 80
    if (sourcePort == 80) {
      processHttpResponse(sourcePort, packet, pkthdr);
    } else if (sourcePort == 443 || dstPort == 80 || dstPort == 443) {
      processHttpRequest(dstPort, packet, pkthdr);
    }
    // DNS PORT 53
    else if(dstPort == 53 ) {
      struct dns_request dnsRequest;
      dnsRequest = processDnsRequest(packet, pkthdr);
      fprintf(stderr, "%s\n", dnsRequest.query->url );
    } else if(sourcePort == 53){
      struct dns_response dnsReponse;
      dnsReponse = processDnsResponse(packet, pkthdr);
      fprintf(stderr, "%i\n", dnsReponse.header->id );
      return;

    } else {
      return;
    }


    inet_ntop(AF_INET, &(ip_header->ip_src), ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), ip_dst, INET_ADDRSTRLEN);



    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
        return;
    }

}



int main(){
    char error_buffer[PCAP_ERRBUF_SIZE];

    const char* path = "./http.cap";

    // check if we can read and acces the file
    if (access(path, F_OK|R_OK)){
        printf("No access to file %s\n", path);
        return 1;
    }



    pcap_t* handle = pcap_open_offline(path, error_buffer);
    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);


    // struct pcap_pkthdr packet_header;


    // const u_char *packet = pcap_next(handle, &packet_header);

    // if (packet == NULL){
    //     printf("No packet available");
    //     return 2;
    // }
    // print_packet_info(packet, packet_header);



}
