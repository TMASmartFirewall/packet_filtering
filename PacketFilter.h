#ifndef PACKETFILTER_H_INCLUDED
#define PACKETFILTER_H_INCLUDED

#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

enum HTTP_METHODS {
  GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
} ;


int Sum(int a, int b);
void processDns();
void processHttpRequest(int dstPort,const u_char* packet,const struct pcap_pkthdr* pkthdr);
void processHttpResponse(int dstPort,const u_char* packet,const struct pcap_pkthdr* pkthdr);
u_char* split_lines_http(u_char* payload, u_int max_length);

void print_uchar_array(u_char* arr, u_int length);



u_char* get_delimiter(u_char delimiter, u_char* array, u_int length);
u_char* analyzeHttpHeader(u_char* payload, u_int max_length);
void getHostHeader(u_char* payload, u_int max_length);

#endif
