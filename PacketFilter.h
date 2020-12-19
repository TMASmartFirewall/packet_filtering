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



struct http_req {
    enum HTTP_METHODS method;
    char* url;
    char* version;
};

struct dnshdr {
    int16_t id;
    int16_t flags;
    int16_t questions;
    int16_t answers;
    int16_t nscount;
    int16_t arcount;
};

struct dns_query{
  int16_t type;
  int16_t class;
  char* url;
};

struct dns_request {
  struct dnshdr* header;
  struct dns_query* query;
};

struct dns_answer {
  int16_t* name;
  int16_t* type;
  int16_t* class;
  int32_t* timetolive;
  int16_t* data;
  char* cname;
  int addr[4];
};

struct dns_response {
  struct dnshdr* header;
  struct dns_query* query;
  struct dns_answer* answer;
};

struct session_data {
  long long int tcp;
  long long int udp;
  long long int dns;
  long long int http;
  long long int https;
};



struct dns_request* processDnsRequest(const u_char* packet, const struct pcap_pkthdr* pkthdr);
struct dns_response* processDnsResponse(const u_char* packet, const struct pcap_pkthdr* pkthdr);
void processHttpRequest(int dstPort,const u_char* packet,const struct pcap_pkthdr* pkthdr);
void processHttpResponse(int dstPort,const u_char* packet,const struct pcap_pkthdr* pkthdr);
u_char* split_lines_http(u_char* payload, u_int max_length);
void freeDnsPaquet(struct dns_request* paquet);
void freeDnsResponse(struct dns_response* paquet);

void print_uchar_array(u_char* arr, u_int length);



u_char* get_delimiter(u_char delimiter, u_char* array, u_int length);
u_char* analyzeHttpHeader(u_char* payload, u_int max_length);
void getHostHeader(u_char* payload, u_int max_length);

#endif
