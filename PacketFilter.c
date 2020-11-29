#include "PacketFilter.h"

enum HTTP_METHODS getHttpType (char* method) {
  if (strcmp(method, "GET") == 0)
  return GET;
  else if (strcmp(method, "HEAD") == 0)
  return HEAD;
  else if (strcmp(method, "POST") == 0)
  return POST;
  else if (strcmp(method, "PUT") == 0)
  return PUT;
  else if (strcmp(method, "DELETE") == 0)
  return DELETE;
  else if (strcmp(method, "CONNECT") == 0)
  return CONNECT;
  else if (strcmp(method, "OPTIONS") == 0)
  return OPTIONS;
  else if (strcmp(method, "TRACE") == 0)
  return TRACE;
  else if (strcmp(method, "PATCH") == 0)
  return PATCH;
  else {
    return -1;
  }
}

int parseDnsQuery(u_char* payload, struct dns_query* paquet) {
  int currentPosition = 0;
  int x = 0;
  paquet->url = malloc(sizeof(char));
  while(payload[currentPosition] != 0x00){
    int blockSize = (int) payload[currentPosition];
    paquet->url = realloc(paquet->url, blockSize + 2 + sizeof(paquet->url));
    for (x = 0 ; x < blockSize; x += 1){
      currentPosition +=1;
      paquet->url[currentPosition -1] = (char) payload[currentPosition];
    }
    currentPosition +=1;
    paquet->url[currentPosition -1] = 0x2E;
  }
  paquet->url[currentPosition - 1] = 0x03;

  currentPosition += 2;
  paquet->type = (int16_t) *(payload + currentPosition);
  currentPosition += 2;
  paquet->class = (int16_t) *(payload + currentPosition);
  return currentPosition +1;
}
struct dns_request processDnsRequest( const u_char* packet, const struct pcap_pkthdr* pkthdr){
  struct dns_query* dnsQuery;
  struct dns_request request;
  dnsQuery = malloc(sizeof(struct dns_query));
  u_char* payload;
  int payload_length;
  int16_t id;

  struct dnshdr* a = (struct dnshdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

  request.header = a;
  payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr));
  int x = 0;
  request.query = malloc(ntohs(request.header->questions) * sizeof(struct dns_query));
  for(x = 0; x < ntohs(request.header->questions); x += 1) {
    payload += parseDnsQuery(payload, request.query + x);
  }
  payload_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr));
  return request;
}

struct dns_response processDnsResponse(const u_char* packet, const struct pcap_pkthdr* pkthdr){
  struct dns_query* dnsQuery;
  struct dns_response response;
  dnsQuery = malloc(sizeof(struct dns_query));
  u_char* payload;
  int payload_length;
  int16_t id;
  payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr));

  struct dnshdr* dnsHeaders = (struct dnshdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
  response.header = dnsHeaders;

  response.query = malloc(ntohs(response.header->questions) * sizeof(struct dns_query));
  int x = 0;
  for(x = 0; x < ntohs(response.header->questions); x += 1) {
    payload += parseDnsQuery(payload, response.query + x);
  }

  response.answer = malloc(ntohs(response.header->answers) * sizeof(struct dns_answer));
  for(x = 0; x < ntohs(response.header->answers); x += 1) {
    // payload += parseDnsAnswer(payload, response.query + x);
  }

  return response;
}


void print_uchar_array(u_char* arr, u_int length){
  printf("[");
  for (u_int ctx = 0; ctx < length; ++ctx){
    printf("%c", *(ctx + arr));
  }
  printf("]");
}



u_char* get_delimiter(u_char delimiter, u_char* array, u_int length){
  for (u_int i = 0; i < length; ++i){
    if (*(array + i) == delimiter)
    return array + i;
  }
  return NULL;
}



u_char* analyzeHttpHeader(u_char* payload, u_int max_length){
  // Search for : delimiter
  for (u_int ctx = 0; ctx < max_length; ++ctx){
    if (*(payload + ctx) == ':'){
      return payload + ctx;
    }
  }
  return NULL;
}
void getHostHeader(u_char* payload, u_int max_length){
  u_char* line_start = payload;
  u_int accum_length = 0;

  while (line_start < (payload + max_length)){
    u_char* act_line = split_lines_http(line_start, max_length - accum_length );
    if (act_line == NULL){
      printf("NULL\n");
      break;
    }

    u_char* split = analyzeHttpHeader(line_start, act_line - line_start);
    if (split == NULL){
      break;
    }
    else printf("OK\n");

    u_char* header_name = malloc(sizeof(u_char) * (split - line_start - 1));
    u_char* value = malloc(sizeof(u_char) * (act_line - split));
    memcpy(header_name, line_start, act_line - line_start - 1);
    memcpy(value, split + 1, act_line - split - 1);

    printf("Header name:\n");
    print_uchar_array(header_name, split - line_start - 1);

    accum_length += (act_line - payload);
    line_start = act_line + 2;

  }

}
u_char* split_lines_http(u_char* payload, u_int max_length){
  // cut at the breakline
  for (u_int ctx = 0; ctx < max_length ; ctx++){
    if (ctx < max_length - 1){
      if (*(payload + ctx) == 0x0d && *(payload + ctx + 1)){
        return payload + ctx;
      }
    }
  }
  return NULL;
}

struct http_req* parseHttpFirstLine(u_char* payload, u_char* first_line, u_int first_line_length){
  struct http_req* packet = malloc(sizeof(struct http_req));
  // Get method
  u_char* payload_position = get_delimiter(0x20, payload, first_line_length);
  u_char* method = malloc(sizeof(u_int) * (payload_position - payload));
  memcpy(method, payload, payload_position - payload);
  packet->method = getHttpType(method);
  payload = payload_position + 1;

  // GET url
  payload_position = get_delimiter(0x20, payload, first_line_length);
  u_char* url = malloc(sizeof(u_char) * (payload_position - payload));
  memcpy(url, payload, payload_position - payload);
  packet->url = url;
  payload = payload_position + 1;

  // GET version
  payload_position = get_delimiter(0x0d, payload, first_line_length);
  u_char* version = malloc(sizeof(u_char) * (payload_position - payload));
  memcpy(version, payload, payload_position - payload);
  packet->version = version;

  return packet;
}

void processHttpRequest(int dstPort,const u_char* packet, const struct pcap_pkthdr* pkthdr) {
  struct http_req* http_paquet;
  if (dstPort == 80){
    u_char* payload;
    int payload_length;
    // set the pointer to the start of tcp payload
    payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    payload_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

    u_char* first_line_http = split_lines_http(payload, payload_length);

    if (first_line_http == NULL){
      return;
    }
    u_int first_line_http_length = first_line_http - payload;
    http_paquet = parseHttpFirstLine(payload, first_line_http, first_line_http_length);

  }
  else {
    return;
  }
}
void processHttpResponse(int dstPort, const u_char* packet, const struct pcap_pkthdr* pkthdr) {
  u_char* data;
  int data_length;
  if (dstPort == 80){

    data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

    u_char* first_line_http = split_lines_http(data, data_length);
    if (first_line_http == NULL){
      return;
    }
    u_int first_line_http_length = first_line_http - data;


    // TODO: Separar GET | URI | Versio HTTP
    // TODO: Obtindre els demes headers
    u_char* first_delimiter = get_delimiter(0x20, data, first_line_http_length);

    if (first_delimiter == NULL){
      printf("Not a valid HTTP Request, couldnt parse the method\n");
      return;
    }

    u_char* method = malloc(sizeof(u_int) * (first_delimiter - data - 2));
    //printf("Method:");
    memcpy(method, data, first_delimiter - data);
    for (u_int k =0; k < first_delimiter - data; ++k){
      printf("%c", *(method + k));
    }
    //printf("\n");

    enum HTTP_METHODS actualHttpMethod = getHttpType(method);

    // Obtenim el path relatiu

    u_char* act_delimiter = get_delimiter(0x20, first_delimiter + 1, first_line_http_length - (first_delimiter - data - 1));
    if (act_delimiter == NULL){
      printf("Couldnt find the relative path\n");
      return;
    }

    u_char* url_relative = malloc(sizeof(u_char) * (act_delimiter - first_delimiter));
    memcpy(url_relative, first_delimiter + 1, (act_delimiter - first_delimiter - 1));

    // print_uchar_array(url_relative, act_delimiter - first_delimiter);

    // What is left is the HTTP Version

    u_int left_bytes = first_line_http_length  - (act_delimiter - data);
    //printf("Left bytes: %i\n", left_bytes);

    u_char* http_version = malloc(sizeof(u_char) * left_bytes);
    memcpy(http_version, act_delimiter + 1, sizeof(u_char) * left_bytes);

    if (act_delimiter == NULL){
      printf("Couldnt find the HTTP version\n");
      return;
    }

    // print_uchar_array(http_version, left_bytes);
    printf("\n");

    // Host:

    // getHostHeader(first_line_http, data_length - first_line_http_length);
  }

  else {
    return;
  }
}
