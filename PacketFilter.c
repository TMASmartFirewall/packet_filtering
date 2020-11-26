#include "PacketFilter.h"

int Sum(int a, int b)
{
    return a+b;
}

void processDns(){

}

void print_uchar_array(u_char* arr, u_int length){
    printf("[");
    if(length > 80)
      length = 80;
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
    // Returns the last character of the HTTP LINE without \r\n
    for (u_int ctx = 0; ctx < max_length ; ctx++){
        if (ctx < max_length - 1){
            if (*(payload + ctx) == 0x0d && *(payload + ctx + 1)){
                return payload + ctx - 1;
            }
        }
    }
    return NULL;
}

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
      printf("Non of the previous\n");
      return -1;
  }
}

void processHttpRequest(int dstPort,const u_char* packet, const struct pcap_pkthdr* pkthdr) {
  u_char* data;
  int data_length;
  fprintf(stderr, "%i\n", dstPort );
  if (dstPort == 80){

      data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
      data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

      print_uchar_array(data,data_length);

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

     u_char* method = malloc(sizeof(u_int) * (first_delimiter - data));
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

     u_char* url_relative = malloc(sizeof(u_char) * (act_delimiter - first_delimiter) - 2);
     memcpy(url_relative, first_delimiter + 1, (act_delimiter - first_delimiter - 1));

     print_uchar_array(url_relative, act_delimiter - first_delimiter);

     // What is left is the HTTP Version

     u_int left_bytes = first_line_http_length  - (act_delimiter - data);
     //printf("Left bytes: %i\n", left_bytes);

     u_char* http_version = malloc(sizeof(u_char) * left_bytes);
     memcpy(http_version, act_delimiter + 1, sizeof(u_char) * left_bytes);

     if (act_delimiter == NULL){
         printf("Couldnt find the HTTP version\n");
         return;
     }

     print_uchar_array(http_version, left_bytes);
     printf("\n");

     // Host:

     getHostHeader(first_line_http, data_length - first_line_http_length);
  }

  else {
    return;
  }
}
void processHttpResponse(int dstPort,const u_char* packet, const struct pcap_pkthdr* pkthdr) {
  u_char* data;
  int data_length;
  fprintf(stderr, "%i\n", dstPort );
  if (dstPort == 80){

      data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
      data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

      print_uchar_array(data,data_length);

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

     u_char* method = malloc(sizeof(u_int) * (first_delimiter - data));
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

     u_char* url_relative = malloc(sizeof(u_char) * (act_delimiter - first_delimiter) - 2);
     memcpy(url_relative, first_delimiter + 1, (act_delimiter - first_delimiter - 1));

     print_uchar_array(url_relative, act_delimiter - first_delimiter);

     // What is left is the HTTP Version

     u_int left_bytes = first_line_http_length  - (act_delimiter - data);
     //printf("Left bytes: %i\n", left_bytes);

     u_char* http_version = malloc(sizeof(u_char) * left_bytes);
     memcpy(http_version, act_delimiter + 1, sizeof(u_char) * left_bytes);

     if (act_delimiter == NULL){
         printf("Couldnt find the HTTP version\n");
         return;
     }

     print_uchar_array(http_version, left_bytes);
     printf("\n");

     // Host:

     getHostHeader(first_line_http, data_length - first_line_http_length);
  }

  else {
    return;
  }
}
