#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>


// DNS (avoid resolving domains) | HTTP (header Host: facebook.com | HTTPS (Only if SNI extension is present)).


void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

enum HTTP_METHODS {GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH};

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



void my_packet_handler(
    u_char *userData,
    const struct pcap_pkthdr* pkthdr,
    const u_char* packet
)
{
    const struct ether_header* eth_header;
    const struct ip* ip_header;
    const struct tcphdr* tcp_header;

    // Wanted fields
    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];

    u_int sourcePort, dstPort;
    u_char* data;
    int data_length;

    eth_header = (const struct ether_header*) packet;
    ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    inet_ntop(AF_INET, &(ip_header->ip_src), ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), ip_dst, INET_ADDRSTRLEN);

    sourcePort = ntohs(tcp_header->source);
    dstPort = ntohs(tcp_header->dest);


    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
        return;
    }
    if (ip_header->ip_p != IPPROTO_TCP){
        return;
    }


    if (!(sourcePort == 80 || sourcePort == 443 || dstPort == 80 || dstPort == 443)){
        return;
    }

    if (dstPort == 80){
        data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));


       u_char* first_line_http = split_lines_http(data, data_length);
       if (first_line_http == NULL){
           return;
       }
       u_int first_line_http_length = first_line_http - data;
       //printf("Length %u\n", first_line_http_length);

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

       enum HTTP_METHODS actualHttpMethod;
       if (strcmp(method, "GET") == 0)
        actualHttpMethod = GET;
       else if (strcmp(method, "HEAD") == 0)
        actualHttpMethod = HEAD;
       else if (strcmp(method, "POST") == 0)
        actualHttpMethod = POST;
       else if (strcmp(method, "PUT") == 0)
        actualHttpMethod = PUT;
       else if (strcmp(method, "DELETE") == 0)
        actualHttpMethod = DELETE;
       else if (strcmp(method, "CONNECT") == 0)
        actualHttpMethod = CONNECT;
       else if (strcmp(method, "OPTIONS") == 0)
        actualHttpMethod = OPTIONS;
       else if (strcmp(method, "TRACE") == 0)
        actualHttpMethod = TRACE;
       else if (strcmp(method, "PATCH") == 0)
        actualHttpMethod = PATCH;
       else {
           printf("Non of the previous\n");
           return;
       }

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























      // u_char* position = split_lines_http(fi)














    //    return;

    //     u_int ctx;
    //     int found = 0;


    //     for (ctx = 0; ctx < data_length && found == 0; ++ctx){
    //         u_char* act = data + ctx;
    //         if (*act == '\n'){
    //             found = 1;
    //         }
    //     }

    //     if (!found){
    //        // printf("Not HTTP packet\n");
    //         return;
    //     }
    //     //else printf("Http Packet\n");


    //     u_char* del = get_delimiter(0x20, data, 10);
    //     if (del == NULL){
    //         printf("Havent found anything\n");
    //     }
    //     u_char* method = malloc(sizeof(u_char) * (del - data));
    //     memcpy(method, data, del - data);

    //     if (strcmp(method, "GET") == 0){
    //         printf("GET petition\n");
    //     }
    //     else if (strcmp(method, "POST") == 0){
    //         printf("POST petition\n");
    //     }




    //     u_char* del2 = get_delimiter(0x20, del + 1, 250);
    //     u_char* uri = malloc(sizeof(u_char) * (del2 - del));
    //     memcpy(uri, del + 1, del2 - del);

    //     if (del2 == NULL){
    //         printf("Havent found anything\n");
    //     }




    //     for (int k=0; k < del2 - del; ++k){
    //         printf("%c", *(uri + k));
    //     }





















    }




    //printf("IP SRC: %s:%u -> IP DST: %s:%u\n", ip_src, sourcePort, ip_dst, dstPort);





}



int main(){
    char error_buffer[PCAP_ERRBUF_SIZE];

    const char* path = "~/http.cap";

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
