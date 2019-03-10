// This program relies heavily on this guide: https://www.tcpdump.org/pcap.html
// Most of the core functionality comes from libpcap
// I marked most of the code borrowed from the guide, both to not take credit
// from it, but also to make it easier for me to see where my program diverges
// from the guide.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //getopt
#include <ctype.h> //isprint
#include <arpa/inet.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include "sniff.h"

// arguments struct (got_packet)
typedef struct {
    pcap_t *_handle;
} configuration;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);

int main(int argc, char *argv[])
{
    // my declarations
    int opt = 0;
    int ret = 0; // used to check return values
    uint16_t rport = 0;
    char *lport = malloc(20);
    struct sniff_ip test;

    // libpcap common declarations
    pcap_t *handle;
    char *filter_exp; 
    char *dev = "wlan0";
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    struct pcap_pkthdr header;

    configuration config[1];

    // make sure the programs has enough args
    if(argc < 3)
    {
        printf("At least 2 arguments required.\n"
               "Usage: %s lport rport\n", argv[0]);
        return 5;
    }

    // little error check    
    // these will go in their own function later
    int portnum = 0;
    ret = sscanf(argv[optind], "%hu", &portnum);
    if(ret < 1)
    {
        puts("Error: unable to read port number from input.");
        return 5;
    }

    // port number goes in bpf filter format
    sprintf(lport, "port %hu", portnum);

    // rport isn't used (yet)
    sscanf(argv[optind+1], "%hu", &rport);

    filter_exp = strdup(lport);

    /*{{-----------------------libpcap setup start-----------------------------}}*/
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    config->_handle = handle;
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, 
            "Device %s doesn't provide ethernet headers, not supported\n", dev);
        return 2;
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, 
            "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr,
            "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));   
        return 2;
    }
    /*{{-----------------------libpcap setup end-------------------------------}}*/

    printf("%p\n", handle);
    pcap_loop(handle, -1, got_packet, (u_char *)config);
    pcap_close(handle);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
    configuration *config = (configuration *)args;
    pcap_t *handle = config->_handle;

    /*{{----------------------------libpcap start------------------------------}}*/
    // 
    /* ethernet headers are always exactly 14 bytes */
    #define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    unsigned size_ip;
    unsigned size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    /*{{----------------------------libpcap end--------------------------------}}*/

    char *ip_address = malloc(INET_ADDRSTRLEN);

    inet_ntop(AF_INET, &ip->ip_src, ip_address, INET_ADDRSTRLEN);
    printf("source ip address: %s\n", ip_address);

    inet_ntop(AF_INET, &ip->ip_dst, ip_address, INET_ADDRSTRLEN);
    printf("dest ip address: %s\n", ip_address); 

    printf("sport: %hu\n", ntohs(tcp->th_sport));
    printf("dport: %hu\n", ntohs(tcp->th_dport));
    puts("\n");
    pcap_inject(handle, packet, header->len);
}

