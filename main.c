#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //getopt
#include <ctype.h> //isprint
#include <arpa/inet.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include "sniff.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);

int main(int argc, char *argv[])
{
    int opt = 0;
    int ret = 0;
    char *lport = malloc(20);
    uint16_t rport = 0;
    char *filter_exp = {0}; // the only filter for right now is port number 
    pcap_t *handle;
    char *dev = "wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const unsigned char *packet;
    struct sniff_ip test;

    if(argc < 3)
    {
        puts("At least 2 arguments required.");
        printf("Usage: %s lport rport\n", argv[0]);
        return 5;
    }

    int n = 0;
    sscanf(argv[optind], "%hu", &n);
    sprintf(lport, "port %hu", n);
    puts(lport);
    sscanf(argv[optind+1], "%hu", &rport);

    filter_exp = strdup(lport);

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
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

    char *ip_address = malloc(INET_ADDRSTRLEN);

    inet_ntop(AF_INET, &ip->ip_src, ip_address, INET_ADDRSTRLEN);
    printf("source ip address: %s\n", ip_address);

    inet_ntop(AF_INET, &ip->ip_dst, ip_address, INET_ADDRSTRLEN);
    printf("dest ip address: %s\n", ip_address); 

    printf("sport: %hu\n", ntohs(tcp->th_sport));
    printf("dport: %hu\n", ntohs(tcp->th_dport));
}

