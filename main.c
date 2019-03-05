#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //getopt
#include <ctype.h> //isprint
#include <string.h>
#include <pcap.h>
#include "sniff.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);

int main(int argc, char *argv[])
{
    int opt = 0;
    int ret = 0;
    char *filter_exp; // the only filter for right now is port number 
    char *port = malloc(20); // "port #####"
    pcap_t *handle;
    char *dev = "wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const unsigned char *packet;
    struct sniff_ip test;

    // get arguments
    while((opt = getopt(argc, argv, ":p:w:")) != -1)
    {
        switch(opt)
        {
            case 'w':
            case 'p':;

                unsigned n = 1;
                ret = sscanf(optarg, "%u", &n);
                if(ret <= 0 || n > 65535)
                {
                    puts("invalid port number.\n");
                    return 5;
                }

                printf("ret == %d\n", ret);
                sprintf(port, "port %u", n);
                filter_exp = strdup(port);

                break;
            default:
                break;
        }
    }

    puts(port);

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

    u_int size_ip;
    u_int size_tcp;

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
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    int i = 0;

    while(i < header->len)
    {
         //isprint, is the character printable?
        if(isprint(payload[i]))
            putchar(payload[i]);
        else
            putchar('.');

        i++;
    }

    putchar('\n');

}
