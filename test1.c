#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
    char *dev = argv[1];
    char errbuf[400];

    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL)
        puts(errbuf);

    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide ethernet headers, not supported\n", dev);
        return(2);
    }


    return 0;
}
