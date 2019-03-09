// old stuff that i might want for later
    from got_packet:
    payload = (uint8_t *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    printf("Packet header length: %u\n", header->len);
    printf("sport: %hu\n", ntohs(tcp->th_sport));
    printf("dport: %hu\n", ntohs(tcp->th_dport));
    printf("tcp_seq: %u\n", ntohl(tcp->th_seq));
    printf("tcp_ack: %u\n", ntohl(tcp->th_ack));

    puts("Got packet! Data:\n");
    int i = 0;
    while(i < header->len)
    {
        #define c payload[i]
        if(isprint(c))
            putchar(c);
        else
            putchar('.');
        
        i++;
    }
    putchar('\n');

    // just looking at some packets of different programs in a hex editor
    int delim = 0x55;
    FILE *file = fopen("test.bin", "ab");
    fwrite(&delim, sizeof(int), 1, file);
    fwrite(payload, 1, header->len, file);
    fwrite(&delim, sizeof(int), 1, file);
    fclose(file);

    from main:
                printf("ret == %d\n", ret);
                sprintf(port, "port %u", n);
                filter_exp = strdup(port);


    // get arguments
    while((opt = getopt(argc, argv, "::")) != -1)
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


                break;
            default:
                puts("requires at least one option -p (send port)");
                break;
        }
    }

    while(optind < argc)
    {
        printf("Extra arguments: %s\n", argv[optind]);
        optind++;
    }
