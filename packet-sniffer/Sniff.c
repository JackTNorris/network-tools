#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "../utils/header.h"
#include "Sniff.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    // network order to host byte order
    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));

        // determine protocol
        switch (ip->iph_protocol)
        {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            return;
        default:
            printf("Protocol: others\n");
            return;
        }
    }
}

void generic_sniff(char* filter_expression, char* interface)
{
    // file descriptor for pcap object
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    //netmask
    bpf_u_int32 net;


    // Step 1: Open live pcap session on Network interface card with name interface name
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter expression into BPF psuedo-code
    pcap_compile(handle, &fp, filter_expression, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); // Close the handle
}

void sniff_and_do(char* filter_expression, char* interface_name, void (*on_sniff_packet)(u_char *args, const struct pcap_pkthdr *header, const u_char *packet))
{
    // file descriptor for pcap object
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    //netmask
    bpf_u_int32 net;

    // Step 1: Open live pcap session on Network interface card with name interface name
    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter expression into BPF psuedo-code
    pcap_compile(handle, &fp, filter_expression, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, on_sniff_packet, NULL);
    pcap_close(handle); // Close the handle
}


