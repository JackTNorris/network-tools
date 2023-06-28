#include <pcap.h>
#ifndef SNIFF_H
#define SNIFF_H

void generic_sniff(char* filter_expression, char* interface);
void sniff_and_do(char* filter_expression, char* interface_name, void (*on_sniff_packet)(u_char *args, const struct pcap_pkthdr *header, const u_char *packet));

#endif
