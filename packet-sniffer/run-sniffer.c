#include "Sniff.h"

int main(int argc, char *argv[])
{
    generic_sniff("icmp and src host 192.168.4.37", "en0");
}