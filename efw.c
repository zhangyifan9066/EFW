#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHER_HEADER_LEN    14
#define ARP_HEADER_LEN      8
//#define _IP_VHL             1

struct arpbody
{
    u_char ar_sha[6];
    u_char ar_spa[4];
    u_char ar_tha[6];
    u_char ar_tpa[4];
};

int cnt = 0;
int arp_cnt = 0;
int dns_cnt = 0;

u_short judge_ethernet(const u_char *data)
{
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *) data;
    return ethernet_header->ether_type;
}

void pkt_handler(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *data)
{
    cnt++;
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *) data;

    char *ethernet_sha = ether_ntoa(ethernet_header->ether_shost);
    char *ethernet_dha = ether_ntoa(ethernet_header->ether_dhost);

    //printf("type: %x\n", ntohs(ethernet_header->ether_type));
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP)
    {
        struct arphdr *arp_header;
        arp_header = (struct arphdr *) (data + ETHER_HEADER_LEN);
        
        //printf("ETHER: %d   PROTOCOL: %x  OP: %d\n", ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro), ntohs(arp_header->ar_op) == ARPOP_REPLY);
        if (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER && ntohs(arp_header->ar_pro) == 0x0800 && ntohs(arp_header->ar_op) == ARPOP_REPLY)
        {
//            printf("An incoming ARP packet from %s(%s) to %s(%s)\n", ether_ntoa())
            arp_cnt++;
            struct arpbody *arp_body;
            arp_body = (struct arpbody *) (data + ETHER_HEADER_LEN + ARP_HEADER_LEN);
            printf("An incoming ARP packet from ");
            int i;
            int first = 1;
            for (i = 0; i < 4; i++) {
                if (!first)
                    printf(".");
                printf("%d", arp_body->ar_spa[i]);
                first = 0;
            }
            first = 1;
            printf(" (");
            for (i = 0; i < 6; i++) {
                if (!first)
                    printf(":");
                printf("%02X", arp_body->ar_sha[i]);
                first = 0;
            }
            first = 1;
            printf(") to ");
            for (i = 0; i < 4; i++) {
                if (!first)
                    printf(".");
                printf("%d", arp_body->ar_tpa[i]);
                first = 0;
            }
            first = 1;
            printf(" (");
            for (i = 0; i < 6; i++) {
                if (!first)
                    printf(":");
                printf("%02X", arp_body->ar_tha[i]);
                first = 0;
            }
            printf(")\n");
        }
    } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        /*int i;
        for (i = 0; i < 20; i++)
            printf("%x ", data[i + ETHER_HEADER_LEN]);
        printf("\n");*/
        struct ip *ip_header;
        ip_header = (struct ip *) (data + ETHER_HEADER_LEN);

        u_short hdr_len = ((u_short)IP_VHL_HL(ip_header->ip_vhl) << 2);
        char *ip_spa = inet_ntoa(ip_header->ip_src);
        char *ip_dpa = inet_ntoa(ip_header->ip_dst);
        //printf("ip header len: %u\n", hdr_len);
        //printf("ip version:  %u\n", IP_VHL_V(ip_header->ip_vhl));

        u_char protocol = ip_header->ip_p;
        if (protocol == 6)   //tcp
        {
            struct tcphdr *tcp_header;
            tcp_header = (struct tcphdr *) (data + ETHER_HEADER_LEN + hdr_len);

            uint16_t tcp_sport = ntohs(tcp_header->th_sport);
            uint16_t tcp_dport = ntohs(tcp_header->th_dport);
            if (tcp_dport == 53)
            {
                dns_cnt++;
                printf("An outgoing DNS packet from %s:%u (%s) to %s:%u (%s)\n", ip_spa, tcp_sport, ethernet_sha, ip_dpa, tcp_dport, ethernet_dha);
                //printf("dns in tcp");
            }
            //printf("tcp\n");

        } else if (protocol == 17)   //udp
        {
            struct udphdr *udp_header;
            udp_header = (struct udphdr *) (data + ETHER_HEADER_LEN + hdr_len);

            uint16_t udp_sport = ntohs(udp_header->uh_sport);
            uint16_t udp_dport = ntohs(udp_header->uh_dport);
            if (udp_dport == 53)
            {
                dns_cnt++;
                printf("An outgoing DNS packet from %s:%u (%s) to %s:%u (%s)\n", ip_spa, udp_sport, ethernet_sha, ip_dpa, udp_dport, ethernet_dha);
                //printf("dns in udp\n");
            }
            //printf("udp\n");
        }
    }

//    printf("cnt: %d\n%s\n", cnt, data);
//    printf("cnt: %d\n%s\n", cnt, ether_ntoa(data));
/*    int i = 0;
    for (i; i < strlen(data); i++)
        printf("%u", data[i]);

    printf("\n");
*/
}

int main(int argc,  char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    char *filter_string = "arp or (dst port 53)";
    //char *filter_string = "arp";

    struct bpf_program filter;

    dev = pcap_lookupdev(errbuf);
    if (!dev)
    {
        printf("error: pcap_lookupdev(): %s", errbuf);
        exit(0);
    }

    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
    {
        printf("error: pcap_lookupnet(): %s", errbuf);
        exit(0);
    }

    pcap_t *pd = pcap_open_offline(argv[1], errbuf);
    if (!pd)
    {
        printf("error: pcap_open_offline(): %s", errbuf);
        exit(0);
    }

    if (pcap_compile(pd, &filter, filter_string, 0, netp) == -1)
    {
        printf("error: pcap_compile() failed");
        exit(0);
    }

    if (pcap_setfilter(pd, &filter) == -1)
    {
        printf("error: pcap_setfilter() failed");
        exit(0);
    }

    pcap_loop(pd, 0, pkt_handler, NULL);

    pcap_close(pd);

    printf("Packet filting done! \n#Incoming ARP packets: %d\n#Outgoing DNS packets: %d\n", arp_cnt, dns_cnt);
    return 0;
}
