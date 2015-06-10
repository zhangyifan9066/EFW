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
#include <netinet/tcp_fsm.h>
#include <string.h>
#include <stdbool.h>

#define MAX_CONNECTION      5
#define ETHER_HEADER_LEN    14
#define ARP_HEADER_LEN      8
//#define _IP_VHL             1

struct connection
{
    uint16_t sport;
    uint16_t dport;
    char spa[16];
    char dpa[16];
    int sstate;
    int dstate;
    tcp_seq seq;
    //tcp_seq ack;
    struct connection *next;
    struct connection *prev;
};

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
struct connection conn_win[MAX_CONNECTION];
bool avail_conn[MAX_CONNECTION] = {true, true, true, true, true};
struct connection *buf;
struct connection *cur;

void add_buf(struct connection conn)
{
    if ((buf == NULL && cur != NULL) || (buf != NULL && cur == NULL))
    {
        printf("error: buf inconsistent!\n");
        exit(0);
    } else
    {
        if (buf == NULL && cur == NULL)
        {
            buf = (struct connection *)calloc(1, sizeof(struct connection));
            cur = buf;
            cur->prev = NULL;
        } else if (buf != NULL && cur != NULL)
        {
            cur->next = (struct connection *)calloc(1, sizeof(struct connection));
            cur->next->prev = cur;
            cur = cur->next;
        }
        cur->sport = conn.sport;
        cur->dport = conn.dport;
        strcpy(cur->spa, conn.spa);
        strcpy(cur->dpa, conn.dpa);
        cur->seq = conn.seq;
        cur->sstate = conn.sstate;
        cur->dstate = conn.dstate;
        cur->next = NULL;
    }
}

struct connection * is_conn_in_buf (struct connection conn)
{
    struct connection *ptr = buf;
    while (ptr != NULL)
    {
        if ((ptr->sport == conn.sport && ptr->dport == conn.dport && strcmp(ptr->spa, conn.spa) == 0 && strcmp(ptr->dpa, conn.dpa) == 0) ||
            (ptr->sport == conn.dport && ptr->dport == conn.sport && strcmp(ptr->spa, conn.dpa) == 0 && strcmp(ptr->dpa, conn.spa) == 0))
        {
            return ptr;
        }
        ptr = ptr->next;
    }
    return NULL;
}

void update_buf(struct connection *conn, int sstate, int dstate, tcp_seq seq)
{
    conn->sstate = sstate;
    conn->dstate = dstate;
    conn->seq = seq;
}

void rm_buf(struct connection *conn)
{
    if (conn == buf && conn->next != NULL)
    {
        buf = conn->next;
        buf->prev = NULL;
        free(conn);
    } else if ((conn == buf && conn->next == NULL) || (conn == cur && conn->prev == NULL))
    {
        buf = cur = NULL;
        free(conn);
    } else if (conn == cur && conn->prev != NULL)
    {
        cur = conn->prev;
        cur->next = NULL;
        free(conn);
    } else if (conn->prev != NULL && conn->next != NULL)
    {
        conn->prev->next = conn->next;
        conn->next->prev = conn->prev;
        free(conn);
    }
}

void clear_buf()
{
    struct connection *ptr = buf;
    while (ptr != NULL)
    {
        struct connection *tmp = ptr->next;
        free(ptr);
        ptr = tmp;
    }
    cur = NULL;
}

/*
 * Usage:   Judge if there is some available connection slot
 * Return:  The index number of the connection slot if is not full
 *          0 if is full
 */
int is_win_full()
{
    int i;
    for (i = 0; i < MAX_CONNECTION; i++)
    {
        if (avail_conn[i])
            return i;
    }
    return -1;
}

int is_conn_in_win(struct connection conn)
{
    int i;
    for (i = 0; i < MAX_CONNECTION; i++)
    {
        if (!avail_conn[i])
        {
            if ((conn_win[i].sport == conn.sport && conn_win[i].dport == conn.dport && strcmp(conn_win[i].spa, conn.spa) == 0 && strcmp(conn_win[i].dpa, conn.dpa) == 0) ||
                (conn_win[i].sport == conn.dport && conn_win[i].dport == conn.sport && strcmp(conn_win[i].spa, conn.dpa) == 0 && strcmp(conn_win[i].dpa, conn.spa) == 0))
            {
                return i;
            }
        }
    }
    return -1;
}

void add_conn(int i, struct connection conn)
{
    avail_conn[i] = false;
    conn_win[i].sport = conn.sport;
    conn_win[i].dport = conn.dport;
    memset(conn_win[i].spa, 0, 16);
    memset(conn_win[i].dpa, 0, 16);
    strcpy(conn_win[i].spa, conn.spa);
    strcpy(conn_win[i].dpa, conn.dpa);
    conn_win[i].sstate = conn.sstate;
    conn_win[i].dstate = conn.dstate;
    conn_win[i].seq = conn.seq;
}

void update_conn(int i, int sstate, int dstate, tcp_seq seq)
{
    conn_win[i].sstate = sstate;
    conn_win[i].dstate = dstate;
    conn_win[i].seq = seq;
}

void rm_conn(int i)
{
    avail_conn[i] = true;
}

u_short judge_ethernet(const u_char *data)
{
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *) data;
    return ethernet_header->ether_type;
}

void pkt_handler(u_char *dd, const struct pcap_pkthdr *pkthdr, const u_char *data)
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
            pcap_dump(dd, pkthdr, data);
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
        char ip_spa[16];// = inet_ntoa(ip_header->ip_src);
        char ip_dpa[16];// = inet_ntoa(ip_header->ip_dst);
        strcpy(ip_spa, inet_ntoa(ip_header->ip_src));
        strcpy(ip_dpa, inet_ntoa(ip_header->ip_dst));
        //printf("%s   %s\n", ip_spa, ip_dpa);
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
                pcap_dump(dd, pkthdr, data);
                //printf("dns in tcp");
            }

            u_char tcp_flags = tcp_header->th_flags & TH_FLAGS;
            u_char tcp_fin = (tcp_flags & TH_FIN);
            u_char tcp_syn = (tcp_flags & TH_SYN) >> 1;
            u_char tcp_rst = (tcp_flags & TH_RST) >> 2;
            u_char tcp_ack = (tcp_flags & TH_ACK) >> 4;
            tcp_seq seq = ntohl(tcp_header->th_seq);
            tcp_seq ack = ntohl(tcp_header->th_ack);

            //printf("flags: %u\n", tcp_flags); 

            struct connection conn;
            conn.sport = tcp_sport;
            conn.dport = tcp_dport;
            memset(conn.spa, 0, 16);
            memset(conn.dpa, 0, 16);
            strcpy(conn.spa, ip_spa);
            strcpy(conn.dpa, ip_dpa);
            conn.seq = seq;

            //printf("fin %u; syn %u; rst %u; ack %u    flags %u    ip: %s   tip: %s\n", tcp_fin, tcp_syn, tcp_rst, tcp_ack, tcp_flags, ip_spa, arg);
            //if (tcp_flags == 18)
            //printf("from: %s:%u to %s:%u  flag: %u  seq: %u\n", ip_spa, tcp_sport, ip_dpa, tcp_dport, tcp_flags, seq);
            //printf ("arg: %s     ip_spa: %s\n", arg, ip_spa);
            //printf("%s\n", ip_spa);

            if (tcp_rst == 1)
            {
                struct connection *ptr = is_conn_in_buf(conn);
                if (ptr != NULL)
                    rm_buf(ptr);
                int index = is_conn_in_win(conn);
                if (index >= 0)
                {
                    printf("Connection terminated (caused by RST) from %s:%d to %s:%d\n", conn_win[index].spa, conn_win[index].sport, conn_win[index].dpa, conn_win[index].dport);
                    rm_conn(index);
                }
            } else
            {
                char *str = "192.168.1.6";
                if (tcp_syn == 1 && strcmp(ip_spa, str) == 0)
                {
                    //printf("tcp_syn == 1\n");
                    //if (strcmp(ip_spa, str) == 0)
                    //{
                        conn.sstate = TCPS_SYN_SENT;
                        conn.dstate = TCPS_CLOSED;
                        add_buf(conn);
                        //printf("from: %s:%u to %s:%u  flag: %u  seq: %u\n", ip_spa, tcp_sport, ip_dpa, tcp_dport, tcp_flags, seq);
                    //}
                } else
                {
                    //printf("tcp_syn != 1\n");
                    //if (tcp_flags == 18)
                        //printf("1\n");
                    int index = is_conn_in_win(conn);
                    if (index >= 0) {
                        if (conn_win[index].sstate == TCPS_ESTABLISHED && conn_win[index].dstate == TCPS_ESTABLISHED)
                        {
                            if (tcp_fin == 1 && tcp_ack == 1)
                            {
                                if (conn_win[index].sport == conn.sport && strcmp(conn_win[index].spa, conn.spa) == 0)
                                    update_conn(index, TCPS_FIN_WAIT_1, TCPS_ESTABLISHED, conn.seq);
                                else if (conn_win[index].sport == conn.dport && strcmp(conn_win[index].spa, conn.dpa) == 0)
                                    update_conn(index, TCPS_ESTABLISHED, TCPS_FIN_WAIT_1, conn.seq);
                                else
                                    conn_win[index].seq = conn.seq;
                            } else
                                conn_win[index].seq = conn.seq;
                        } else if (conn_win[index].sstate == TCPS_FIN_WAIT_1 && conn_win[index].dstate == TCPS_ESTABLISHED)
                        {
                            if (tcp_ack == 1 && ack == conn_win[index].seq+1)
                                update_conn(index, TCPS_FIN_WAIT_2, TCPS_CLOSE_WAIT, conn.seq);
                            else
                                conn_win[index].seq = conn.seq;
                        } else if (conn_win[index].sstate == TCPS_FIN_WAIT_2 && conn_win[index].dstate == TCPS_CLOSE_WAIT)
                        {
                            if (tcp_fin == 1 && tcp_ack == 1)
                                update_conn(index, TCPS_FIN_WAIT_2, TCPS_LAST_ACK, conn.seq);
                            else
                                conn_win[index].seq = conn.seq;
                        } else if (conn_win[index].sstate == TCPS_FIN_WAIT_2 && conn_win[index].dstate == TCPS_LAST_ACK)
                        {
                            if (tcp_ack == 1 && ack == conn_win[index].seq+1)
                            {
                                update_conn(index, TCPS_TIME_WAIT, TCPS_CLOSED, conn.seq);
                                printf("Connection terminated from %s:%d to %s:%d\n", conn_win[index].spa, conn_win[index].sport, conn_win[index].dpa, conn_win[index].dport);
                                rm_conn(index);
                            } else
                                conn_win[index].seq = conn.seq;
                        } else if (conn_win[index].sstate == TCPS_ESTABLISHED && conn_win[index].dstate == TCPS_FIN_WAIT_1)
                        {
                            if (tcp_ack == 1 && ack == conn_win[index].seq+1)
                                update_conn(index, TCPS_CLOSE_WAIT, TCPS_FIN_WAIT_2, conn.seq);
                            else
                                conn_win[index].seq = conn.seq;
                        } else if (conn_win[index].sstate == TCPS_CLOSE_WAIT && conn_win[index].dstate == TCPS_FIN_WAIT_2)
                        {
                            if (tcp_fin == 1 && tcp_ack == 1)
                                update_conn(index, TCPS_LAST_ACK, TCPS_FIN_WAIT_2, conn.seq);
                            else
                                conn_win[index].seq = conn.seq;
                        } else if (conn_win[index].sstate == TCPS_LAST_ACK && conn_win[index].dstate == TCPS_FIN_WAIT_2)
                        {
                            if (tcp_ack == 1 && ack == conn_win[index].seq+1)
                            {
                                update_conn(index, TCPS_CLOSED, TCPS_TIME_WAIT, conn.seq);
                                printf("Connection terminated from %s:%d to %s:%d\n", conn_win[index].spa, conn_win[index].sport, conn_win[index].dpa, conn_win[index].dport);
                                rm_conn(index);
                            } else
                                conn_win[index].seq = conn.seq;
                        }
                    } else
                    {
                        //if (tcp_flags == 18)
                            //printf("2\n");
                            //printf("from: %s:%u to %s:%u  flag: %u  seq: %u\n", ip_spa, tcp_sport, ip_dpa, tcp_dport, tcp_flags, seq);
                        struct connection * ptr = is_conn_in_buf(conn);
                        if (ptr != NULL)
                        {
                            //if (tcp_flags == 18)
                                //printf("3\n");
                            if (ptr->sstate == TCPS_SYN_SENT && ptr->dstate == TCPS_CLOSED)
                            {
                                //if (tcp_flags == 18)
                                    //printf("4\n");
            //printf("!!!!!!!!!from: %s:%u to %s:%u  flag: %u  seq: %u\n", ip_spa, tcp_sport, ip_dpa, tcp_dport, tcp_flags, seq);
                                if (tcp_syn == 1 && tcp_ack == 1 && ack == ptr->seq+1)
                                    update_buf(ptr, TCPS_SYN_SENT, TCPS_SYN_RECEIVED, conn.seq);
                                else
                                    ptr->seq = conn.seq;
                            } else if (ptr->sstate == TCPS_SYN_SENT && ptr->dstate == TCPS_SYN_RECEIVED)
                            {
                                if (tcp_ack == 1 && ack == ptr->seq+1)
                                {
                                    update_buf(ptr, TCPS_ESTABLISHED, TCPS_SYN_RECEIVED, conn.seq);
                                    int chosen_index = is_win_full();
                                    if (chosen_index >= 0)
                                    {
                                        update_buf(ptr, TCPS_ESTABLISHED, TCPS_ESTABLISHED, conn.seq);
                                        add_conn(chosen_index, *ptr);
                                        printf("Connection established from %s:%d to %s:%d\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
                                        int j;
                                        int c = 0;
                                        for (j = 0; j < MAX_CONNECTION; j++)
                                            if (avail_conn[j] == false)
                                                c++;
                                        printf("Current connection number: %d\n", c);
                                        //printf("Connection established from %s:%d to %s:%d\n", conn_win[chosen_index].spa, conn_win[chosen_index].sport, conn_win[chosen_index].dpa, conn_win[chosen_index].dport);
                                        rm_buf(ptr);
                                    } else
                                    {
                                        printf("Connection discarded from %s:%d to %s:%d\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
                                        rm_buf(ptr);
                                    }
                                } else
                                    ptr->seq = conn.seq;
                            } else
                            {
                                ptr->seq = conn.seq;
                            }
                        }
                    }
                }
            }

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
                pcap_dump(dd, pkthdr, data);
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
    char *net;

    char *filter_string = "arp or (dst port 53) or tcp";
    //char *filter_string = "arp";

    struct bpf_program filter;

    struct in_addr addr;


    buf = (struct connection *)calloc(1, sizeof(struct connection));
    cur = buf;

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
    addr.s_addr = netp;
    net = inet_ntoa(addr);

    pcap_t *pd = pcap_open_offline(argv[1], errbuf);
    if (!pd)
    {
        printf("error: pcap_open_offline(): %s", errbuf);
        exit(0);
    }

    pcap_dumper_t *dd = pcap_dump_open(pd, "dump.pcap");
    if (!dd)
    {
        printf("error: pcap_dump_open() failed\n");
        exit(0);
    }

    if (pcap_compile(pd, &filter, filter_string, 0, (u_char *)netp) == -1)
    {
        printf("error: pcap_compile() failed");
        exit(0);
    }

    if (pcap_setfilter(pd, &filter) == -1)
    {
        printf("error: pcap_setfilter() failed");
        exit(0);
    }

    printf("the net is %s\n", net);
    pcap_loop(pd, 0, pkt_handler, (u_char *)dd);

    pcap_close(pd);
    pcap_dump_close(dd);

    printf("Packet filting done! \n#Incoming ARP packets: %d\n#Outgoing DNS packets: %d\n", arp_cnt, dns_cnt);

    free(buf);
    return 0;
}
