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
#include <time.h>

#define MAX_CONNECTION      5       // max connections in the connection window
#define ETHER_HEADER_LEN    14      // ethernet header length
#define ARP_HEADER_LEN      8       // arp header length
#define EST_TIMEOUT         10.0     // timeout for tcp connection establishment
#define TER_TIMEOUT         30.0     // timeout for tcp connection termination 


/*
 * structure for TCP connection between two ends (linked list)
 */
struct connection
{
    uint16_t sport;                 // source port
    uint16_t dport;                 // destination port
    char spa[16];                   // source ip
    char dpa[16];                   // destination ip
    int sstate;                     // source state
    int dstate;                     // destination port
    tcp_seq sseq;                   // source sequence number
    tcp_seq dseq;                   // destination sequence number
    struct connection *next;        // next connection
    struct connection *prev;        // previous connection
    time_t *start_time;             // start time for the timeout
};

/*
 * structure for timer for a connection (linked list)
 */
struct timer
{
    struct connection *conn;         // the connection for the timer
    struct timer *prev;             // previous timer
    struct timer *next;             // next timer
};

/*
 * structure for the body of an arp packet
 */
struct arpbody
{
    u_char ar_sha[6];
    u_char ar_spa[4];
    u_char ar_tha[6];
    u_char ar_tpa[4];
};

int cnt = 0;                    // total packet count
int arp_cnt = 0;                // total arp packet count
int dns_cnt = 0;                // total dns packet count
struct connection conn_win[MAX_CONNECTION];                             // tcp connection window
bool avail_conn[MAX_CONNECTION] = {true, true, true, true, true};       // available connection
struct connection *buf;         // the header for the connection buffer (connection that is being established)
struct connection *cur;         // the current connection
struct timer *timer_list;       // the header for all the timer
struct timer *cur_timer;        // current timer

/*
 * Usage:   Print connection number
 */
void print_connection_number()
{
    int j;
    int c = 0;
    for (j = 0; j < MAX_CONNECTION; j++)
        if (avail_conn[j] == false)
            c++;
    printf("Current connection number: %d\n", c);
}

/*
 * Usage:   Check if a connection is in the buffer
 * Return:  the pointer to the connection if in the buffer
 *          NULL if not
 */
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

/*
 * Usage:   Add a connection being establish in a buffer
 */
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
        cur->sseq = conn.sseq;
        cur->dseq = conn.dseq;
        cur->sstate = conn.sstate;
        cur->dstate = conn.dstate;
        cur->start_time = NULL;
        cur->next = NULL;
    }
}

/*
 * Usage:   Update the states and sequene number in a connection
 */
void update_buf(struct connection *conn, int sstate, int dstate, tcp_seq sseq, tcp_seq dseq)
{
    conn->sstate = sstate;
    conn->dstate = dstate;
    conn->sseq = sseq;
    conn->dseq = dseq;
}

/*
 * Usage:   Remove the connection in the buffer
 */
void rm_buf(struct connection *conn)
{
    if (conn == buf && conn->next != NULL)
    {
        buf = conn->next;
        buf->prev = NULL;
    } else if ((conn == buf && conn->next == NULL) || (conn == cur && conn->prev == NULL))
    {
        buf = cur = NULL;
    } else if (conn == cur && conn->prev != NULL)
    {
        cur = conn->prev;
        cur->next = NULL;
    } else if (conn->prev != NULL && conn->next != NULL)
    {
        conn->prev->next = conn->next;
        conn->next->prev = conn->prev;
    }
    if (conn->start_time != NULL)
        free(conn->start_time);
    free(conn);
}

/*
 * Usage:   Check if there is some available connection window
 * Return:  The index number of the connection window if is not full
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

/*
 * Usage:   Check if a connection is in the connection widnow
 * Return:  the index to the connection if in the window
 *          -1 if not
 */
int is_conn_in_win(struct connection conn)
{
    int i;
    for (i = 0; i < MAX_CONNECTION; i++)
    {
        if (!avail_conn[i])
        {
            //printf("%s      %s     %s      %s      %d      %d      %d      %d\n", conn_win[i].spa, conn.spa, conn_win[i].dpa, conn.dpa, conn_win[i].sport, conn.sport, conn_win[i].dport, conn.dport);
            if ((conn_win[i].sport == conn.sport && conn_win[i].dport == conn.dport && strcmp(conn_win[i].spa, conn.spa) == 0 && strcmp(conn_win[i].dpa, conn.dpa) == 0) ||
                (conn_win[i].sport == conn.dport && conn_win[i].dport == conn.sport && strcmp(conn_win[i].spa, conn.dpa) == 0 && strcmp(conn_win[i].dpa, conn.spa) == 0))
            {
                return i;
            }
        }
    }
    return -1;
}

/*
 * Usage:   Add a connection in the certain position i in the connection window
 */
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
    conn_win[i].sseq = conn.sseq;
    conn_win[i].dseq = conn.dseq;
    conn_win[i].start_time = NULL;
}

/*
 * Usage:   Update connection states and sequence numbers in the connection window
 */
void update_conn(int i, int sstate, int dstate, tcp_seq sseq, tcp_seq dseq)
{
    conn_win[i].sstate = sstate;
    conn_win[i].dstate = dstate;
    conn_win[i].sseq = sseq;
    conn_win[i].dseq = dseq;
}

/*
 * Usage:   Remove the connection in the  window
 */
void rm_conn(int i)
{
    avail_conn[i] = true;
    if (conn_win[i].start_time != NULL)
        free(conn_win[i].start_time);
}

/*
 * Usage:   check if the certain timer of the connection is timeout
 * Return:  true if is timeout
 *          false if is not
 */
bool is_timeout(struct connection *conn, time_t *cur_time, double timeout)
{
    double delta = difftime( *cur_time, *(conn->start_time));
    //printf("time: %f\n", delta);
    if (delta > timeout)
        return true;
    else
        return false;
}

/*
 * Usage:   Check if there have already been a timer for the connection
 * Return:  the pointer to the timer if true
 *          NULL is false
 */
struct timer * is_in_timer(struct connection *conn)
{
    struct timer *ptr = timer_list;
    while (ptr != NULL)
    {
        if (ptr->conn == conn)
        {
            return ptr;
        }
        ptr = ptr->next;
    }
    return NULL;
}

/*
 * Usage:   Remove a certain timer in the timer list
 */
void rm_timer(struct timer *t)
{
    if (t == timer_list && t->next != NULL)
    {
        timer_list = t->next;
        timer_list->prev = NULL;
        free(t);
    } else if ((t == timer_list && t->next == NULL) || (t == cur_timer && t->prev == NULL))
    {
        timer_list = cur_timer = NULL;
        free(t);
    } else if (t == cur_timer && t->prev != NULL)
    {
        cur_timer = t->prev;
        cur_timer->next = NULL;
        free(t);
    } else if (t->prev != NULL && t->next != NULL)
    {
        t->prev->next = t->next;
        t->next->prev = t->prev;
        free(t);
    }
}

/*
 * Usage:   Set the start time of a connection. If there has already been a timer for the connection in the timer list,
 *          just update the start time, if not, add a new timer in the timer list for the connection
 */
void set_start_time(struct connection *conn, time_t *t)
{
    //printf("start a timer\n");
    if (conn->start_time == NULL)
        conn->start_time = (time_t *)calloc(1, sizeof(time_t));
    *(conn->start_time) = *t;

    struct timer *ptr;
    ptr = is_in_timer(conn);
    if (ptr == NULL)
    {
        if ((timer_list == NULL && cur_timer != NULL) || (timer_list != NULL && cur_timer == NULL))
        {
            printf("error: timer_list inconsistent!\n");
            exit(0);
        } else
        {
            if (timer_list == NULL && cur_timer == NULL)
            {
                timer_list = (struct timer *)calloc(1, sizeof(struct timer));
                cur_timer = timer_list;
                cur_timer->prev = NULL;
            } else if (timer_list != NULL && cur_timer != NULL)
            {
                cur_timer->next = (struct timer *)calloc(1, sizeof(struct timer));
                cur_timer->next->prev = cur_timer;
                cur_timer = cur_timer->next;
            }
            cur_timer->conn = conn;
            cur_timer->next = NULL;
        }
    }
}

/*
 * Usage:   Check all the timers in the timer list to see if someone is timeout
 */
void check_timeout(time_t *t)
{
    struct timer *ptr = timer_list;
    while (ptr != NULL)
    {
        struct connection *conn = ptr->conn;
        if (conn->sstate == TCPS_ESTABLISHED && conn->dstate == TCPS_SYN_RECEIVED)
        {
            // if it's a timer for a connection being established
            if (is_timeout(conn, t, EST_TIMEOUT))
            {
                // if conn is timeout
                int chosen_index = is_win_full();
                if (chosen_index >= 0)
                {
                    // if connection window is not full, establish a new connection
                    update_buf(conn, TCPS_ESTABLISHED, TCPS_ESTABLISHED, conn->sseq, conn->dseq);
                    add_conn(chosen_index, *conn);
                    printf("Connection established from %s:%d to %s:%d (timeout)\n", conn->spa, conn->sport, conn->dpa, conn->dport);
                    print_connection_number();
                    rm_buf(conn);
                } else
                {
                    // if connection window is full, discard the connection
                    printf("Connection discarded from %s:%d to %s:%d (timeout but connection window is full)\n", conn->spa, conn->sport, conn->dpa, conn->dport);
                    rm_buf(conn);
                }

                // remove the timeouted timer
                struct timer *tmp;
                if (ptr->next == NULL)
                {
                    rm_timer(ptr);
                    ptr = NULL;
                } else
                {
                    tmp = ptr->next;
                    rm_timer(ptr);
                    ptr = tmp;
                }
            } else
                ptr = ptr->next;
        } else if ((conn->sstate == TCPS_TIME_WAIT && conn->dstate == TCPS_LAST_ACK) || (conn->sstate == TCPS_LAST_ACK && conn->dstate == TCPS_TIME_WAIT))
        {
            // if it is a timer for a connedtion being terminated
            if (is_timeout(conn, t, TER_TIMEOUT))
            {
                // if timeout, remove the connection from the window to terminate it
                printf("Connection terminated (normally) from %s:%d to %s:%d (timeout)\n", conn->spa, conn->sport, conn->dpa, conn->dport);
                int index = is_conn_in_win(*conn);
                if (index >= 0)
                    rm_conn(index);
                print_connection_number();

                struct timer *tmp;
                if (ptr->next == NULL)
                {
                    rm_timer(ptr);
                    ptr = NULL;
                } else
                {
                    tmp = ptr->next;
                    rm_timer(ptr);
                    ptr = tmp;
                }
            }  else
                ptr = ptr->next;
        } else
        {
            ptr = ptr->next;
        }
    }
}

/*
 * Print the ip and mac address in the format of x.x.x.x (x:x:x:x:x:x)
 */
void print_ip_mac(u_char *ip, u_char *mac)
{
    int i;
    int first = 1;
    for (i = 0; i < 4; i++) {
        if (!first)
            printf(".");
        printf("%d", *(ip + i));
        first = 0;
    }
    first = 1;
    printf(" (");
    for (i = 0; i < 6; i++) {
        if (!first)
            printf(":");
        printf("%02X", *(mac + i));
        first = 0;
    }
    printf(")");
}

/*
 * Usage:   Process an arp packet
 */
void process_arp(u_char *dd, const struct pcap_pkthdr *pkthdr, const u_char *data, char *ethernet_sha, char *ethernet_dha)
{
    struct arphdr *arp_header;
    arp_header = (struct arphdr *) (data + ETHER_HEADER_LEN);       // the header for an arp packet
    
    if (ntohs(arp_header->ar_op) == ARPOP_REPLY)
    {
        // if it is a reply arp packet
        arp_cnt++;
        struct arpbody *arp_body;
        arp_body = (struct arpbody *) (data + ETHER_HEADER_LEN + ARP_HEADER_LEN);
        printf("An incoming ARP packet from ");
        print_ip_mac(arp_body->ar_spa, ethernet_sha);
        printf(" to ");
        print_ip_mac(arp_body->ar_tpa, ethernet_dha);
        printf("\n");
        pcap_dump(dd, pkthdr, data);
    }
}

/*
 * Usage:   Process a tcp packet
 */
void process_tcp(u_char *dd, const struct pcap_pkthdr *pkthdr, const u_char *data, u_short hdr_len, u_char *ip_spa, u_char *ip_dpa, char *ethernet_sha, char *ethernet_dha)
{
    struct tcphdr *tcp_header;                                      // tcp packet header
    tcp_header = (struct tcphdr *) (data + ETHER_HEADER_LEN + hdr_len);

    uint16_t tcp_sport = ntohs(tcp_header->th_sport);               // source and destination port of the tcp connection
    uint16_t tcp_dport = ntohs(tcp_header->th_dport);
    if (tcp_dport == 53)
    {
        // if the destination port is 53, the packet is an outgoing DNS packet
        dns_cnt++;
        printf("An outgoing DNS packet from %s:%u (%s) to %s:%u (%s)\n", ip_spa, tcp_sport, ethernet_sha, ip_dpa, tcp_dport, ethernet_dha);
        pcap_dump(dd, pkthdr, data);
    }

    u_char tcp_flags = tcp_header->th_flags & TH_FLAGS;             // get the connection flags, sequence number and ack from the header
    u_char tcp_fin = (tcp_flags & TH_FIN);
    u_char tcp_syn = (tcp_flags & TH_SYN) >> 1;
    u_char tcp_rst = (tcp_flags & TH_RST) >> 2;
    u_char tcp_ack = (tcp_flags & TH_ACK) >> 4;
    tcp_seq seq = ntohl(tcp_header->th_seq);
    tcp_seq ack = ntohl(tcp_header->th_ack);

    struct connection conn;                         // initialize the connection structure
    conn.sport = tcp_sport;
    conn.dport = tcp_dport;
    memset(conn.spa, 0, 16);
    memset(conn.dpa, 0, 16);
    strcpy(conn.spa, ip_spa);
    strcpy(conn.dpa, ip_dpa);
    conn.start_time = NULL;

    check_timeout((time_t *)(&pkthdr->ts.tv_sec));      // check all the timers first

    if (tcp_rst == 1)
    {
        // it rst flag is 1, terminate the connection
        struct connection *ptr = is_conn_in_buf(conn);  // check if the connection in the buffer
        if (ptr != NULL)
        {
            // if the connection in the buffer
            struct timer *tmp = is_in_timer(ptr);       // remove the timer if the connection has some
            if (tmp != NULL)
                rm_timer(tmp);
            rm_buf(ptr);                                // remov the connection form the buffer
        }
        int index = is_conn_in_win(conn);               // check if the connection in the buffer
        if (index >= 0)
        {
            // fi the connection in the window
            printf("Connection terminated (caused by RST) from %s:%d to %s:%d\n", conn_win[index].spa, conn_win[index].sport, conn_win[index].dpa, conn_win[index].dport);
            struct timer *tmp = is_in_timer(&conn_win[index]);      // remove the timer if the connection has some
            if (tmp != NULL)
                rm_timer(tmp);
            rm_conn(index);                             // remove the connection form the window
            print_connection_number();
        }
    } else
    {
        // if rst flag is 0
        char *str = "192.168.1.6";
        if (tcp_syn == 1 && strcmp(ip_spa, str) == 0)
        {
            // if syn flag is 1 (the first packet of three handshake of tcp) and the connection is start from us
            struct connection *ptr;
            ptr = is_conn_in_buf(conn);
            if (ptr == NULL)
            {
                conn.sstate = TCPS_SYN_SENT;
                conn.dstate = TCPS_LISTEN;
                conn.sseq = seq;
                add_buf(conn);                  // add the new connection to the buffer
            }
        } else
        {
            // if it isn't a syn packet from us
            int index = is_conn_in_win(conn);           // check if the connection is established
            if (index >= 0) {
                // if the connection is established
                if (conn_win[index].sstate == TCPS_ESTABLISHED && conn_win[index].dstate == TCPS_ESTABLISHED)
                {
                    // if src and dest state is TCPS_ESTABLISHED
                    if (tcp_fin == 1 && tcp_ack == 1)
                    {
                        // if the a fin packet (the first packet of the four-way handshake), update the states of the connection according to the src of the packet
                        if (conn_win[index].sport == conn.sport && strcmp(conn_win[index].spa, conn.spa) == 0)
                            update_conn(index, TCPS_FIN_WAIT_1, TCPS_ESTABLISHED, seq, conn_win[index].dseq);
                        else if (conn_win[index].sport == conn.dport && strcmp(conn_win[index].spa, conn.dpa) == 0)
                            update_conn(index, TCPS_ESTABLISHED, TCPS_FIN_WAIT_1, conn_win[index].sseq, seq);
                    }
                } else if (conn_win[index].sstate == TCPS_FIN_WAIT_1 && conn_win[index].dstate == TCPS_ESTABLISHED)
                {
                    // if the four-way handshake is from us and is waiting for the second packet
                    if (tcp_ack == 1 /*&& ack == conn_win[index].sseq+1*/)
                        // if receive the second packet, update the connection states
                        update_conn(index, TCPS_FIN_WAIT_2, TCPS_CLOSE_WAIT, conn_win[index].sseq, conn_win[index].dseq);
                    else if (tcp_fin == 1 && tcp_ack == 1 && conn_win[index].dport == conn.dport && strcmp(conn_win[index].dpa, conn.dpa) == 0)
                        // if receive another fin packet from the server, indicate this is a simultaneous closing
                        update_conn(index, TCPS_FIN_WAIT_1, TCPS_FIN_WAIT_1, conn_win[index].sseq, seq);
                } else if (conn_win[index].sstate == TCPS_FIN_WAIT_2 && conn_win[index].dstate == TCPS_CLOSE_WAIT)
                {
                    // if the four-way handshake is from us and is waiting to send the third packet
                    if (tcp_fin == 1 && tcp_ack == 1)
                        // if is sending the third packet, update the connection states
                        update_conn(index, TCPS_FIN_WAIT_2, TCPS_LAST_ACK, conn_win[index].sseq, seq);
                } else if (conn_win[index].sstate == TCPS_FIN_WAIT_2 && conn_win[index].dstate == TCPS_LAST_ACK)
                {
                    // if the four-way handshake is from us and is waiting for the last packet
                    if (tcp_ack == 1 && ack == conn_win[index].dseq+1)
                    {
                        // if receive the last packet, update the connection states and start a timer for the termination
                        update_conn(index, TCPS_TIME_WAIT, TCPS_LAST_ACK, conn_win[index].sseq, conn_win[index].dseq);
                        set_start_time(&conn_win[index], (time_t *)(&pkthdr->ts.tv_sec));
                    } 
                } else if (conn_win[index].sstate == TCPS_TIME_WAIT && conn_win[index].dstate == TCPS_LAST_ACK)
                {
                    // the connection is waiting to be closed
                    if ((tcp_fin == 1 && tcp_ack == 1) && strcmp(conn_win[index].dpa, conn.spa) == 0 && conn_win[index].dport == conn.sport)
                        // the final packet is lost, and a retransmission packet is receiverd, roll back the state
                        update_conn(index, TCPS_FIN_WAIT_2, TCPS_LAST_ACK, conn_win[index].sseq, seq);
                } else if (conn_win[index].sstate == TCPS_ESTABLISHED && conn_win[index].dstate == TCPS_FIN_WAIT_1)
                {
                    // if the four-way handshake is from the server and is waiting to the second packet
                    if (tcp_ack == 1 /*&& ack == conn_win[index].dseq+1*/)
                        // if is sending the second packet, update the connection states
                        update_conn(index, TCPS_CLOSE_WAIT, TCPS_FIN_WAIT_2, conn_win[index].sseq, conn_win[index].dseq);
                    else if (tcp_fin == 1 && tcp_ack == 1 && conn_win[index].sport == conn.sport && strcmp(conn_win[index].spa, conn.spa) == 0)
                        // if send another fin packet from us, indicate this is a simultaneous closing
                        update_conn(index, TCPS_FIN_WAIT_1, TCPS_FIN_WAIT_1, seq, conn_win[index].dseq);
                } else if (conn_win[index].sstate == TCPS_CLOSE_WAIT && conn_win[index].dstate == TCPS_FIN_WAIT_2)
                {
                    // if the four-way handshake is from the server and is waiting for the third packet
                    if (tcp_fin == 1 && tcp_ack == 1)
                        // if receive the third packet, update the connection states
                        update_conn(index, TCPS_LAST_ACK, TCPS_FIN_WAIT_2, seq, conn_win[index].dseq);
                } else if (conn_win[index].sstate == TCPS_LAST_ACK && conn_win[index].dstate == TCPS_FIN_WAIT_2)
                {
                    // if the four-way handshake is from the server and is waiting send the last packet
                    if (tcp_ack == 1 && ack == conn_win[index].sseq+1)
                    {
                        // if is sending the last packet, update the connection states and start a timer for the termination
                        update_conn(index, TCPS_LAST_ACK, TCPS_TIME_WAIT, conn_win[index].sseq, conn_win[index].dseq);
                        set_start_time(&conn_win[index], (time_t *)(&pkthdr->ts.tv_sec));
                    } 
                } else if (conn_win[index].sstate == TCPS_LAST_ACK && conn_win[index].dstate == TCPS_TIME_WAIT)
                {
                    // the connection is waiting to be closed
                    if ((tcp_fin == 1 && tcp_ack == 1) && strcmp(conn_win[index].spa, conn.spa) == 0 && conn_win[index].sport == conn.sport)
                        // the final packet is lost, and a retransmission packet is receiverd, roll back the state
                        update_conn(index, TCPS_LAST_ACK, TCPS_FIN_WAIT_2, seq, conn_win[index].dseq);
                } else if (conn_win[index].sstate == TCPS_FIN_WAIT_1 && conn_win[index].dstate == TCPS_FIN_WAIT_1)
                {
                    // if src and dest state is TCPS_FIN_WAIT_1, the connection is being simultaneously closing
                    if (conn_win[index].sport == conn.sport && strcmp(conn_win[index].spa, conn.spa) == 0)
                    {
                        // if the packet is sent from us
                        if (tcp_ack == 1 && ack == conn_win[index].dseq+1)
                        {
                            // if the packet is the ack packet to the fin, update the server (dest) state to TCPS_TIME_WAIT and start a timer for termination
                            update_conn(index, TCPS_CLOSING, TCPS_TIME_WAIT, conn_win[index].sseq, conn_win[index].dseq);
                            set_start_time(&conn_win[index], (time_t *)(&pkthdr->ts.tv_sec));
                        }
                    } else if (conn_win[index].sport == conn.dport && strcmp(conn_win[index].spa, conn.dpa) == 0)
                    {
                        // if the packet is sent from the server
                        if (tcp_ack == 1 && ack == conn_win[index].sseq+1)
                        {
                            // if the packet is the ack packet to the fin, update the our (src) state to TCPS_TIME_WAIT and start a timer for termination
                            update_conn(index, TCPS_TIME_WAIT, TCPS_CLOSING, conn_win[index].sseq, conn_win[index].dseq);
                            set_start_time(&conn_win[index], (time_t *)(&pkthdr->ts.tv_sec));
                        }
                    }
                } else if (conn_win[index].sstate == TCPS_CLOSING && conn_win[index].dstate == TCPS_TIME_WAIT)
                {
                    // when simultaneously closing and the server is waiting for the ack packet
                    if (tcp_ack == 1 && ack == conn_win[index].sseq+1 && conn_win[index].sport == conn.sport && strcmp(conn_win[index].spa, conn.spa) == 0)
                    {
                        // the other ack packet packet is send from us, both are reaching the state of TCPS_TIME_WAIT, update the start time of the timer
                        update_conn(index, TCPS_TIME_WAIT, TCPS_TIME_WAIT, conn_win[index].sseq, conn_win[index].dseq);
                        set_start_time(&conn_win[index], (time_t *)(&pkthdr->ts.tv_sec));
                    } else if (tcp_fin == 1 && tcp_ack == 1)
                        // the first ack packet is lost, and a retransmission packet is sent or received, roll back the state
                        update_conn(index, TCPS_FIN_WAIT_1, TCPS_FIN_WAIT_1, conn_win[index].sseq, conn_win[index].dseq);
                } else if (conn_win[index].sstate == TCPS_TIME_WAIT && conn_win[index].dstate == TCPS_CLOSING)
                {
                    // when simultaneously closing and we are waiting for the ack packet
                    if (tcp_ack == 1 && ack == conn_win[index].dseq+1 && conn_win[index].sport == conn.dport && strcmp(conn_win[index].spa, conn.dpa) == 0)
                    {
                        // the other ack packet packet is send from the server, both are reaching the state of TCPS_TIME_WAIT, update the start time of the timer
                        update_conn(index, TCPS_TIME_WAIT, TCPS_TIME_WAIT, conn_win[index].sseq, conn_win[index].dseq);
                        set_start_time(&conn_win[index], (time_t *)(&pkthdr->ts.tv_sec));
                    } else if (tcp_fin == 1 && tcp_ack == 1)
                        // the first ack packet is lost, and a retransmission packet is sent or received, roll back the state
                        update_conn(index, TCPS_FIN_WAIT_1, TCPS_FIN_WAIT_1, conn_win[index].sseq, conn_win[index].dseq);
                } else if (conn_win[index].sstate == TCPS_TIME_WAIT && conn_win[index].dstate == TCPS_TIME_WAIT)
                {
                    // if both are waiting for the timeout 
                    if (tcp_fin == 1 && tcp_ack == 1 && conn_win[index].sport == conn.sport && strcmp(conn_win[index].spa, conn.spa) == 0)
                        // the second ack packet is lost, and a retransmission packet is sent from us, roll back the state
                        update_conn(index, TCPS_CLOSING, TCPS_TIME_WAIT, conn_win[index].sseq, conn_win[index].dseq);
                    else if (tcp_fin == 1 && tcp_ack == 1 && conn_win[index].sport == conn.dport && strcmp(conn_win[index].spa, conn.dpa) == 0)
                        // the second ack packet is lost, and a retransmission packet is sent from the server, roll back the state
                        update_conn(index, TCPS_TIME_WAIT, TCPS_CLOSING, conn_win[index].sseq, conn_win[index].dseq);
                }
            } else
            {
                // if the connection is being established
                struct connection * ptr = is_conn_in_buf(conn);         // the connection should be in the buffer
                if (ptr != NULL)
                {
                    // if the connection is in the buffer
                    if (ptr->sstate == TCPS_SYN_SENT && ptr->dstate == TCPS_LISTEN)
                    {
                        // if is wait for the second packet for the three handshake (the syn/ack packet from the server)
                        if (tcp_syn == 1 && tcp_ack == 1 && ack == ptr->sseq+1)
                            // if it is the second packet, update the state
                            update_buf(ptr, TCPS_SYN_SENT, TCPS_SYN_RECEIVED, ptr->sseq, seq);\
                    } else if (ptr->sstate == TCPS_SYN_SENT && ptr->dstate == TCPS_SYN_RECEIVED)
                    {
                        // if is wait for the last packet for the three handshake (the ack packet from us)
                        if (tcp_ack == 1 && ack == ptr->dseq+1)
                        {
                            // if it is the second packet, update the state, and start a timer for the connection establishment
                            update_buf(ptr, TCPS_ESTABLISHED, TCPS_SYN_RECEIVED, ptr->sseq, ptr->dseq);
                            set_start_time(ptr, (time_t *)(&pkthdr->ts.tv_sec));
                        }
                    } else if (ptr->sstate == TCPS_ESTABLISHED && ptr->dstate == TCPS_SYN_RECEIVED)
                    {
                        // if is waiting for the timeout
                        if (!(tcp_syn == 1 && tcp_ack == 1) && strcmp(ptr->dpa, conn.spa) == 0 && ptr->dport == conn.sport)
                        {
                            // if is not reach the timeout, be we get a normal data packet from the server, indicating the server has received final packet and the connection is established
                            int chosen_index = is_win_full();           // check if the connection window is full
                            if (chosen_index >= 0)
                            {
                                // if the window is not full, establish a new connection, move the connection from the buffer to the window 
                                update_buf(ptr, TCPS_ESTABLISHED, TCPS_ESTABLISHED, ptr->sseq, ptr->dseq);
                                add_conn(chosen_index, *ptr);
                                printf("Connection established from %s:%d to %s:%d (received a incoming data packet before timeout)\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
                                print_connection_number();
                                struct timer *tmp = is_in_timer(ptr);         // if the connection has start a timer, remove it
                                if (tmp != NULL)
                                    rm_timer(tmp);
                                rm_buf(ptr);
                            } else
                            {
                                // if the window is full, discard the connection
                                printf("Connection discarded from %s:%d to %s:%d (received a incoming data packet before timeout but connection window is full)\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
                                struct timer *tmp = is_in_timer(ptr);         // if the connection has start a timer, remove it
                                if (tmp != NULL)
                                    rm_timer(tmp);
                                rm_buf(ptr);
                            }
                        } else if ((tcp_syn == 1 && tcp_ack == 1 && ack == ptr->sseq+1) && strcmp(ptr->dpa, conn.spa) == 0 && ptr->dpa == conn.dpa)
                        {
                            // if received a retransmission packet, roll back the state
                            update_buf(ptr, TCPS_SYN_SENT, TCPS_SYN_RECEIVED, ptr->sseq, seq);
                        } else if (tcp_fin == 1 && tcp_ack == 1)
                        {
                            // if before the timeout, the first four-way handshake packet is send or received
                            int chosen_index = is_win_full();       // check the window is full
                            if (chosen_index >= 0)
                            {
                                // if the window is not full, establish a new connection, move the connection from the buffer to the window
                                update_buf(ptr, TCPS_ESTABLISHED, TCPS_ESTABLISHED, ptr->sseq, ptr->dseq);
                                add_conn(chosen_index, *ptr);
                                printf("Connection established from %s:%d to %s:%d (received a fin packet before timeout)\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
                                print_connection_number();
                                struct timer *tmp = is_in_timer(ptr);         // if the connection has start a timer, remove it
                                if (tmp != NULL)
                                    rm_timer(tmp);
                                rm_buf(ptr);

                                // update the state for sent or received the first four-way handshake packet*/
                                if (conn_win[chosen_index].sport == conn.sport && strcmp(conn_win[chosen_index].spa, conn.spa) == 0)
                                    update_conn(chosen_index, TCPS_FIN_WAIT_1, TCPS_ESTABLISHED, seq, conn_win[chosen_index].dseq);
                                else if (conn_win[chosen_index].sport == conn.dport && strcmp(conn_win[chosen_index].spa, conn.dpa) == 0)
                                    update_conn(chosen_index, TCPS_ESTABLISHED, TCPS_FIN_WAIT_1, conn_win[chosen_index].sseq, seq);
                            } else
                            {
                                // if the window is full, discard the connection
                                printf("Connection discarded from %s:%d to %s:%d (received a fin packet before timeout)\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
                                struct timer *tmp = is_in_timer(ptr);         // if the connection has start a timer, remove it
                                if (tmp != NULL)
                                    rm_timer(tmp);
                                rm_buf(ptr);
                            }
                        }
                    }
                }
            }
        }
    }
}

/*
 * Usage:   Process a udp packet
 */
void process_udp(u_char *dd, const struct pcap_pkthdr *pkthdr, const u_char *data, u_short hdr_len, u_char *ip_spa, u_char *ip_dpa, char *ethernet_sha, char *ethernet_dha)
{
    struct udphdr *udp_header;                                      // udp header
    udp_header = (struct udphdr *) (data + ETHER_HEADER_LEN + hdr_len);

    uint16_t udp_sport = ntohs(udp_header->uh_sport);               // source and destination port of the udp connection
    uint16_t udp_dport = ntohs(udp_header->uh_dport);
    if (udp_dport == 53)
    {
        // if the destination port is 53, the packet is an outgoing packet
        dns_cnt++;
        printf("An outgoing DNS packet from %s:%u (%s) to %s:%u (%s)\n", ip_spa, udp_sport, ethernet_sha, ip_dpa, udp_dport, ethernet_dha);
        pcap_dump(dd, pkthdr, data);
    }
}

/*
 * Usage:   Process an ip packet
 */
void process_ip(u_char *dd, const struct pcap_pkthdr *pkthdr, const u_char *data, char *ethernet_sha, char *ethernet_dha)
{
    struct ip *ip_header;                                               // ip packet header
    ip_header = (struct ip *) (data + ETHER_HEADER_LEN);

    u_short hdr_len = ((u_short)IP_VHL_HL(ip_header->ip_vhl) << 2);     // calculate the length of the ip packet header
    u_char ip_spa[16];                                                    // get source and destination ip address from the header
    u_char ip_dpa[16];
    strcpy(ip_spa, inet_ntoa(ip_header->ip_src));
    strcpy(ip_dpa, inet_ntoa(ip_header->ip_dst));

    u_char protocol = ip_header->ip_p;                                  // get the protocol of the packet
    if (protocol == 6)
    {
        // if it is a tcp packet
        process_tcp(dd, pkthdr, data, hdr_len, ip_spa, ip_dpa, ethernet_sha, ethernet_dha);
    } else if (protocol == 17)
    {
        // if it is a udp packet
        process_udp(dd, pkthdr, data, hdr_len, ip_spa, ip_dpa, ethernet_sha, ethernet_dha);
    }
}

/*
 * Usage: The packet handler, process every packet filtered out from the filter program
 */
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
        // if the packet is a arp packet
        process_arp(dd, pkthdr, data, ethernet_sha, ethernet_dha);
    } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        // if the packet is a ip packet
        process_ip(dd, pkthdr, data, ethernet_sha, ethernet_dha);
    }
}

int main(int argc,  char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];                          // error buffer for pcap error
    /*char *dev;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    char *net;*/

    char *filter_string = "arp or ((tcp or udp) and dst port 53) or tcp";    // setting for packet filter, filter out all arp, dns and tcp packets
    //char *filter_string = "arp";

    struct bpf_program filter;                              // the filter program

    //struct in_addr addr;


    buf = cur = timer_list = cur_timer = NULL;

    pcap_t *pd = pcap_open_offline(argv[1], errbuf);        // open the recorded packet file
    if (!pd)
    {
        printf("error: pcap_open_offline(): %s", errbuf);
        exit(0);
    }

    pcap_dumper_t *dd = pcap_dump_open(pd, "filtered.pcap");    // open dump file
    if (!dd)
    {
        printf("error: pcap_dump_open() failed\n");
        exit(0);
    }

    if (pcap_compile(pd, &filter, filter_string, 0, NULL) == -1)    // compile the filter program
    {
        printf("error: pcap_compile() failed");
        exit(0);
    }

    if (pcap_setfilter(pd, &filter) == -1)                  // set the filter
    {
        printf("error: pcap_setfilter() failed");
        exit(0);
    }

    pcap_loop(pd, 0, pkt_handler, (u_char *)dd);            // the packet processing loop

    pcap_close(pd);                                         // close recorded packet file
    pcap_dump_close(dd);                                    // close dump file

    struct connection *ptr = buf;                           // print all connection still in the buffer
    while (ptr != NULL)
    {
        printf("Connection from %s:%d to %s:%d is still waiting to be established\n", ptr->spa, ptr->sport, ptr->dpa, ptr->dport);
        ptr = ptr->next;
    }

    printf("Packet filtering done! \n#Incoming ARP packets: %d\n#Outgoing DNS packets: %d\n", arp_cnt, dns_cnt);    // print result

    if (buf != NULL)
        free(buf);
    if (timer_list != NULL)
        free(timer_list);
    return 0;
}
