#<center>EFW</center>

<center>Zhang Yifan  5110379066</center>
<center>Yan Fangge   5110378056</center>

###Description
In this project, we've implemented an emulated firewall called **EFW** that filters out certain packets and limits up to 5 TCP connections. The implementation is powered by **tcpdump** and **libpcap**. *tcpdump* is being used to record all the packets on the network interface as a sample for further processing. *libpcap* is the main library we rely on to do the packet processing and filtering.

The program reads the recorded packets from *dump.pcap*, then filters out all the incoming **ARP** packets and outgoing **DNS** packets, dumps them to the *filtered.pcap*. EFW tracks the establishment and termination of every *TCP* connections so that it can precisely limits the total connection number.

* *Establishment*: If and only if the connection has gone through the whole process of **three-way handshake** for a TCP establishment.
* *Termination*: If and only if the connection has gone through the whole process of **four-way handshake** for a TCP termination or one part of the connection sent a **RST** packet.

Our implementation for connection limitation is based on a **finite state machine**. We take the retransmission and timeout for TCP EST/TER into consideration in EFW, which makes the emulation to be more realistic.

Here's all the files included in the project.

* *grab.sh*: A script to grab packets from the network interface using tcpdump.
* *efw.c*: The main implementation for EFW.
* *dump.pcap*: The dumped packets file.
* *filtered.pcap*: The filtered out packets by EFW.
* *result.txt*: The output of file of EFW.
* *makefile*: Makefile for EFW.

Usage:

    $ sudo ./grab.sh dump.pcap
    $ sudo ./efw dump.pcap > result.txt

###Design

####Packet Recording

To record the packets going through the network interface, we leverage the tool *tcpdump* to finish the job. In the *grab.sh*, we first run the *tcpdump* in the background.

    tcpdump -i en0 -w $1 &

*en0* is the name of the network interface on our computer, *$1* is the argument pass to *grab.sh*, which should be the recorded file we are writing to.

We need to filter out ARP and DNS packet in the recorded file as required. But we find that if we don't clean the local ARP table or the DNS cache, there will be very little target packets. So we explicitly clean the table and cache in the script to get more ARP or DNS packet. The clean work is done in turn for every 10 seconds.

    arp -d -a     // clean the local arp translation table
    sleep 10;
    discoveryutil mdnsflushcache  // clean the local dns cache (for Mac Yosemite)
    sleep 10;

*tcpdump* runs for 5 minutes. For the dump.pcap, we've visited several websites listed below to increase the total recorded packets.

* *www.sjtu.edu.cn*
* *www.baidu.com*
* *www.sina.com.cn*
* *www.github.com*
* *www.tcpdump.org*
* *www.youku.com*
* *www.taobao.com*
* *www.jd.com*
* *www.amazon.cn*
* *www.hzbook.com*
* *www.ifeng.com*
* *www.google.com.hk*
* ...

####Firewall implementation

We use *libpcap* to implement our firewall. *libpcap* provides many helpful functions to process the packets. We first call `pcap_open_offline()` to open the recorded packet file *dump.pcap*, then `pcap_loop()` continuously reads packets from the file and lets `pkt_handler()`, which is a callback function to `pcap_loop()`, process them.

As to the requirement, our target packets includes the incoming ARP packets, the outgoing DNS packets and all TCP packets. So before processing every recorded packet, we can do a coarse-grained filtering by leveraging the *BPF* programs. This is a filter program supported by *libpcap*. We just need to set the filter expression of the filter program and call a function to compile it. Then, `pcap_loop()` will only hand over the packets that satisfy the filter expression to `pkt_handler()`. So we can focus the target packets to do further process in the next step. The filter expression is as follows:

    char * filter_string = "arp or ((tcp or udp) and dst port 53) or tcp";


`arp` represents all the ARP packets; `(tcp or udp) and dst port 53` represents all the outgoing DNS packets (DNS is a tcp or udp packet and the port is 53); `tcp` repesents all the TCP packets.

The implementation fulfills the following 3 tasks.

#####1. Filter out all incoming ARP packets

**ARP** is a network layer protocol. So to judge whether a packet is a ARP packet, we need to process the ethernet header of the packet. In the `pkt_handler()`, we get the source and destination mac address of the packet and the ethernet type, which indicates what is the network layer protocol. If it is an ARP packet, call the `process_arp()` to see whether is an incoming one. This is judged by the **OP** flag in the ARP header. OP equals to ARPOP_REPLY indicates it is a ARP reply packet, incoming from some other computer from in the LAN. So record the packet to the *filtered.pcap*.

#####2. Filter out all outgoing DNS packets.

**DNS** is an application layer protocol. It's usually sent in a UDP packet, but sometimes in a TCP packet when packet size is larger than 512 bytes. The DNS server is always using the port **53** to provide the server.

We need to first check the ethernet header to see that it is a IP packet for both UDP and TCP packet is based on the IP protocol. If `ethernet_type == ETHERTYPE_IP`, we call `process_ip()`. In `process_ip()`, we similarly check the **P** flag in IP header to see whether the it's a UDP or TCP packet. `process_udp()` or `process_tcp()` is called to further process the packet. In the transport layer, we can get the source and destination port of this packet. If the destination port we get in the UDP or TCP header equals **53**, then we judge it a DNS packet and record it to *filtered.pcap*.

#####3. Limits the number of outgoing TCP connections to 5.

To limit the total TCP connection number, we need to track the establishment and termination of every connection. We all know that TCP is a reliable transport protocol, and the establishment of the a connection should go through a *three-way handshake*, while the termination should go through the *four-way handshake*. So in our implementation, we require every connection to be established or terminated only when it has finished the whole handshake process. This is mainly based on a **finite state machine**. When sending or receiving a certain, the states of the connection will change from one to another.

We first introduce the connection structure we use.

```
struct connection
{
    uint16_t sport;                 // source port
    uint16_t dport;                 // destination port
    char spa[16];                   // source ip address
    char dpa[16];                   // destination ip address
    int sstate;                     // source state
    int dstate;                     // destination port
    tcp_seq sseq;                   // source sequence number
    tcp_seq dseq;                   // destination sequence number
    struct connection *next;        // next connection (for buf)
    struct connection *prev;        // previous connection (for buf)
};
```

Since we are limiting all the outgoing connections, we only care about the connection start from us. We consider us as a client (connection source) and the connection destination as a server. In `struct connection`, `sstate` is the client state for establishment or termination in the process of handshake, `dstate` stands for the server state. `sseq` is the client's *ISN* (Initial Sequence Number) for establishment stage and *FIN* packet sequence number for termination. while `dseq` is the server's.

We've got three kinds of connections in the processing.
* *establishing*: A connection is going through the three-way handshake establishment process.
* *established*: A connection has finished the three-way handshake establishment process.
* *finished*: A connection is terminated or discarded due to limited connection number.

For the first two kinds, we need to record them for further process.

    struct connection * buf;                      // the connection linked list for all establishing connections
    struct connection conn_win[MAX_CONNECTION];   // the connection window for all established connections

When we sends a SYN packet, a new connection is started to establishing. We add it to the `buf`, and when some connection has went through the three-way handshake, we move it from `buf` to the `conn_win`. If some connection is terminated in the `conn_win`, we remove it from the window.

All the tracking work is done in `process_tcp()`. Now we detailedly describe how we track the tcp establishment and termination.

######Establishment

Here's the process of the three-way handshake establishment. Our FSM for establishment tracking is based on it.

```
    TCP A                                                     TCP B

1.  CLOSED                                                LISTEN

2.  SYN-SENT    --> <SEQ=100><CTL=SYN>                --> SYN-RECEIVED  handshake 1

3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>   <-- SYN-RECEIVED  handshake 2

4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED   handshake 3

5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
```

For every packet processed by `process_tcp()`, it will go through the following steps for establishment.

1. Check the *syn* and *ack* flag to see if it is the first packet of three-way handshake (line 2 in the graph). Also we need to check it's an outgoing packet from us. If both true and the connection is not existed in the `buf`, indicates that it is a new connection and add it to `buf` with `sstate` to be *SYN-SENT*, while `dstate` still to be *LISTEN*. This is because by far, we only know that the first handshake packet is sent from us, but whether the server has received it is **uncertain**. These are the first states of our FSM.
2. If the packet is not the first handshake packet and is already in the `buf`. This indicates that it is a packet being established, and is waiting for some packet to move the establishing process on (also move the FSM on).  
If now the states are *SYN-SENT* for `sstate` and *LISTEN* for `dstate`, the FSM is waiting for second handshake packet. If the packet is *syn* and *ack* and the ACK = sseq + 1 (the requirement of the second packet), update the connection state for *SYN-SENT* and *SYN-RECEIVED* for `sstate` and `dstate`.
3. If now the states are *SYN-SENT* for `sstate` and *SYN_RECEIVED* for `dstate`, the FSM is waiting for last handshake packet. If the packet is *ack* and the ACK == dseq + 1 (the requirement of the third packet), update the connection state for *ESTABLISHED* and *SYN-RECEIVED* for `sstate` and `dstate`.  
By now, we've tracked all the three handshake packets. But we don't know whether the server has received the last ack packet. So we **cannot ensure that the connection is indeed established**. Here, **we just regards the three-way handshake is finished and the connection is established** and move the connection to the `conn_win`, update the `sstate` and `dstate` both to *ESTABLISHED*. We will handle the problem using timeout in the later design.

######Termination

Here's the process of the the four-way handshake termination. Our FSM for termination tracking is based on it.

```
       TCP A                                                      TCP B

  1.  ESTABLISHED                                          ESTABLISHED

  2.  (Close)
      FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  --> CLOSE-WAIT  handshake 1

  3.  FIN-WAIT-2  <-- <SEQ=300><ACK=101><CTL=ACK>      <-- CLOSE-WAIT  handshake 2

  4.                                                       (Close)
      TIME-WAIT   <-- <SEQ=300><ACK=101><CTL=FIN,ACK>  <-- LAST-ACK    handshake 3

  5.  TIME-WAIT   --> <SEQ=101><ACK=301><CTL=ACK>      --> CLOSED      handshake 4

  6.  (2 MSL)
      CLOSED
```

The termination can be started by either the client or the server. The graph above is the process of a termination started by the client, while the one started by server is vice versa. For every packet processed by `process_tcp()`, it will go through the following steps. The termination started from the server is quite similar, and we don't detailedly describe here.

1. If the coming packets belongs to a connection in the `conn_win`, and the `sstate` and `dstate` are both *ESTABLISHED*, indicates it's a normal connection waiting to be terminated. Check the *fin* and *ack* flag to see if it is the first packet of four-way handshake. If true and the packet is sent from us, then update the connection states to *FIN-WAIT-1* and *ESTABLISHED* for `sstate` and `dstate`.
2. If now the connection states are *FIN-WAIT-1* and *ESTABLISHED* for `sstate` and `dstate`, the connection is waiting for the second handshake packet for termination. If *ack* and ACK == sseq + 1, then update the connection states to *FIN_WAIT-2* and *CLOSE-WAIT*.
3. If the now the connection states are *FIN-WAIT-2* and *CLOSE_WAIT* for `sstate` and `dstate`, the connection is waiting for the third handshake packet for termination. If *fin* and *ack*, then update the connection states to *FIN_WAIT-2* and *LAST-ACK*.
4. If the now the connection states are *FIN-WAIT-2* and *LAST-ACK* for `sstate` and `dstate`, the connection is waiting for the last handshake packet for termination. If and *ack*  and ACK == dseq + 1, then update the connection states to *TIME_WAIT* and *LAST-ACK*.  
By now, we've tracked all the four handshake packets. But we don't know whether the server has received the last ack packet. So we **cannot ensure that the connection is indeed terminated**. And the we need to wait **2 MSL** here as the protocol required. Here, **we just regards the four-way handshake is finished and the connection is terminated** and remove the connection from the `conn_win`. We will handle the problem using timeout in the later design.

Sometimes there is a **simultaneous closing** case for the termination. Here's its process.


```
      TCP A                                                      TCP B

  1.  ESTABLISHED                                          ESTABLISHED

  2.  (Close)                                              (Close)
      FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  ... FIN-WAIT-1
                  <-- <SEQ=300><ACK=100><CTL=FIN,ACK>  <--
                  ... <SEQ=100><ACK=300><CTL=FIN,ACK>  -->

  3.  CLOSING     --> <SEQ=101><ACK=301><CTL=ACK>      ... CLOSING
                  <-- <SEQ=301><ACK=101><CTL=ACK>      <--
                  ... <SEQ=101><ACK=301><CTL=ACK>      -->

  4.  TIME-WAIT                                            TIME-WAIT
      (2 MSL)                                              (2 MSL)
      CLOSED                                               CLOSED
```

To take this case into consideration,  in the Step 2 above, we need to check a second case that whether it is another *fin* packet from the server in the four-way handshake. If true update the `sstate` and `dstate` both to *FIN-WAIT-1*. And then follow the graph to move on the states.

Another case that can cause a connection termination is that some part of the connection explicitly send a **rst** packet. Once we find a packet is a *rst* packet and it belongs to some connection in the `conn_win`, unconditionally terminate the connection and remove it from the `conn_win`.

######Timeout

As mentioned above, after sending the last packet of three-way/four-way handshake for EST/TER, we don't really know that the server has received the packet. If it hasn't received, a retransmitting packet will be sent by it. So we cannot ensure the establishment and termination. To make sure that the server do received the packet and there is no retransmitting packet, we involved the **timeout** mechanism. After we receiving the last handshake packet, we will start a timer for the connection. If there's no retransmitting packet received before the timeout, we regards the establishment or termination is indeed finished. Otherwise, process the retransmitting packet and roll back the connection states.

We add a `start_time` in the `connection` structure, indicates the start time of the timer we set. The `timer` structure records the connection the timer is attached to. `timer_list` is the linked list for all timers.

```
struct connection
{
    ......
    time_t *start_time;             // start time for the timeout
};

struct timer
{
    struct connection *conn;         // the connection for the timer
    struct timer *prev;             // previous timer
    struct timer *next;             // next timer
};

struct timer *timer_list;
```
Since this is an emulation, how do we know how much time has passed away from the start time. Fortunately, every packet recorded by *tcpdump* has a **timestamp** to it, we check this *timestamp* before processing the packet. If some packets in the timer_list is timeout at this *timestamp* moment, then the connection is finishing the three-way/four-way handshake, and the connection is established or discarded or terminated depending on certain conditions.

For the establishment, after sending the last handshake packet, we just start a timer for this connection and add the timer to `timer_list`. The establishing timeout is not certain, because it depends on the real network traffic. So in this emulation, we cannot exactly tell how long is the timeout, we just set it to 10 seconds. If timeout and no retransmitting packet received, we establish the connection and move it to `conn_win` if the window is not full, otherwise discard the connection.  
Before the timeout, there're 3 conditions we need to handle.

1. If there's a retransmitting packet, roll back the connection states and reset the timer.
2. If there's a normal data packet coming from the server which indicates the connection has indeed established, establishing the connection if `conn_win` is not full or discard it if full.
3. If there's a *fin* packet of the four-way handshake which indicates the connection has indeed established and has started to be terminated, establishing the connection first if `conn_win` is not full and update the connection states to those after received a *fin* packet. Otherwise, discard `conn_win` if full.

For the termination, after sending the last handshake packet, we start another timer. The termination timeout is *2 * MSL* (Maximum Segment Lifetime). This is require by the protocol. On my Mac, the *MSL* is set to be **15** seconds. If timeout and no retransmitting received, we terminate the connection and remove it from `conn_win` otherwise roll back the connection states and reset the timer.

Add the timeout mechanism makes the emulation more realistic.

######Retransmission

TCP is a reliable transport protocol, if there is a packet lost, a retransmitting request will be sent. So in the process of the establishment and termination, we also handle the packet lost and retransmission.

Since we are using the *FSM*, before a timer is set, we don't need to roll back the states when finding a retransmitting packet. Bacause after the retransmitting packets is received and the lost packet is resent, the handshake process moves on and it will finally rereach the states at the time we found a packet lose. Sometimes, there is no reply any more, for example a down server, in these case, the connection will finally be shut down by a *rst* packet.

After a timer is set, and we find the last handshake packet is lost, we need to roll back the connection states to clear the timer when the retransmitting packet is received.
