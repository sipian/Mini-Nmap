#include "packet.h"

Packet::Packet() {
    // important to not include any data
    packetSize = sizeof(struct iphdr) + sizeof(struct tcphdr);
}

int Packet::allocateSocket() {
    int tmp = 1;

    // creating a RAW socket for sending packets
    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

    if(sockfd < 0) {
        log.error("Packet::allocateSocket => Error while creating sender socket -- " + Error::ErrStr());
        throw Error::SOCKET_NOT_CREATED;
    }

    // Set option IP_HDRINCL (headers are included in packet)
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&tmp, sizeof(tmp)) < 0) {
        log.error("Packet::allocateSocket => Error while setting sender socket options -- " + Error::ErrStr());
        throw Error::IP_HDRINCL_NOT_SET;
    }
    // Set option SO_REUSEADDR to reuse ports if previous connection operation killed
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&tmp, sizeof(tmp)) < 0) {
        log.error("Packet::allocateSocket => Error while setting sender socket options -- " + Error::ErrStr());
        throw Error::SO_REUSEADDR_NOT_SET;
    }
    return sockfd;
}

std::tuple<int, int, int> Packet::open_socket() {

    int sender_sockfd = allocateSocket();
    int port;

    // allocating a socket for receiving packets
    int receiver_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;              //any free port

    // binding any free port to socket
    if (bind(receiver_sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        log.error("Packet::allocateSocket => unable to bind port to socket");
        throw Error::SOCKET_NOT_BOUND;
    }

    // getting the alloted port number of socket
    socklen_t len = sizeof(addr);
    if (getsockname(receiver_sockfd, (struct sockaddr *)&addr, &len) < 0) {
        log.error("Packet::open_connection => unable to getsockname for allocated socket");
        throw Error::UNABLE_TO_GET_SOCKET_DETAILS;
    }
    else {
        port = ntohs(addr.sin_port);
    }

    log.info("Packet::open_socket => Allocated socket at srcport " + std::to_string(port));
    return std::make_tuple(sender_sockfd, receiver_sockfd, port);
}

unsigned short Packet::calcsum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

unsigned short Packet::calcsumTCP(const char* srcIP, const char* dstIP, struct tcphdr *tcpHdr) {
    struct pseudoTCPPacket pTCPPacket;
    pTCPPacket.srcAddr = inet_addr(srcIP);    //32 bit format of source address
    pTCPPacket.dstAddr = inet_addr(dstIP);    //32 bit format of source address
    pTCPPacket.zero = 0;                      //8 bit always zero
    pTCPPacket.protocol = IPPROTO_TCP;        //8 bit TCP protocol
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr)); // 16 bit length of TCP header

    //Populate the pseudo packet
    char *pseudo_packet = new char[((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr)))];
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr));

    //Copy pseudo header
    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));

    //Calculate check sum: zero current check
    tcpHdr->check = 0;

    //Copy tcp header + data to fake TCP header for checksum
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr));

    //Set the TCP header's checksum field
    unsigned short chksum = (calcsum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) +
          sizeof(struct tcphdr))));

    delete[] pseudo_packet;
    return chksum;
}

void Packet::populateTCPheader(struct tcphdr *tcpHdr, int srcPort) {
    tcpHdr->source = htons(srcPort);    // 16 bit in nbp format of source port
    tcpHdr->dest = 0;      // 16 bit in nbp format of destination port
    tcpHdr->seq = 0;           // 32 bit sequence number
    tcpHdr->ack_seq = 0x0;              // 32 bit ack sequence number, depends whether ACK is set or not
    tcpHdr->doff = 5;                   // Data offset :: 4 bits: 5 x 32-bit words on tcp header
    tcpHdr->res1 = 0;                   // Reserved :: 4 bits: Not used
    tcpHdr->cwr = 0;                    // Congestion control mechanism
    tcpHdr->ece = 0;                    // Congestion control mechanism
    tcpHdr->urg = 0;                    // Urgent flag
    tcpHdr->ack = 0;                    // Ack
    tcpHdr->psh = 0;                    // Push data immediately
    tcpHdr->rst = 0;                    // RST flag
    tcpHdr->syn = 0;                    // SYN flag
    tcpHdr->fin = 0;                    // FIN flag
    tcpHdr->window = htons(155);        // 0xFFFF; // 16 bit max number of databytes MSS
    tcpHdr->check = 0;                  // 16 bit check sum. Can't calculate at this point
    tcpHdr->urg_ptr = 0;                // 16 bit indicate the urgent data. Only if URG flag is set
}

char* Packet::create_packet(const std::string &sourceIP, const int srcPort, const std::string &destinationIP) {
    char* packet = new char[packetSize];
    const char* srcIP = sourceIP.c_str();
    const char* dstIP = destinationIP.c_str();

    memset(packet, 0, packetSize);
    // setting pointers to the different headers in the packet
    struct iphdr *ipHdr = (struct iphdr *) packet;
    struct tcphdr *tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
    //no payload

    // Populate ip Header
    ipHdr->ihl = 5;         // Internet IP Header Length = 5 x 32-bit words in the header :: minimum #words in IP header = 5
    ipHdr->version = 4;     // ipv4
    ipHdr->tos = 0;         // Type of Service = [0:5] DSCP + [5:7] Not used, low delay
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);        // total length of packet
    ipHdr->id = htons(rand()%10000); // identifying the group of fragments :: 0x00; // 16 bit id
    ipHdr->frag_off = 0x00;          // Fragment Offset :: 16 bit field = [0:2] flags + [3:15] offset = 0x0
    ipHdr->ttl = 0xFF;               // Time To Live (TTL) :: 16 bit time
    ipHdr->protocol = IPPROTO_TCP;   // TCP protocol
    ipHdr->check = 0;                // 16 bit checksum of IP header.
    ipHdr->saddr = inet_addr(srcIP); // 32 bit format of source address
    ipHdr->daddr = inet_addr(dstIP); // 32 bit format of source address

    ipHdr->check = (calcsum((unsigned short *) packet, ipHdr->tot_len));
    populateTCPheader(tcpHdr, srcPort);
    return packet;
/*
http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2tcp_8h-source.html#l00027
https://www.devdungeon.com/content/using-libpcap-c
*/
}
