#include "packet.h"

Packet::Packet() {
    packetSize = 512;
    timeout_tv.tv_sec = 0;
    timeout_tv.tv_usec = Ping::timeout;     // same timeout as ping service discovery
}

unsigned short Packet::calcsum(unsigned short *ptr,int nbytes) {
  long sum;
  unsigned short oddbyte;
  short answer;

  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;

  return(answer);
}

int Packet::allocateSocket() {
    int sockfd, one = 1;
    if((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        log.error("Packet::open_socket => Error while creating socket");
        throw Error::SOCKET_NOT_CREATED;
    }

    // Set option IP_HDRINCL (headers are included in packet)
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
        log.error("Packet::open_socket => Error while setting socket options");
        throw Error::IP_HDRINCL_NOT_SET;
    }
    // Set option SO_REUSEADDR to reuse ports if previous connection operation killed
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one))) {
        log.error("Packet::open_socket => Error while setting socket options");
        throw Error::SO_REUSEADDR_NOT_SET;
    }
    // Set a timeout for receiving packet
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)(&timeout_tv), sizeof(timeout_tv)) < 0) {
        log.error("Ping::open_ping_socket => Error in creating timeout for socket connection -- " + Error::ErrStr());
        throw Error::TIMEOUT_NOT_CREATED;
    }
    return sockfd;
}

int Packet::findFreePort(int sockfd) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    int attempts = 0;
    // loop until we get a port in non-special region
    while (addr.sin_port < 1024) {
        if (++attempts > 500) {
            log.error("Packet::findFreePort => Failed to reserve a port");
            throw Error::NO_FREE_PORT;
        }
        int sock = allocateSocket();
        if (sock == 0) {
            continue;
        }
        if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
            if (errno == EADDRINUSE) {
                /* address already in use */
                continue;
            }
            perror("bind()");
            return -1;
        }
        if (getsockname(sock, (struct sockaddr*) &addr, &len) != 0) {
            perror("getsockname()");
            return -1;
        }
    }
}

Packet::open_connection() {

}

// Reference :: 
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
    return (calcsum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
          sizeof(struct tcphdr))));
}

void Packet::create_packet(const std::string &sourceIP, int srcPort, const std::string &destinationIP, int dstPort) {
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
    
    ipHdr->check = calcsum((unsigned short *) packet, ipHdr->tot_len);

    uint32_t sequenceNo = 1138083240;

    populateTCPheader(tcpHdr, srcPort, dstPort,  sequenceNo);
    tcpHdr->check = calcsumTCP(srcIP, dstIP, tcpHdr);



}


/*
http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2tcp_8h-source.html#l00027
https://www.devdungeon.com/content/using-libpcap-c
*/