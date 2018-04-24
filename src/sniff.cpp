#include "sniff.h"


int Sniff::packetSize;
int Sniff::timeout_sec;
int Sniff::timeout_usec;

int Sniff::open_socket() {
     
    //Create a raw socket that will sniff
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sockfd < 0) {
	    log.info("Sniff::open_socket => unable to open sniffer packet -- " + Error::ErrStr());
        throw Error::SOCKET_NOT_CREATED;
    }

    struct timeval timeout_tv;
    timeout_tv.tv_sec = Sniff::timeout_sec;
    timeout_tv.tv_usec = Sniff::timeout_usec;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)(&timeout_tv), sizeof(timeout_tv)) < 0) {
        log.error("Sniff::open_socket => Error in creating timeout for socket connection -- " + Error::ErrStr());
        throw Error::TIMEOUT_NOT_CREATED;
    }

    return sockfd;
}

void Sniff::process_packet(const char *packet, const std::string &targetIP) {

    struct iphdr *ip_header = (struct iphdr*)packet;

    if (ip_header->protocol == 6) {     // only accept TCP packets

        if (ip_header->saddr == inet_addr(targetIP.c_str())) {  // only accept TCP packets from targetIP
		    unsigned short ip_header_length = ip_header->ihl*4;
		    struct tcphdr* tcp_header = (struct tcphdr *)(packet + ip_header_length);
		    uint16_t srcPort = ntohs(tcp_header->source);
		    log.info("Sniff::process_packet => Sniffed TCP packet from " + targetIP + ":" + std::to_string(srcPort));
		    sniffDetails[srcPort] = tcp_header;
    	}
    }
}

void Sniff::sniff(const std::string &targetIP) {
	int sockfd = open_socket();
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);
     
    while(!objectiveAchieved) {
        char* buffer = new char[Sniff::packetSize];
        if(recvfrom(sockfd, buffer, Sniff::packetSize, 0, &saddr, &saddr_size) < 0 ) {
            log.info("Sniff::sniff => recvfrom error -- " + Error::ErrStr());
        }
        else {
            process_packet(buffer, targetIP);        
        }
    }
    close(sockfd);
    
}
