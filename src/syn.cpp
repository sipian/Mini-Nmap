#include "syn.h"

Syn::Syn():noOfThreads(4) {
}

/*
	https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
*/

void Syn::listen() {
	
}

void Syn::populateTCPheader(struct tcphdr *tcpHdr, int srcPort, int dstPort, uint32_t sequenceNo) {
    tcpHdr->source = htons(srcPort);    // 16 bit in nbp format of source port
    tcpHdr->dest = htons(dstPort);      // 16 bit in nbp format of destination port
    tcpHdr->seq = sequenceNo;           // 32 bit sequence number
    tcpHdr->ack_seq = 0x0;              // 32 bit ack sequence number, depends whether ACK is set or not
    tcpHdr->doff = 5;                   // Data offset :: 4 bits: 5 x 32-bit words on tcp header
    tcpHdr->res1 = 0;                   // Reserved :: 4 bits: Not used
    tcpHdr->cwr = 0;                    // Congestion control mechanism
    tcpHdr->ece = 0;                    // Congestion control mechanism
    tcpHdr->urg = 0;                    // Urgent flag
    tcpHdr->ack = 0;                    // Ack
    tcpHdr->psh = 0;                    // Push data immediately
    tcpHdr->rst = 0;                    // RST flag
    tcpHdr->syn = 1;                    // SYN flag
    tcpHdr->fin = 0;                    // FIN flag
    tcpHdr->window = htons(155);        // 0xFFFF; // 16 bit max number of databytes MSS
    tcpHdr->check = 0;                  // 16 bit check sum. Can't calculate at this point
    tcpHdr->urg_ptr = 0;                // 16 bit indicate the urgent data. Only if URG flag is set
}

void Syn::scanPerThread(const std::string &dstIP, int startPort, int endPort) {
	try {
		int sockfd = open_socket();

		create_packet(const std::string &sourceIP, int srcPort, const std::string &destinationIP, int dstPort)

    	// creating destination address
	    struct sockaddr_in addr_in;
	    addr_in.sin_family = AF_INET;
	    addr_in.sin_addr.s_addr = inet_addr(dstIP.c_str());

	    for (int dstPort = startPort; dstPort < endPort; ++dstPort) {
	    	addr_in.sin_port = htons(dstPort);
		    if((bytes = sendto(sockfd, packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0) {
		      perror("Error on sendto()");
    }


	    }

	} catch (Error::error &e) {

	}
}

void Syn::initialize() {
	// check if any previous thread is still working on something
	if (!threads.empty()) {
		log.error("Syn::initialize => Previous scan not finished yet");
		throw Error::RESOURCE_BUSY;
	}

	// open all mutex locks and clear vectors
	lock.unlock();
	threads.clear();
	openPorts.clear();
}

void Syn::scan(const std::string &dstIP) {
	// ports exucluding 
	int startPort = 0;
	int endPort = 65535;
	int binSize = (endPort - startPort)/noOfThreads;
	log.info("Syn::scan => Starting port scan of " + dstIP);

	for (int i = 0; i < noOfThreads; ++i)
	{
		int nextPort = (startPort + binSize > endPort)? endPort : startPort + binSize;
		threads.push_back(std::thread(scanPerThread, dstIP, startPort, nextPort));
		startPort += binSize;
	}
	for (auto &th : threads) {
		th.join();
	}
	threads.clear();
}
