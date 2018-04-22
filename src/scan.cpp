#include "scan.h"

int Scan::noOfThreads;
int Scan::noOfAttempts;

void Scan::setTCPHeader(struct tcphdr *tcpHdr, std::string type) {
	if (type.compare("SYN") == 0) {
		tcpHdr->syn = 1;	// setting SYN bit to 1
	}
}

Scan::scanResult Scan::checkTCPHeader(struct tcphdr *tcpHdr, std::string type) {
	if (type.compare("SYN") == 0) {
		if(tcpHdr->rst == 1) {
			return CLOSED;
		}
		else if(tcpHdr->syn == 1 && tcpHdr->ack == 1){
			return OPEN;
		}
		else {
			return UNKNOWN;
		}
	}
	return UNKNOWN;
}

void Scan::scanPerThread(const std::string &destinationIP, uint16_t startPort, uint16_t endPort, std::string type) {
	std::tuple<int, int, std::string> sockDetails = open_socket();
	int sockfd = std::get<0>(sockDetails);
	int srcPort = std::get<1>(sockDetails);
	std::string srcIP = std::get<2>(sockDetails);
	const char* dstIP = destinationIP.c_str();

	char* packet = create_packet(srcIP, srcPort, destinationIP);
    struct iphdr *ipHdr = (struct iphdr *) packet;
	struct tcphdr *tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));

	// setting TCP flags
	setTCPHeader(tcpHdr, type);
    
	// creating destination address
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = inet_addr(dstIP);

    // variables for receiving a packet
    char* rcvPacket = new char[packetSize];
    struct sockaddr senderAddr;
    socklen_t senderLen = sizeof(senderAddr);

    //variables for manipulating received packet
    unsigned char* ptrToRecievedPacket = NULL;
	struct iphdr *ptrToIPHeader=NULL;
	struct tcphdr *ptrToTCPHeader=NULL;

	// populating query queue
	std::queue<query*> listOfPorts;
    for (uint16_t dstPort = startPort; dstPort < endPort; ++dstPort) {
    	query* tmp = new query;
    	tmp->port = dstPort;
    	tmp->trial = Scan::noOfAttempts;
    	tmp->seqNo = rand();
    	listOfPorts.push(tmp);
    }
	std::vector<uint16_t> open_Ports;
	std::vector<uint16_t> closed_Ports;
	std::vector<uint16_t> unknown_Ports;

	while(!listOfPorts.empty()) {
		query* tmp = listOfPorts.front();
		listOfPorts.pop();

		tmp->trial--;
    	addr_in.sin_port = htons(tmp->port);
    	
        // set fields for creating SYN packet
        tcpHdr->dest = htons(tmp->port); 
        tcpHdr->seq = tmp->seqNo;
    	tcpHdr->check = calcsumTCP(srcIP.c_str(), dstIP, tcpHdr);

    	// send TCP packet
	    if(sendto(sockfd, packet, packetSize, 0, (struct sockaddr *) &addr_in, sizeof(addr_in)) < 0) {
	    	log.info("Scan::scanPerThread => unable to sendto TCP SYN packet to " + destinationIP + ":" + std::to_string(tmp->port) + " -- " + Error::ErrStr());
	    	// check if trials left
	    	if (tmp->trial > 0) {
	    		listOfPorts.push(tmp);
	    	}
	    	else {
	    		unknown_Ports.push_back(tmp->port);
	    	}
	    	continue;
		}

	    // wait for ICMP reply with timeout
	    if (recvfrom(sockfd, rcvPacket, packetSize, 0, &senderAddr, &senderLen) < 0) {
	        log.info("Scan::scanPerThread => unable to receive TCP SYN reply from " + destinationIP + ":" + std::to_string(tmp->port) + " -- " + Error::ErrStr());
	        // check if trials left
	        if (tmp->trial > 0) {
	    		listOfPorts.push(tmp);
	    	}
	    	else {
	    		unknown_Ports.push_back(tmp->port);
	    	}
	    	continue;
	    }

	    //extracting flags from packet
	    ptrToRecievedPacket = (unsigned char*)(rcvPacket);	
	    ptrToIPHeader = (struct iphdr *)ptrToRecievedPacket;
	    ptrToTCPHeader = (struct tcphdr *)(ptrToIPHeader + (ptrToIPHeader->ihl*4));
	    
	    if (ptrToIPHeader->protocol == IPPROTO_TCP) { 			// filtering TCP packets
	    	if(tmp->port == ntohs(ptrToTCPHeader->source)) {		// filtering packets for the interested port
	    		tmp->trial = 0;
	    		scanResult status = checkTCPHeader(ptrToTCPHeader, type);
	    		// adding result 
	    		switch(status) {
	    			case OPEN: log.debug("Scan::scanPerThread => " + std::to_string(tmp->port) + " is open"); open_Ports.push_back(tmp->port); break;
	    			case CLOSED: log.debug("Scan::scanPerThread => " + std::to_string(tmp->port) + " is closed"); closed_Ports.push_back(tmp->port); break;
	    			case UNKNOWN: log.debug("Scan::scanPerThread => " + std::to_string(tmp->port) + " is unknown"); unknown_Ports.push_back(tmp->port); break;
	    		}
	    		continue;
	    	}
	    }
        // check if trials left
        if (tmp->trial > 0) {
    		listOfPorts.push(tmp);
    	}
    	else {
    		unknown_Ports.push_back(tmp->port);
    	}	    
    }
}

void Scan::initialize() {
	// check if any previous thread is still working on something
	if (!threads.empty()) {
		log.error("Scan::initialize => Previous scan not finished yet");
		throw Error::RESOURCE_BUSY;
	}

	// open all mutex locks and clear vectors
	lock.unlock();
	threads.clear();
	openPorts.clear();
}

void Scan::scan(const std::string &dstIP, std::string type = "SYN") {
	// ports exucluding 
	uint16_t startPort = 1; 	//not doing 0
	uint16_t endPort = 65535;
	uint16_t binSize = (endPort - startPort)/noOfThreads;
	log.info("Scan::scan => Starting port scan of " + dstIP);

	for (int i = 0; i < noOfThreads; ++i)
	{
		uint16_t nextPort = (startPort + binSize > endPort)? endPort : startPort + binSize;
		threads.push_back(std::thread(scanPerThread, dstIP, startPort, nextPort, type));
		startPort += binSize;
	}
	for (auto &th : threads) {
		th.join();
	}
	threads.clear();
}
