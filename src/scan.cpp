#include "scan.h"

int Scan::noOfThreads;
int Scan::noOfAttempts;
int Scan::timeout;

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

void Scan::scanPerThread(const std::string &srcIP, const std::string &destinationIP, uint16_t startPort, uint16_t endPort, std::string type) {

	// opening a new socket to send packets
	std::tuple<int, int, int> sockfd = open_socket();
	int sender_sockfd = std::get<0>(sockfd);
	int receiver_sockfd = std::get<1>(sockfd);
	int srcPort = std::get<2>(sockfd);

	const char* dstIP = destinationIP.c_str();

	//make packet with required IP headers
	char* packet = create_packet(srcIP, srcPort, destinationIP);
	struct tcphdr *tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));

	// setting TCP flags
	setTCPHeader(tcpHdr, type);
    
	// creating destination address
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = inet_addr(dstIP);

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
    	log.debug("Scan::scanPerThread => Scanning port " + std::to_string(tmp->port));

    	// send TCP packet
	    if(sendto(sender_sockfd, packet, packetSize, 0, (struct sockaddr *) &addr_in, sizeof(addr_in)) < 0) {
	    	log.info("Scan::scanPerThread => unable to sendto TCP SYN packet to " + destinationIP + ":" + std::to_string(tmp->port) + " -- " + Error::ErrStr());
	    	// check if trials left
	    	if (tmp->trial > 0) {
	    		listOfPorts.push(tmp);
	    	}
	    	else {
	    		unknown_Ports.push_back(tmp->port);
	    		delete tmp;
	    	}
	    	continue;
		}

	    // wait for TCP reply with timeout
	    struct tcphdr *ptrToTCPHeader = recvPacket(tmp->port);
	    if (ptrToTCPHeader == NULL) {
	        log.info("Scan::scanPerThread => unable to receive TCP SYN reply from " + destinationIP + ":" + std::to_string(tmp->port));
	        // check if trials left
	        if (tmp->trial > 0) {
	    		listOfPorts.push(tmp);
	    	}
	    	else {
	    		unknown_Ports.push_back(tmp->port);
	    		delete tmp;
	    	}
	    }
	    else {
	    	tmp->trial = 0;
	    	scanResult status = checkTCPHeader(ptrToTCPHeader, type);
	    	// adding result 
    		switch(status) {
    			case OPEN: log.debug("Scan::scanPerThread => " + std::to_string(tmp->port) + " is open"); open_Ports.push_back(tmp->port); break;
    			case CLOSED: log.debug("Scan::scanPerThread => " + std::to_string(tmp->port) + " is closed"); closed_Ports.push_back(tmp->port); break;
    			case UNKNOWN: log.debug("Scan::scanPerThread => " + std::to_string(tmp->port) + " is unknown"); unknown_Ports.push_back(tmp->port); break;
    		}
    		delete tmp;
	    }    
    }
    close(receiver_sockfd);
    close(sender_sockfd);
    delete[] packet;
    finishTask(open_Ports, closed_Ports, unknown_Ports);
}

void Scan::finishTask(std::vector<uint16_t> &open_Ports, std::vector<uint16_t> &closed_Ports, std::vector<uint16_t> &unknown_Ports) {
	lock.lock();

	openPorts.insert(openPorts.begin(), open_Ports.begin(), open_Ports.end());
	closedPorts.insert(closedPorts.begin(), closed_Ports.begin(), closed_Ports.end());
	unknownPorts.insert(unknownPorts.begin(), unknown_Ports.begin(), unknown_Ports.end());
	
	lock.unlock();

	open_Ports.clear();
	closed_Ports.clear();
	unknown_Ports.clear();
}

void Scan::initialize() {
	// check if any previous thread is still working on something
	if (!threads.empty()) {
		log.error("Scan::initialize => Previous scan not finished yet");
		throw Error::RESOURCE_BUSY;
	}

	// open all mutex locks and clear vectors
	sniffer.objectiveAchieved = false;
	lock.unlock();
	threads.clear();
	openPorts.clear();
	closedPorts.clear();
	sniffer.sniffDetails.clear();
	unknownPorts.clear();
}

struct tcphdr* Scan::recvPacket(uint16_t dstPort) {
	std::chrono::time_point<std::chrono::high_resolution_clock> beg_ = std::chrono::high_resolution_clock::now();

	// check presence of packet until timeout
	while(std::chrono::duration_cast<std::chrono::microseconds> (std::chrono::high_resolution_clock::now() - beg_).count() <= Scan::timeout) {
		if (sniffer.sniffDetails.find(dstPort) != sniffer.sniffDetails.end()) {
			return sniffer.sniffDetails[dstPort];
		}
	}
	return NULL;
}

void Scan::scan(const std::string &srcIP, const std::string &dstIP, std::string type = "SYN") {

	initialize();
	std::thread snifferThread(&Sniff::sniff, &(this->sniffer), dstIP);		//starting a thread to start sniffing IP packets

	// port range 
	uint16_t startPort = 5430; 	//not doing 0
	uint16_t endPort = 5435;
	uint16_t binSize = (endPort - startPort)/noOfThreads;
	log.info("Scan::scan => Starting port scan of " + dstIP);

	for (int i = 0; i < noOfThreads; ++i) {
		uint16_t nextPort = (startPort + binSize > endPort)? endPort : startPort + binSize;
		threads.push_back(std::thread(&Scan::scanPerThread, this, srcIP, dstIP, startPort, nextPort, type));
		startPort += binSize;
	}
	for (int i = 0; i < noOfThreads; ++i) {
		threads[i].join();
	}
	log.info("Scan::scan => Finished port scan of " + dstIP);
	sniffer.objectiveAchieved = true;
	snifferThread.join();
	threads.clear();
}
