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
	    	continue;
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
    finishTask(open_Ports, closed_Ports, unknown_Ports);
}

void Scan::finishTask(std::vector<uint16_t> &open_Ports, std::vector<uint16_t> &closed_Ports, std::vector<uint16_t> &unknown_Ports) {
	lock.lock();
	openPorts.insert(openPorts.begin(), open_Ports.begin(), open_Ports.end());
	closedPorts.insert(openPorts.begin(), closed_Ports.begin(), closed_Ports.end());
	unknownPorts.insert(openPorts.begin(), unknown_Ports.begin(), unknown_Ports.end());	
	lock.unlock();
}

void Scan::initialize() {
	// check if any previous thread is still working on something
	if (!threads.empty()) {
		log.error("Scan::initialize => Previous scan not finished yet");
		throw Error::RESOURCE_BUSY;
	}

	objectiveAchieved = false;
	// open all mutex locks and clear vectors
	lock.unlock();
	threads.clear();
	openPorts.clear();
	closedPorts.clear();
	sniffDetails.clear();
	unknownPorts.clear();
}

pcap_t* Scan::initializePcap(const std::string &targetIP) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    const char* filter_exp = (std::string("tcp and src host " + targetIP)).c_str();
    bpf_u_int32 subnet_mask, ip;

    /* Open the device */
    if ( (handle= pcap_open_live("any",         // name of interface
                              65536,            // portion of the packet to capture.65536 guarantees that the whole packet will be captured on all the link layers
                              0,                // promiscuous mode
                              Scan::timeout,    // read timeout
                              errbuf            // error buffer
                              ) ) == NULL)
    { 
        log.error("Scan::initializePcap => Unable to open the adapter.");
        throw Error::UNABLE_TO_SNIFF;
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) < 0) {
        log.error("Scan::initializePcap => Bad filter - " + std::string(pcap_geterr(handle)));
        throw Error::INVALID_FILTER;
    }
    if (pcap_setfilter(handle, &filter) < 0) {
        log.error("Scan::initializePcap => Error setting filter - " + std::string(pcap_geterr(handle)));
        throw Error::INVALID_FILTER;
    }
    log.info("Scan::initializePcap => Initialized PCAP handle and set filter also");
    return handle;
}

std::tuple<uint16_t, struct tcphdr*> Scan::extractSrcPort(const u_char *packet) {

    const int ethernet_header_length = 14; 

    const u_char *ip_header = packet + ethernet_header_length;      	  //Find start of IP header
    int ip_header_length = ((*ip_header) & 0x0F)*4;       				  //The second-half of the first byte in ip_header contains the IP header length (IHL)

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    struct tcphdr* tcp_header = (struct tcphdr *)(packet + ethernet_header_length + ip_header_length);
    uint16_t srcPort = ntohs(tcp_header->source);
    return std::make_tuple(srcPort, tcp_header);
}

void Scan::sniff(const std::string &targetIP) {

    pcap_t* handle = initializePcap(targetIP);
	struct pcap_pkthdr *header;
	const u_char *pkt_data;    

    /* Retrieve the packets */
    while(!objectiveAchieved) {

        int res = pcap_next_ex(handle, &header, &pkt_data);

        if(res < 0) {
        	log.error("Scan::sniff => pcap_next_ex is giving errors");
            throw Error::UNABLE_TO_SNIFF;
        }
        else if (res == 0) {
        	log.warn("Scan::sniff => pcap_next_ex has timed-out");
        }
        else {
        	std::tuple<uint16_t, struct tcphdr*> pkt = extractSrcPort(pkt_data);
        	log.info("Got packet from " + targetIP + ":" + std::to_string(std::get<0>(pkt)));
        	sniffDetails[std::get<0>(pkt)] = std::get<1>(pkt);
        }
    }
}

struct tcphdr* Scan::recvPacket(uint16_t dstPort) {
	std::chrono::time_point<std::chrono::high_resolution_clock> beg_ = std::chrono::high_resolution_clock::now();

	// loop until timeout
	while(std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::high_resolution_clock::now() - beg_).count() <= Scan::timeout) {
		if (sniffDetails.find(dstPort) != sniffDetails.end()) {
			return sniffDetails[dstPort];
		}
	}
	return NULL;
}

void Scan::scan(const std::string &srcIP, const std::string &dstIP, std::string type = "SYN") {

	std::thread snifferThread(&Scan::sniff, this, dstIP);	//starting a thread to start sniffing IP packets

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
	for (auto &th : threads) {
		th.join();
	}
	snifferThread.join();
	objectiveAchieved = true;
	threads.clear();
}
