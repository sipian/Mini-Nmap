#ifndef SCAN_H
#define SCAN_H

#include "error.h"
#include "logger.h"
#include "packet.h"
#include <mutex>
#include <queue>
#include <vector>
#include <thread>

/*
	https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
*/

class Scan: public Packet {
    /*!
     * \brief logger object
     */
	Logger log;
	std::mutex lock;
	std::vector<std::thread> threads;
	void scanPerThread(const std::string &dstIP, int startPort, int endPort, std::string type);
	void setTCPHeader(struct tcphdr *tcpHdr, std::string type);
	typedef struct query {
		uint16_t port;
		int trial;
		int seqNo;		
	} query;
public:
	static int noOfThreads;
	static int noOfAttempts;
	enum scanResult {
			OPEN,
			CLOSED,
			UNKNOWN
	};
	scanResult checkTCPHeader(struct tcphdr *tcpHdr, std::string type);
	std::vector<int> openPorts;
	void initialize();
	void scan(const std::string &dstIP, std::string type);
};
#endif // SCAN_H