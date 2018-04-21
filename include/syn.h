#ifndef SYN_H
#define SYN_H

#include "error.h"
#include "logger.h"
#include "packet.h"
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

class Syn: public Packet {
	const int noOfThreads;
	Logger log;
	std::mutex lock;
	std::vector<std::thread> threads;
	void scanPerThread(const std::string &dstIP, int startPort, int endPort);

public:
	std::vector<int> openPorts;
	Syn();
	void initialize();
	void scan(const std::string &dstIP);
};
#endif // SYN_H