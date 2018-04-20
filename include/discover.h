#ifndef DISCOVER_H
#define DISCOVER_H

#include "ping.h"
#include "error.h"
#include "logger.h"
#include <regex>
#include <queue>
#include <math.h>
#include <vector>

class Discover {
private:
	Logger log;
	std::string get_IP_from_int(unsigned long int a);
	Ping ping;
	int noOfAttempts;

public:
	Discover();
	typedef struct request {
		std::string IP;
		int trial;
		uint16_t sequenceNo;
	} request;

	bool is_valid_CIDR(const std::string &IP);
	std::tuple<std::string, int> split_CIDR(const std::string &IP);
	std::queue <request*> handle_CIDR(std::string IP, int netmask);
	std::vector<std::string> discover_host(std::queue <Discover::request*> &roundRobin);
};

#endif // DISCOVER_H