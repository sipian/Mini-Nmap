#include "discover.h"

int Discover::noOfAttempts;

bool Discover::is_valid_CIDR(const std::string &IP) {
    return std::regex_match (IP, std::regex("^([0-9]{1,3}[.]){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$"));
}

std::tuple<std::string, int> Discover::split_CIDR(const std::string &IP) {
	int netmask = std::stoi(IP.substr(IP.find("/") + 1));
	std::string IPRange = IP.substr(0, IP.find("/"));
	return std::make_tuple(IPRange, netmask);
}

std::string Discover::get_IP_from_int(unsigned long int a) {
	std::string IP = "";
	for (int i = 0; i < 4; ++i)
	{
		IP += std::to_string(a & 0xFF);
		a = a >> 8;
        if (i < 3) {
            IP += ".";
        }
	}
	return IP;
}

unsigned long int Discover::get_int_from_IP(std::string IP) {
    unsigned long int val = 0;
    size_t pos = 0;
    int count = 3;
    std::string token;
    while ((pos = IP.find(".")) != std::string::npos) {
        int token = std::stoi(IP.substr(0, pos));
        val += (token << (8 * count));
        count--;
        IP.erase(0, pos + 1);
    }
    return val;
}

std::queue <Discover::request*> Discover::handle_CIDR(std::string IP, int netmask) {
	std::queue <request*> roundRobin;

	// converting a.b.c.d into integer using bit manipulations for computation
	std::string myIP = ping.get_my_IP_address();

	unsigned long int IPRange = get_int_from_IP(IP);

    unsigned long int bitmask = (unsigned long int)(pow(2,32 - netmask) * (pow(2,netmask) - 1));

	unsigned long int range = IPRange & bitmask, limit = pow(2, 32 - netmask) - 1;

	for (unsigned long int i = 1; i < limit; ++i)
	{
		range++;
		if(get_IP_from_int(range).compare(myIP) != 0) { 	//  don't include own IP address as request
			request* tmp = new (struct request);
			tmp->IP = get_IP_from_int(range);
			tmp->trial = Discover::noOfAttempts;
			tmp->sequenceNo = 1;
			roundRobin.push(tmp);
		}
	}
	log.debug("Discover::handle_CIDR => added " + std::to_string(roundRobin.size()) + " IPs of CIDR to queue");
	return roundRobin;
}

std::vector<std::string> Discover::discover_host(const std::string &CIDR) {
	
	if (! is_valid_CIDR(CIDR)) {
		log.error("Discover::discover_host => CIDR input is invalid");
		throw Error::INVALID_CIDR;
	}

	std::tuple<std::string, int> a = split_CIDR(CIDR);
	std::queue <Discover::request*> roundRobin = handle_CIDR(std::get<0>(a), std::get<1>(a));

	int sockfd = ping.open_icmp_socket();

	std::vector<std::string> active_IPs;
	ping.set_src_addr(sockfd, ping.get_my_IP_address());

	while(!roundRobin.empty()) {
		// testing in round-robin format
		request* tmp = roundRobin.front();
		roundRobin.pop();
		log.debug("Discover::discover_host => checking activeness of " + tmp->IP + " - trial #" + std::to_string(tmp->trial));
		tmp->trial--;

		try {
			ping.ping_request(sockfd, tmp->IP, tmp->sequenceNo);
			if (ping.ping_reply(sockfd).compare(tmp->IP) == 0) {
				active_IPs.push_back(tmp->IP);
				delete tmp;
			}
		} catch (const Error::error &e) {
			// did not ping
			if (! (e == Error::UNABLE_TO_RECEIVE_ICMP || e == Error::UNABLE_TO_SEND_ICMP)) {
                throw e;  // throw the error if it is something other than an inability to send / receive
			}
		}
		if (tmp->trial > 0) {
			roundRobin.push(tmp);
			tmp->sequenceNo++;
		}
	}
	if (active_IPs.size() == 0) {
		log.warn("Discover::discover_host => No active IP found in CIDR range");
		throw Error::NO_ACTIVE_IP;
	}
	close(sockfd);
	log.info("Discover::discover_host => " + std::to_string(active_IPs.size()) + " active IPs found in subnet");
	return active_IPs;
}
