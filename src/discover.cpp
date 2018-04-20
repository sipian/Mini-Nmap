#include "discover.h"

Discover::Discover() {
	noOfAttempts = 5;	
}

bool Discover::is_valid_CIDR(const std::string &IP) {
	if (std::regex_match (IP, std::regex("^([0-9]{1,3}[.]){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$"))) {
	  	return true;
	  }
	  return false;
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
		IP = "." + std::to_string(a & 0xFF) + IP;
		a = a >> 8; 
	}
	return IP.substr(1);
}

std::queue <Discover::request*> Discover::handle_CIDR(std::string IP, int netmask) {
	std::queue <request*> roundRobin;
	size_t pos = 0;
	unsigned long int IPRange = 0;
	int count = 3;

	while ((pos = IP.find(".")) != std::string::npos) {
	    int token = stoi(IP.substr(0, pos));
	    IPRange += (token << (8 * count));
    	count--;
    	IP.erase(0, pos + 1);
    }

    unsigned long int bitmask = (unsigned long int)(pow(2,32 - netmask) * (pow(2,netmask) - 1));

	unsigned long int range = IPRange & bitmask, limit = pow(2, 32 - netmask) - 1;

	for (unsigned long int i = 1; i < limit; ++i)
	{
		range++;
		request* tmp = new request;
		tmp->IP = get_IP_from_int(range);
		tmp->trial = noOfAttempts;
		tmp->expectedSequenceNo = 1;
		roundRobin.push(tmp);
	}
	log.debug("Discover::handle_CIDR => added " + std::to_string(roundRobin.size()) + " IPs of CIDR to queue");
	return roundRobin;
}

const std::vector<std::string> Discover::discover_host(std::queue <Discover::request*> &roundRobin) {
	int sockfd = ping.open_icmp_socket();
	std::vector<std::string> active_IPs;
	ping.set_src_addr(sockfd, ping.get_my_IP_address("enp7s0"));
	while(!roundRobin.empty()) {
		// testing in round-robin format
		request* tmp = roundRobin.front();
		roundRobin.pop();
		log.debug("Discover::discover_host => checking activeness of " + tmp->IP);
		tmp->trial--;

		try {
			ping.ping_request(sockfd, tmp->IP, tmp->expectedSequenceNo);
			struct icmp* response = ping.ping_reply(sockfd);
			if(response->icmp_seq == tmp->expectedSequenceNo) {
				active_IPs.push_back(tmp->IP);
			}
		} catch (const Error::error &e) {
			if (tmp->trial > 0) {
				roundRobin.push(tmp);
			}
		}

		tmp->expectedSequenceNo++;
	}
	if (active_IPs.size() == 0) {
		log.warn("Discover::discover_host => No active IP found in CIDR range");
		throw Error::NO_ACTIVE_IP;
	}
	return active_IPs;
}

