#include "scan.h"
#include "discover.h"

#include <time.h>
#include <stdlib.h>

/*!
 * \brief Initialize static variables and set seed for rand()
 */
void initialize() {
	srand(time(NULL));

	Ping::timeout = 1e3; 	//microseconds
	Ping::interface = "enp7s0";
	Logger::logLevel = Logger::DEBUG;
	Discover::noOfAttempts = 1;

	Scan::noOfThreads = 1;
	Scan::noOfAttempts = 5;
	Scan::timeout = 1e3; 	//microseconds

	Sniff::packetSize = 500;
}

/*!
 * \brief Perform port scan
 * \param CIDR subnet details
 * \param type type of port scan
 */
void scan(const std::string &CIDR, const std::string &type) {
	Logger log;
	Discover obj;
	log.result("\n\n\n\nStarting port-scanner 1.0.0\n");
	
	std::vector<std::string> active_IPs = obj.discover_host(CIDR);
	log.result("\n\n\n\n\tThere are " + std::to_string(active_IPs.size()) + " active IPs in the subnet");
	for(auto& i : active_IPs) {
		log.result("\t\t" + i);
	}
	std::cout << "\n\n\n\n";

	Ping ping;
	Scan trial;

	for(auto& i : active_IPs) {
		trial.scan(ping.get_my_IP_address(), i, type);
	}
}

int main() {
	initialize();
	scan("127.0.0.1/30", "SYN");	
    return 0;
}