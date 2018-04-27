#include "scan.h"
#include "discover.h"

#include <time.h>
#include <stdlib.h>

/*!
 * \brief Initialize static variables and set seed for rand()
 */
void initialize() {
	srand(time(NULL));

	Ping::timeout = 1e4; 		//microseconds
	Ping::interface = "enp7s0";
	Logger::logLevel = Logger::DEBUG;
	Discover::noOfAttempts = 2;

	Scan::startPort = 5430;
	Scan::endPort = 5435; 	//exclusive
	Scan::noOfThreads = 1;
	Scan::noOfAttempts = 5;
	Scan::timeout = 1e4; 		//microseconds

	Sniff::packetSize = 100;
	Sniff::timeout_sec = 0;
	Sniff::timeout_usec = 1e4; 	//microseconds
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
		usleep(5e6);
	}
}

int main() {
	initialize();
	scan("127.0.0.1/30", "FIN");	
    return 0;
}
