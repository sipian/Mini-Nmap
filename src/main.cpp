#include "scan.h"
#include "discover.h"

#include <time.h>
#include <stdlib.h>

/*!
 * \brief Validates user input for scan type
 */
bool isTypeSupported(const char* type) {

	return ((strcasecmp(type,"SYN")==0) || (strcasecmp(type,"FIN")==0) || (strcasecmp(type,"NULL")==0) || (strcasecmp(type,"XMAS")==0) || (strcasecmp(type,"DECOY")==0));
}

/*!
 * \brief Initialize static variables and set seed for rand()
 */
void initialize() {
	srand(time(NULL));

	Ping::timeout = 1e4; 		//microseconds
	Ping::interface = "enp7s0";
	Logger::logLevel = Logger::INFO;
	Discover::noOfAttempts = 2;

	Scan::startPort = 5430;
	Scan::endPort = 5435; 		//exclusive
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
	log.result("\n\n************************************************************\n\nStarting port-scanner ("+ type +") 1.0.0\n");
	
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
	log.result("************************************************************");
}

int main(int argc, char const *argv[])
{
	Logger log;

	initialize();
	if (argc < 3) {
		log.error("INPUT MISSING.\nUsage => ./bin/port-scanner <CIDR> <SYN | FIN | NULL | XMAS | DECOY>");
		throw Error::INPUT_PARAMETER_MISSING;
	}
	std::vector<std::string> scan_types;
	for (int i = 2; i < argc; ++i)
	{
		if(isTypeSupported(argv[i])) {
			std::string tmp = std::string(argv[i]);
			std::transform(tmp.begin(), tmp.end(),tmp.begin(), ::toupper);
			scan_types.push_back(tmp);
		}
		else {
			log.error("INVALID SCAN TYPE.\nUsage => ./bin/port-scanner <CIDR> <SYN | FIN | NULL | XMAS | DECOY>");
			throw Error::SCAN_NOT_SUPPORTED;	
		}
	}
	for(auto& i : scan_types) {
		scan(argv[1], i);	
	}
    return 0;
}
