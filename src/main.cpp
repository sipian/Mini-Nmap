#include "json.h"
using json = nlohmann::json;

#include "scan.h"
#include "discover.h"
#include <time.h>
#include <fstream>
#include <stdlib.h>

/*!
 * \brief Validates user input for scan type
 */
bool isTypeSupported(const char* type) {

	return (
			(strcasecmp(type,"SYN")==0) || (strcasecmp(type,"FIN")==0) || 
			(strcasecmp(type,"NULL")==0) || (strcasecmp(type,"XMAS")==0) || 
			(strcasecmp(type,"DECOY")==0)
			);
}

/*!
 * \brief Initialize static variables and set seed for rand()
 */
void initialize(const char* jsonFile) {

	Logger log;
	std::ifstream fin;
	fin.open(jsonFile);
	json j;
	fin >> j;

	std::map<std::string, Logger::logLevelNames> logLevels;
	logLevels["Logger::ERROR"] = Logger::ERROR;
	logLevels["Logger::WARN"] = Logger::WARN;
	logLevels["Logger::INFO"] = Logger::INFO;
	logLevels["Logger::DEBUG"] = Logger::DEBUG;

	if(logLevels.find(j["logLevel"]) == logLevels.end()) {
		log.error("Incorrect log level specified");
		throw Error::INPUT_PARAMETER_MISSING;
	} 

	srand(time(NULL));

	Ping::timeout = j["Ping::timeout"]; 				//microseconds
	Ping::interface = j["interface"];

	Logger::logLevel = logLevels[j["logLevel"]];

	Discover::noOfAttempts = j["Discover::noOfAttempts"];

	Scan::startPort = j["startPort"];
	Scan::endPort = j["endPort"]; 						//exclusive
	Scan::noOfThreads = j["noOfThreads"];
	Scan::noOfAttempts = j["Scan::noOfAttempts"];
	Scan::timeout = j["Scan::timeout"]; 				//microseconds

	Sniff::packetSize = j["packetSize"];
	Sniff::timeout_sec = j["Sniff::timeout_sec"];
	Sniff::timeout_usec = j["Sniff::timeout_usec"]; 	//microseconds

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
		trial.scan(ping.get_my_IP_address(), i, active_IPs, type);
	}
	log.result("************************************************************");
}

int main(int argc, char const *argv[])
{
	Logger log;

	if (argc < 4) {
		log.error("INPUT MISSING.\nUsage => ./bin/port-scanner <INPUT_FILE> <CIDR> <SYN | FIN | NULL | XMAS | DECOY>");
		throw Error::INPUT_PARAMETER_MISSING;
	}

	initialize(argv[1]);

	std::vector<std::string> scan_types;
	for (int i = 3; i < argc; ++i)
	{
		if(isTypeSupported(argv[i])) {
			std::string tmp = std::string(argv[i]);
			std::transform(tmp.begin(), tmp.end(),tmp.begin(), ::toupper);
			scan_types.push_back(tmp);
		}
		else {
			log.error("INVALID SCAN TYPE.\nUsage => ./bin/port-scanner <INPUT_FILE> <CIDR> <SYN | FIN | NULL | XMAS | DECOY>");
			throw Error::SCAN_NOT_SUPPORTED;	
		}
	}
	for(auto& i : scan_types) {
		scan(argv[2], i);	
	}
    return 0;
}
