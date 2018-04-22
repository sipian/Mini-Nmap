#include <time.h>
#include <stdlib.h>
#include "scan.h"
#include "ping.h"
#include "logger.h"
#include "discover.h"

int main() {
	srand(time(NULL));
	Ping::timeout = 1e3; 	//microseconds
	Ping::interface = "enp7s0";
	Logger::logLevel = Logger::DEBUG;
	Discover::noOfAttempts = 1;
	Scan::noOfThreads = 1;
	Scan::noOfAttempts = 5;
	Scan::timeout = 10; 	//milliseconds

	/* test ping  */

	Discover obj;
	Ping ping;
	std::tuple<std::string, int> a = obj.split_CIDR("127.0.0.1/30");
	std::queue <Discover::request*> test= obj.handle_CIDR(std::get<0>(a), std::get<1>(a));
	std::vector<std::string> active_IPs = obj.discover_host(test);

	Scan trial;
	for(auto& i : active_IPs) {
		trial.initialize();
		trial.scan(ping.get_my_IP_address(), i, "SYN");
	}



	// Ping obj;
	// int sockfd = obj.open_icmp_socket();
	// obj.set_src_addr(sockfd, obj.get_my_IP_address("enp7s0"));
	// while(true) {
	// 	obj.ping_request(sockfd, "192.168.35.7", 1);
	// 	obj.ping_reply(sockfd);
	// }
    return 0;
}