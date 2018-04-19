#include <iostream>
#include "ping.h"
#include "logger.h"

int main() {
	Ping::timeout = 5e5;
	Logger::logLevel = Logger::DEBUG;
	/* test ping  */
	Ping obj;
	int sockfd = obj.open_icmp_socket();
	obj.set_src_addr(sockfd, obj.get_my_IP_address("enp7s0"));
	while(true) {
		obj.ping_request(sockfd, "192.168.35.7", 1);
		obj.ping_reply(sockfd);
	}
    std::cout << "Hello, World! :: " << std::endl;
    return 0;
}