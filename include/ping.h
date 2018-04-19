#ifndef PING_H
#define PING_H

#include "error.h"
#include "logger.h"
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>

using namespace std;

class Ping {
	Logger log;
	struct timeval timeout_tv;
public:
	static int timeout; 	//in microseconds
	Ping();
	int open_icmp_socket();
	void set_src_addr(int sockfd, const string &IP);
	// int ping_request(int sockfd, struct sockaddr* saddr, socklen_t saddr_len, uint16_t icmp_seq_nr, uint16_t icmp_id_nr);
	// unsigned short calcsum(unsigned short* buffer, int length);
};

#endif // PING_H