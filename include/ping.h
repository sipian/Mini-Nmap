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
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>

class Ping {
    Logger log;
    struct timeval timeout_tv;
    unsigned short calcsum(unsigned short* buffer, int length);
public:
    static int timeout;     //in microseconds
    Ping();
    int open_icmp_socket();
    std::string get_my_IP_address(const std::string &interface);
    void set_src_addr(int sockfd, const std::string &IP);
    void ping_request(int sockfd, const std::string &destinationIP, uint16_t icmp_seq_nr);
};

#endif // PING_H