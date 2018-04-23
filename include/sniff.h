#ifndef SNIFF_H
#define SNIFF_H

#include "error.h"
#include "logger.h"

#include <map>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>

class Sniff {
    /*!
     * \brief logger object
     */
	Logger log;

    /*!
     * \brief Allocate a new RAW socket for sniffing
     * \return RAW socket identifier
     */
	int open_socket();

    /*!
     * obtain port number and TCP header from packet obtained by sniffer
     * \param packet packet payload obtained from sniffer
     * \param targetIP target host under scanning
     */
	void process_packet(const u_char *packet, const std::string &targetIP);    
public:
    /*!
     * keep in sniffing packets until objective is achieved
     */
    bool objectiveAchieved;

    /*!
     * \brief static variable to hold sniffer recvfrom packet size
     */
	static int packetSize;

    /*!
     * map to store port information obtained from sniffer
     */
    std::map<uint16_t, struct tcphdr*> sniffDetails;

    /*!
     * RAW socket sniffer
     * \param RAW socket identifier
     * \param targetIP target host under scanning
     */
	void sniff(const std::string &targetIP);
};

#endif // SNIFF_H