#ifndef SNIFF_H
#define SNIFF_H

#include "error.h"
#include "logger.h"
#include "packet.h"

#include <map>
#include <atomic>
#include <unistd.h>

class Sniff : public Packet {
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
    bool process_packet(const char *packet, const std::string &targetIP);    
public:
    /*!
     * keep in sniffing packets until objective is achieved
     */
    std::atomic<bool> objectiveAchieved;

    /*!
     * \brief static variable to hold sniffer recvfrom packet size
     */
    static int packetSize;

    /*!
     * \brief static variable to hold timeout in seconds for socket
     */
    static int timeout_sec;

    /*!
     * \brief static variable to hold timeout in microseconds for socket
     */
    static int timeout_usec;

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