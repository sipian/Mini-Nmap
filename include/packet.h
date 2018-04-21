#ifndef PACKET_H
#define PACKET_H

#include "ping.h"
#include "error.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*!
 * \brief The base class for manipulating packets
 * Various port scans will call this to set-up sockets, connections, etc.
 */
class Packet {
    Logger log;
    Ping ping;
    /*!
     * \brief Calculates the checksum (as specified in rfc793)
     * (Ref :: http:// www.binarytides.com/raw-sockets-c-code-on-linux/)
     * \param ptr typecasted packet payload
     * \param nbytes payload size
     * \return calculated checksum
     */
    unsigned short calcsum(unsigned short *ptr,int nbytes);

    /*!
     * \brief Calculates the TCP checksum by prepending pseudoTCPPacket to TCP header and calling checksum
     * (Ref :: http://www.freesoft.org/CIE/Course/Section4/8.htm)
     * \param srcIP source IP address
     * \param dstIP destination IP address
     * \param tcpHdr TCP header of the packet
     * \return calculated TCP checksum
     */    
    unsigned short calcsumTCP(const char* srcIP, const char* dstIP, struct tcphdr *tcpHdr);

    /*!
     * \brief Pseudo header prepended to TCP header for TCP checksum
     * (Ref :: http://www.freesoft.org/CIE/Course/Section4/8.htm)
     */
    struct pseudoTCPPacket {
        uint32_t srcAddr;
        uint32_t dstAddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t TCP_len;
    };
    bool reservePort(int sock, int port);
    int findFreePort(int sockfd);

protected:
    int packetSize;
    

public:
    Packet();
    int allocateSocket();
    void create_packet(const std::string &sourceIP, int srcPort, const std::string &destinationIP, int dstPort);




};

#endif // PACKET_H