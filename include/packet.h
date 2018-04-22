#ifndef PACKET_H
#define PACKET_H

#include "ping.h"
#include "error.h"
#include "logger.h"
#include <tuple>
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
    /*!
     * \brief logger object
     */
    Logger log;
    /*!
     * \brief Calculates the checksum (as specified in rfc793)
     * (Ref :: http:// www.binarytides.com/raw-sockets-c-code-on-linux/)
     * \param ptr typecasted packet payload
     * \param nbytes payload size
     * \return calculated checksum
     */
    unsigned short calcsum(unsigned short *ptr,int nbytes);

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

    /*!
     * \brief Add TCP header fields
     * \param tcpHdr starting pointer to TCP header
     * \param  srcPort source Port of socket
     */
    void populateTCPheader(struct tcphdr *tcpHdr, int srcPort);

    /*!
     * \brief Allocate a new socket and set IP_HDRINCL, SO_REUSEADDR, SO_RCVTIMEO options to it
     * Also bind socket to any free port 
     * \return created socket identifier
     */    
    int allocateSocket();

protected:
    int packetSize;

    /*!
     * \brief Calculates the TCP checksum by prepending pseudoTCPPacket to TCP header and calling checksum
     * (Ref :: http://www.freesoft.org/CIE/Course/Section4/8.htm)
     * \param srcIP source IP address
     * \param dstIP destination IP address
     * \param tcpHdr TCP header of the packet
     * \return calculated TCP checksum
     */    
    unsigned short calcsumTCP(const char* srcIP, const char* dstIP, struct tcphdr *tcpHdr);
    

public:
    Packet();

    /*!
     * \brief Create new socket using allocateSocket(), set it's properties & allocate an open port to it
     * \return tuple containing (socket, portNo, IP-address)
     */    
    std::tuple<int, int, std::string> open_socket();
    char* create_packet(const std::string &sourceIP, int srcPort, const std::string &destinationIP);




};

#endif // PACKET_H