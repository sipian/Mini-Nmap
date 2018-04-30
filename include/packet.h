#ifndef PACKET_H
#define PACKET_H

#include "ping.h"
#include "error.h"
#include "logger.h"
#include <tuple>
#include <stdlib.h>
#include <string.h>
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
     * \brief ping object to get IP address
     */
    Ping ping;

    /*!
     * \brief Pseudo header prepended to TCP header for TCP checksum
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
     * \brief Allocate a new RAW socket for sending => set IP_HDRINCL, SO_REUSEADDR options to it
     * \return sender socket identifier
     */
    int allocateSocket();

protected:
    int packetSize;

    /*!
     * \brief Calculates the checksum (as specified in rfc793)
     * \param ptr typecasted packet payload
     * \param nbytes payload size
     * \return calculated checksum
     */
    unsigned short calcsum(unsigned short *ptr,int nbytes);

    /*!
     * \brief Calculates the TCP checksum by prepending pseudoTCPPacket to TCP header and calling checksum
     * \param srcIP source IP address
     * \param dstIP destination IP address
     * \param tcpHdr TCP header of the packet
     * \return calculated TCP checksum
     */
    unsigned short calcsumTCP(const char* srcIP, const char* dstIP, struct tcphdr *tcpHdr);

public:
    Packet();

    /*!
     * \brief Allocate a new RAW socket for sending => set IP_HDRINCL, SO_REUSEADDR options to it
     * \return sender socket identifier, receiver socket identitfier , receiver port
     */
    std::tuple<int, int, int> open_socket();

    char* create_packet(const std::string &sourceIP, int srcPort, const std::string &destinationIP);
};

#endif // PACKET_H
