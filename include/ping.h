#ifndef PING_H
#define PING_H

#include "error.h"
#include "logger.h"
#include <memory>
#include <netdb.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

/*!
 * \brief Class for making and receiving ping requests
 */
class Ping {
    /*!
     * \brief logger object
     */
    Logger log;

    /*!
     * \brief Calculates the checksum for ICMP (as specified in rfc1071)
     * (Ref :: https://tools.ietf.org/html/rfc1071#section-4.1)
     * \param buffer typecasted ICMP pakcet
     * \param length ICMP packet size
     * \return calculated checksum
     */
    unsigned short calcsum(unsigned short* buffer, int length);

public:
    /*!
     * \brief static variable to hold interface to be used for the port scan
     */
    static std::string interface;

    /*!
     * \brief static variable to hold recvfrom timeout in microseconds
     */
    static int timeout;

    /*!
     * \brief opens a new ICMP socket and sets SO_RCVTIMEO to Ping::timeout
     * \return ICMP socket identifier
     */
    int open_icmp_socket();

    /*!
     * \brief static function to get current host's IPv4 address on interface Ping::interface
     * \return Host's IPv4 address
     */
    std::string get_my_IP_address();

    /*!
     * \brief Bind source IP to socket
     * \param sockfd socket
     * \param IP source IP address in a.b.c.d notation
     */
    void set_src_addr(int sockfd, const std::string &IP);

    /*!
     * \brief Send an ICMP request message (using sendto) to a destination IP
     * \param sockfd socket
     * \param destinationIP IP address of destination host in a.b.c.d notation
     * \param icmp_seq_nr sequence number of the ICMP packet
     */
    void ping_request(int sockfd, const std::string &destinationIP, uint16_t icmp_seq_nr);

    /*!
     * \brief Waits Ping::timeout for an ICMP reply
     * \param sockfd socket
     * \return IP address of host machine from which the ICMP reply was received
     */
    std::string ping_reply(int sockfd);
};

#endif // PING_H
