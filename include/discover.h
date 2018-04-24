#ifndef DISCOVER_H
#define DISCOVER_H

#include "ping.h"
#include "error.h"
#include "logger.h"
#include <tuple>
#include <regex>
#include <queue>
#include <math.h>
#include <vector>
#include <stdlib.h>

/*!
 * \brief Class for discvering active IPs in a subnet using ping messages 
 */
class Discover {
    /*!
     * \brief logger object
     */
	Logger log;

    /*!
     * \brief ping object to perform ICMP scanning
     */
    Ping ping;

    /*!
     * \brief transforms an int IP into a.b.c.d format
     * \param IP in unsigned long int
     * \return IP in a.b.c.d notation
     */
	std::string get_IP_from_int(unsigned long int a);

    /*!
     * \brief transforms an IP string into integer
     * \param IP in a.b.c.d format
     * \return IP as unsigned long int
     */
    unsigned long int get_int_from_IP(std::string IP);

    /*!
     * \brief validates a CIDR input using regex
     * \param IP IP address in CIDR format
     * \return validation result
     */
	bool is_valid_CIDR(const std::string &IP);

    /*!
     * \brief split a CIDR expression into IP and netmask
     * \param IP IP address in CIDR format
     * \return tuple containing IP & netmask
     */	
	std::tuple<std::string, int> split_CIDR(const std::string &IP);

    /*!
     * \brief an element in the job queue, keeping track of unsuccessfull trials and sequence numbers
     */ 
    typedef struct request {
        std::string IP;
        int trial;
        uint16_t sequenceNo;
    } request;

    /*!
     * \brief makes queue containing #request objects for all IPs in subnet
     * \param IP IP address in a.b.c.d format
     * \param netmask subnet's netmask
     * \return queue of #request pointers
     */ 
    std::queue <request*> handle_CIDR(std::string IP, int netmask);
public:

    /*!
     * \brief static variable to hold maximum number of trials to ping IP to detect activeness
     */
    static int noOfAttempts;

    /*!
     * \brief In a round-robin manner discover active IP from queue found in handle_CIDR()
     * \param roundRobin queue of #request pointers
     * \return vector of active IPs
     */		
	std::vector<std::string> discover_host(const std::string &CIDR);
};

#endif // DISCOVER_H
