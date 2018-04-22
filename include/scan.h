#ifndef SCAN_H
#define SCAN_H

#include "error.h"
#include "logger.h"
#include "packet.h"

#include <map>
#include <chrono>
#include <mutex>
#include <queue>
#include <vector>
#include <thread>
#include <pcap/pcap.h>

/*
	https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
*/

class Scan: public Packet {
    /*!
     * \brief logger object
     */
	Logger log;

    /*!
     * \brief mutex used when collecting result from all threads
     */
	std::mutex lock;

    /*!
     * \brief vector of threads for port-scanning
     */
	std::vector<std::thread> threads;


    /*!
     * \brief function called per thread to scan for ports
     * This adds the classfied ports in global vectors
     * \param srcIP IP of source host for port-scanning
     * \param dstIP IP of destination host for port-scanning
     * \param startPort start port-scanning from this port 
     * \param endPort end port-scanning at this port 
     * \param type what kind of scan is to be performed
     */	
    void scanPerThread(const std::string &srcIP, const std::string &destinationIP, uint16_t startPort, uint16_t endPort, std::string type);

	/*!
	 * \brief enum of port status
	 */	
	enum scanResult {
			OPEN,
			CLOSED,
			UNKNOWN
	};
    /*!
     * \brief check if received TCP header is as expected 
     * \param tcpHdr pointer to the TCP header
     * \param type what kind of scan is to be performed
     * \return status of current port
     */		
	scanResult checkTCPHeader(struct tcphdr *tcpHdr, std::string type);

    /*!
     * \brief set appropriate TCP flags according to type of port-scan
     * \param tcpHdr pointer to the TCP header
     * \param type what kind of scan is to be performed
     */	
    void setTCPHeader(struct tcphdr *tcpHdr, std::string type);

    /*!
     * \brief an element in the job queue, keeping track of unsuccessfull trials
     */	    
	typedef struct query {
		uint16_t port;
		int trial;
		int seqNo;		
	} query;

    /*!
     * \brief collect results from all threads into common vectors
     * \param open_Ports vector of open-ports calculated by a thread
     * \param closed_Ports vector of closed-ports calculated by a thread
     * \param unknown_Ports vector of unknown-ports calculated by a thread
     */	
	void finishTask(std::vector<uint16_t> &open_Ports, std::vector<uint16_t> &closed_Ports, std::vector<uint16_t> &unknown_Ports);

    /*!
     * map to store information obtained from sniffer
     */
    std::map<uint16_t, struct tcphdr*> sniffDetails;

    /*!
     * initializes pcap sniffer and sets filter
     * \param targetIP victim IP address to set filter
     * \return pcap handle pointer 
     */
    pcap_t* initializePcap(const std::string &targetIP);

    /*!
     * obtain port number from packet obtained by sniffer
     * \param packet packet payload obtained from sniffer
     * \return tuple containing src port and pointer to TCP header
     */
    std::tuple<uint16_t, struct tcphdr*> extractSrcPort(const u_char *packet);

    /*!
     * check with a timeout if packet from targer port is received or not
     * \param dstPort port under scanning
     * \return link to TCP header
     */
    struct tcphdr* recvPacket(uint16_t dstPort);

    /*!
     * start pcap sniffer to 
     * \param dstPort port under scanning
     * \return link to TCP header
     */
    void sniff(const std::string &targetIP);

    /*!
     * keep in sniffing packets until objective is achieved
     */
    bool objectiveAchieved;
public:

    /*!
     * \brief static variable to hold maximum number of threads for speedup
     */
	static int noOfThreads;

    /*!
     * \brief static variable to hold maximum number of trials to perform scan
     */
	static int noOfAttempts;

    /*!
     * \brief static variable to hold timeout in milliseconds for TCP response
     */    
    static int timeout;
    /*!
     * \brief vector containing list of open ports in 1 host
     */	
	std::vector<uint16_t> openPorts;

    /*!
     * \brief vector containing list of closed ports in 1 host
     */	
    std::vector<uint16_t> closedPorts;

    /*!
     * \brief vector containing list of unknown ports in 1 host
     */	
    std::vector<uint16_t> unknownPorts;

    /*!
     * \brief free threads and clear the vectors before starting a new scan
     */	   
	void initialize();
    
    /*!
     * \brief scan for port in a host
     * \param dstIP IP address of target host
     * \param type of port-scan to do
     */	   
    void scan(const std::string &srcIP, const std::string &dstIP, std::string type);
};
#endif // SCAN_H