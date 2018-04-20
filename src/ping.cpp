#include "ping.h"

int Ping::timeout;

Ping::Ping() {
    timeout_tv.tv_sec = 0;
    timeout_tv.tv_usec = Ping::timeout;
}

int Ping::open_icmp_socket() {

    log.debug("Ping::open_ping_socket => Creating an ICMP socket");
    struct protoent* proto = getprotobyname("icmp");

    /* Confirm that ICMP is available on this machine */
    if (! proto) {
        
        log.error("Ping::open_ping_socket => ICMP not a known protocol");
        throw Error::ICMP_UNKNOWN;
    }

    /* create raw socket for ICMP calls (ping) */
    int sockfd = socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (sockfd < 0) {
        sockfd = socket(AF_INET, SOCK_DGRAM, proto->p_proto);
        if (sockfd < 0) {
            log.error("Ping::open_ping_socket => Error in creating ICMP socket -- " + Error::ErrStr());
            throw Error::SOCKET_NOT_CREATED;
        }
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_tv, sizeof(timeout_tv)) < 0) {
        log.error("Ping::open_ping_socket => Error in creating timeout for socket connection -- " + Error::ErrStr());
        throw Error::TIMEOUT_NOT_CREATED;
    }

    /* Make sure that we use non-blocking IO */
    int flags;

    if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        log.warn("Ping::open_ping_socket => Error in making non-blocking IO -- " + Error::ErrStr());
        throw Error::NONBLOCKING_IO_NOT_CREATED;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log.warn("Ping::open_ping_socket => Error in making non-blocking IO -- " + Error::ErrStr());
        throw Error::NONBLOCKING_IO_NOT_CREATED;
    }
    return sockfd;
}

std::string Ping::get_my_IP_address(const std::string &interface) {
    struct ifaddrs * ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    void * tmpAddrPtr = NULL;
    std::string tmpInterface;
    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        tmpInterface = std::string(ifa->ifa_name);
        if (interface.compare(tmpInterface) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4 ,a valid IP4 Address
                tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                log.info("Ping::get_my_IP_address => My IP address is " + std::string(addressBuffer));
                return std::string(addressBuffer);
            }
        }
    }

    log.error("Ping::set_src_addr => Source IP not found of interface " + interface);
    throw Error::HOST_IP_MISSING;
}

void Ping::set_src_addr(int sockfd, const std::string &IP) {
    if (IP.empty()) {
        log.error("Ping::set_src_addr => Source IP not inputted");
        throw Error::INPUT_PARAMETER_MISSING;
    }

    struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(IP.c_str());
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log.error("Ping::set_src_addr => Error in binding ICMP socket to source");
		throw Error::SOCKET_NOT_BOUND;
	}
}

unsigned short Ping::calcsum(unsigned short* buffer, int length) {
    unsigned long sum;

    /* initialize sum to zero and loop until length (in words) is 0 */
    for (sum = 0; length > 1; length -= 2) {/* sizeof() returns number of bytes, we're interested in number of words */
        sum += *buffer++; /* add 1 word of buffer to sum and proceed to the next */
	}

    /* we may have an extra byte */
    if (length == 1) {
        sum += (char)*buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF); /* add high 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    return ~sum;
}

void Ping::ping_request(int sockfd, const std::string &destinationIP, uint16_t icmp_seq_nr) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(destinationIP.c_str());

    if (addr.sin_addr.s_addr == INADDR_NONE) {
        log.error("Ping::ping_request => echo ping to an invalid IP address -- " + destinationIP);
        throw Error::INVALID_IP;
    }

    struct icmp* icp = new (struct icmp);

    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;
    icp->icmp_seq = htons(icmp_seq_nr);
    icp->icmp_id = htons(getpid() & 0xFFFF);

    icp->icmp_cksum = calcsum((unsigned short*)icp, sizeof(struct icmp));

    if (sendto(sockfd, icp, sizeof(struct icmp), 0, (struct sockaddr*)(&addr), sizeof(struct sockaddr)) < 0) {
        log.error("Ping::ping_request => unable to send ICMP echo -- " + Error::ErrStr());
        delete icp;
        throw Error::UNABLE_TO_SEND_ICMP;
    }
    log.debug("Ping::ping_request => Sent ping echo to " + destinationIP);
    delete icp;
}

struct icmp* Ping::ping_reply(int sockfd) {
    struct icmp* icp = new (struct icmp);
    struct sockaddr senderAddr;
    socklen_t senderLen = sizeof(senderAddr);

    if (recvfrom(sockfd, icp, sizeof(struct icmp), 0, &senderAddr, &senderLen) < 0) {
        log.error("Ping::ping_reply => unable to receive ICMP reply -- " + Error::ErrStr());
        throw Error::UNABLE_TO_RECEIVE_ICMP;
    }

    char addressBuffer[INET_ADDRSTRLEN];
    void *tmpAddrPtr = &(((struct sockaddr_in*)(&senderAddr))->sin_addr);
    inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
    log.debug("Ping::ping_request => Received ping reply from " + std::string(addressBuffer));
    return icp;
}