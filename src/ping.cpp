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
            log.warn("Ping::open_ping_socket => Error in creating ICMP socket");
            throw Error::SOCKET_NOT_CREATED;
        }
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_tv, sizeof(timeout_tv)) < 0) {
        log.warn("Ping::open_ping_socket => Error in creating timeout for socket connection");
        throw Error::TIMEOUT_NOT_CREATED;
    }

    /* Make sure that we use non-blocking IO */
    int flags;

    if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        log.error("Ping::open_ping_socket => Error in making non-blocking IO");
        throw Error::NONBLOCKING_IO_NOT_CREATED;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log.error("Ping::open_ping_socket => Error in making non-blocking IO");
        throw Error::NONBLOCKING_IO_NOT_CREATED;
    }
    return sockfd;
}

void Ping::set_src_addr(int sockfd, const string &IP)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(IP.c_str());
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log.warn("Ping::socket_set_src_addr_ipv4 => Error in binding ICMP socket");
		throw Error::SOCKET_NOT_BOUND;
	}
}

// unsigned short Ping::calcsum(unsigned short* buffer, int length)
// {
//     unsigned long sum;

//     /* initialize sum to zero and loop until length (in words) is 0 */
//     for (sum = 0; length > 1; length -= 2) {/* sizeof() returns number of bytes, we're interested in number of words */
//         sum += *buffer++; /* add 1 word of buffer to sum and proceed to the next */
// 	}

//     /* we may have an extra byte */
//     if (length == 1) {
//         sum += (char)*buffer;
//     }

//     sum = (sum >> 16) + (sum & 0xFFFF); /* add high 16 to low 16 */
//     sum += (sum >> 16); /* add carry */
//     return ~sum;
// }

// int Ping::ping_request(int sockfd, struct sockaddr* saddr, socklen_t saddr_len, uint16_t icmp_seq_nr, uint16_t icmp_id_nr)
// {
//     struct icmp* icp;
//     int n;

//     icp = (struct icmp*)ping_buffer_ipv4;

//     icp->icmp_type = ICMP_ECHO;
//     icp->icmp_code = 0;
//     icp->icmp_cksum = 0;
//     icp->icmp_seq = htons(icmp_seq_nr);
//     icp->icmp_id = htons(icmp_id_nr);

//     icp->icmp_cksum = calcsum((unsigned short*)icp, ping_pkt_size_ipv4);

//     n = sendto(s, icp, ping_pkt_size_ipv4, 0, saddr, saddr_len);

//     return n;
// }
