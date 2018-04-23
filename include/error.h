#ifndef ERROR_H
#define ERROR_H

#include <string>
#include <cstring>
#include <errno.h>

/*!
 * \brief Class for storing Error types
 */
class Error {
public:
		/*!
		 * \brief enum of Error types
		 */	
		enum error {
			ICMP_UNKNOWN,
			SOCKET_NOT_CREATED,
			TIMEOUT_NOT_CREATED,
			SOCKET_NOT_BOUND,
			HOST_IP_MISSING,
			INPUT_PARAMETER_MISSING,
			INVALID_IP,
			UNABLE_TO_SEND_ICMP,
			UNABLE_TO_RECEIVE_ICMP,
			INVALID_CHECKSUM,
			NO_ACTIVE_IP,
			IP_HDRINCL_NOT_SET,
			SO_REUSEADDR_NOT_SET,
			RESOURCE_BUSY,
			NO_FREE_PORT,
			UNABLE_TO_GET_SOCKET_DETAILS,
			INVALID_PORT,
			UNABLE_TO_SNIFF,
			INVALID_FILTER,
			OTHER_PACKET
	};
	
	/*!
	 * \brief get string form of errno
	 */	
	static std::string ErrStr() {
	   	char* e = std::strerror(errno);
	   	return e ? std::string(e) : "";
	}
};
#endif // ERROR_H