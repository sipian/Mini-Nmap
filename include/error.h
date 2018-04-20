#ifndef ERROR_H
#define ERROR_H

#include <string>
#include <cstring>
#include <errno.h>

class Error {
public:
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
			NO_ACTIVE_IP
	};
	static std::string ErrStr() {
	   	char* e = std::strerror(errno);
	   	return e ? std::string(e) : "";
	}
};
#endif // ERROR_H