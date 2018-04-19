#ifndef ERROR_H
#define ERROR_H

class Error {
public:
		enum error {
			ICMP_UNKNOWN,
			SOCKET_NOT_CREATED,
			TIMEOUT_NOT_CREATED,
			NONBLOCKING_IO_NOT_CREATED,
			SOCKET_NOT_BOUND
	};
};
#endif // ERROR_H