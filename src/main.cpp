#include <iostream>
#include "ping.h"
#include "logger.h"

int main() {
	Ping::timeout = 10;
	Logger::logLevel = Logger::WARN;

    std::cout << "Hello, World! :: " << std::endl;
    return 0;
}