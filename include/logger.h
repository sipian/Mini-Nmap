#ifndef LOGGER_H
#define LOGGER_H

#include <ostream>
#include <iostream>
#include <string.h>

namespace Color {
    enum Code {
        FG_RED      = 31,
        FG_GREEN    = 32,
        FG_BLUE     = 34,
        FG_DEFAULT  = 39,
        FG_YELLOW   = 33,
        FG_CYAN     = 36,
        BG_RED      = 41,
        BG_GREEN    = 42,
        BG_BLUE     = 44,
        BG_DEFAULT  = 49
    };
    class Modifier {
        Code code;
    public:
        Modifier(Code pCode) : code(pCode) {}
        friend std::ostream&
        operator<<(std::ostream& os, const Modifier& mod) {
            return os << "\33[" << mod.code << "m";
        }
    };
}

/*!
 * \brief Class for printing log messages
 */
class Logger {
public:
    /*!
     * \brief enum of various log levels
     */ 
    enum logLevelNames{ERROR, WARN, INFO, DEBUG};

    /*!
     * \brief static variable to user log level choice
     */
    static enum logLevelNames logLevel;

    void error(const std::string &message);
    void warn(const std::string &message);
    void info(const std::string &message);
    void debug(const std::string &message);
    void result(const std::string &message);
};

/*
    Order of log levels
    1 - ERROR
    2 - WARN
    3 - INFO
    4 - DEBUG
*/

#endif // LOGGER_H
