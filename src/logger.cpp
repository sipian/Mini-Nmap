#include "logger.h"

Logger::logLevelNames Logger::logLevel;

void Logger::error(const std::string &message) {
    if (Logger::logLevel >= Logger::ERROR) {
        Color::Modifier red(Color::FG_RED);
        Color::Modifier def(Color::FG_DEFAULT);
        std::cout << red << message << def << std::endl;
    }
}

void Logger::warn(const std::string &message) {
    if (Logger::logLevel >= Logger::WARN) {
        Color::Modifier yellow(Color::FG_YELLOW);
        Color::Modifier def(Color::FG_DEFAULT);
        std::cout << yellow << message << def << std::endl;
    }
}

void Logger::info(const std::string &message) {
    if (Logger::logLevel >= Logger::INFO) {
        Color::Modifier green(Color::FG_GREEN);
        Color::Modifier def(Color::FG_DEFAULT);
        std::cout << green << message << def << std::endl;
    }
}

void Logger::debug(const std::string &message) {
    if (Logger::logLevel >= Logger::DEBUG) {
        Color::Modifier blue(Color::FG_BLUE);
        Color::Modifier def(Color::FG_DEFAULT);
        std::cout << blue << message << def << std::endl;
    }
}

void Logger::result(const std::string &message) {
        Color::Modifier cyan(Color::FG_CYAN);
        Color::Modifier def(Color::FG_DEFAULT);
        std::cout << cyan << message << def << std::endl;
}
