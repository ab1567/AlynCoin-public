#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <string>

class Logger {
public:
    static void info(const std::string& msg);
    static void warn(const std::string& msg);
    static void error(const std::string& msg);
    static void success(const std::string& msg);
};

#endif // LOGGER_H
