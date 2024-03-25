#ifndef MODULES_H
#define MODULES_H
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>

class Modules
{
public:
    Modules();

    std::string getMACAddress(const std::string& interface);
    std::string getInterfaceIP(const std::string& interfaceName);
};

#endif // MODULES_H
