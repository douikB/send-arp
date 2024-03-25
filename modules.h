#ifndef MODULES_H
#define MODULES_H
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>

class Modules
{
public:
    Modules();

    std::string getMACAddress(const std::string& interface);
};

#endif // MODULES_H
