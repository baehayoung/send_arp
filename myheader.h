#ifndef MYHEADER_H
#define MYHEADER_H

#include <stdint.h>
#include <netinet/in.h>


struct arpHeader{
    uint16_t hwType= htons(0x0001);
    uint16_t protoType = htons(0x0800);
    uint8_t hwLenv=0x06;
    uint8_t protoLen =0x04;
    uint16_t opCode;
    uint8_t sMac[6];
    uint8_t sIP[4];
    uint8_t tMac[6];
    uint8_t tIP[4];
};

struct mEther{
    uint8_t dEther[6];
    uint8_t sEther[6];
    uint16_t type = htons(0x0806);
};

#endif // MYHEADER_H
