#include <pcap.h>
#include <cstdio>
#include "myheader.h"
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>

void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp enp0s3 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  unsigned char* packetReq = (unsigned char*)malloc(sizeof(char)*42);

  int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct ifreq ifr;
  strcpy(ifr.ifr_name, argv[1]);

  ioctl(fd,SIOCGIFHWADDR, &ifr);

  struct mEther * myEther;
  struct arpHeader * arpH;
  char *dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  myEther = (mEther *)malloc(sizeof(mEther));
  arpH = (arpHeader *)malloc(sizeof(arpHeader));
   for(int i=0; i<6; i++) myEther->dEther[i]=0xff;

  inet_pton(AF_INET,ifr.ifr_addr.sa_data+2,arpH->sIP);
  inet_pton(AF_INET,argv[2],arpH->tIP);

  memcpy(myEther->sEther, (unsigned char*)ifr.ifr_hwaddr.sa_data,6);
  arpH->opCode = htonl(0x0001);
  for(int i=0; i<6; i++)
      arpH->tMac[i] = 0x00;

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  packetReq = (unsigned char*)strcat((char*)myEther,(char*)arpH);
  pcap_sendpacket(handle,(unsigned char*)packetReq, sizeof(packetReq));

  while (true) {
    struct pcap_pkthdr* header;

    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res != 0) break;

    const struct mEther* mEthernet = reinterpret_cast<const struct mEther*>(packet);
    if(mEthernet->type == ntohs(0x0806)){
        struct mEther *newEther = (mEther*)malloc(sizeof (mEther));
        struct arpHeader *newArp = (arpHeader *)malloc(sizeof(arpHeader));
        newEther->dEther[0] = *mEthernet->sEther;
        newEther->sEther[0] = *mEthernet->dEther;
        inet_pton(AF_INET,argv[3],newArp->sIP);
        inet_pton(AF_INET,argv[2],newArp->tIP);
        packetReq = (unsigned char*)strcat((char*)myEther,(char*)arpH);
        pcap_sendpacket(handle,(unsigned char*)packetReq, sizeof(packetReq));
    }
  }

  pcap_close(handle);

  free(arpH);
  free(myEther);

  return 0;
}
