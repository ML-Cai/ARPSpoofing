This program support an simple operator of ARP spoofing .

NOTE : 	DO NOT use this programing in illegal area , this program is written for education .

Current Release Version :

	Version 1.2 :   Add -i Control Operator ,
        	        Update Localhost IP/MAC information fetch function ,
                	Enhance -t Operator , add ARP table lookup capability .

	Version 1.0 :   Basic ARP Spoofing function
	Version 1.1 :   Add Control Operatior (-t , -s)

************************************************************************************************

-t [IP] : 

	Taget IP

-s [IP]/[MAC] : 

	Spoofing IP and MAC , 
	  IP format 	: OOO.OOO.OOO.OOO
	  MAC format 	: XX:XX:XX:XX:XX:XX


-i [interface :]

	choose which interface you want sending this packet .

-P : (unuse)

	this argument means "ignore"/"pass" inpute data format recognization ,
	program speeded up when using this operator , BUT is has some side effect ,
	please confirm your program argument legally , or it will cause some execute problem

************************************************************************************************

example :

	./ARP_Spoofing -t 192.168.0.3 -s 192.168.0.6/c8:a0:30:b6:5c:23 -i eth0

	spoofing host 192.168.0.3 the mac address of 192.168.0.6 is c8:a0:30:b6:5c:23 , using eth0
