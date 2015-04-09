#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include "packethdr.h"
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

using namespace std;

pcap_t *handle = NULL;

/*Sending the Initial information packet*/

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
    char **argv = (char **)useless;
    u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
    if(pkt->direction == 'I'){
        pkt->Vehicle_ID = 0;   /*Vehicle ID*/
        pkt->direction = argv[1][0]; /*Direction N/E/S/W */
        pkt->sub_direction = '-';
        pkt->Lane = atoi(argv[2]); /*Lane (Redundant)*/
        pkt->SID = atoi(argv[2]); /*Source ID*/
        pkt->DID = 5;     /*Destination ID (Redundant)*/
        printf("INFORMATION PACKET SENT\n");
        int result = pcap_inject(handle, pkt,sizeof(struct packet));
    }
    /*Invalid I-node packet*/
    else{
        printf("ERROR: I-NODE INFORMATION INCORRECT!!!!!\n");
        exit(1);
    }
}

int main(int argc, const char * argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n,result, type;
    char host[NI_MAXHOST],interface[4],errbuf[PCAP_ERRBUF_SIZE],filter_exp[]="(ether proto !(0x88cc) and !(stp))";
    struct packet *pkt= (struct packet*)malloc(sizeof(struct packet));
	struct bpf_program fp;
    bpf_u_int32 mask,net;


    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    //Walk through the linked list maintaining head pointer for freeing memory
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        //get the interface family from the interface
        family = ifa->ifa_addr->sa_family;
        
        //check for ipv4 addresses only excluding loopback
        if (family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            
            //obtain the host name and check for errors
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            
            if(!(strncmp("192",host,3) == 0)){
            	strncpy(interface,ifa->ifa_name,4);
            }
        }
    }
    //free linked list
    freeifaddrs(ifaddr);

    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
        net = 0;
        mask = 0;
    }
	if ((handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERROR: %s\n", errbuf);
  		exit(1);
	}
            /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(0);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(0);
    }

    /*Looping to tell the I-node its presence*/
    pcap_loop(handle,1,procpkt,(u_char*)argv);

	/* Initializing packet*/
	pkt->Vehicle_ID = 1;   /*Vehicle ID*/
	pkt->direction = argv[1][0]; /*Direction N/E/S/W*/
	pkt->Lane = atoi(argv[2]); /*Lane (Redundant)*/
	pkt->SID = atoi(argv[2]); /*Source ID*/
	type = atoi(argv[3]); 	/*Type: CBR/Poisson*/
	pkt->DID = 5; 	/*Destination ID (Redundant)*/
	/*End of initialization*/
    usleep(1000000);
    printf("BEGIN TRANSMISSION\n");
	while(1){
		pkt->Vehicle_ID++;
		/*Contant bit Rate*/
		if(type==0){
			/*Sleep for 1 sec*/
			usleep(5000000);
		}
		/*Poisson*/
		else if(type==1){
			int halt = rand()%1000000;
			usleep(halt);	
		}	
		/*Inject packets*/
		result = pcap_inject(handle, pkt,sizeof(struct packet));			
	}
    return 0;
}