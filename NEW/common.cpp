#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packethdr.h"
#include <string.h>
#include <unistd.h>
#include <queue>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

using namespace std;
pcap_t *handle[2]; /* handles*/
char dir1,dir2; /* dir1,dir2 correspond to what direction the common node is*/
int SID; /* source ID*/


/*packet_proc: forwards the packet from one interface to another */

void packet_proc(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	pcap_t *handle_h = (pcap_t*)useless;
	int result;
	u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
	if(handle_h == handle[0]){
		result = pcap_inject(handle[1], pkt,sizeof(struct packet));
	}
	else{
		result = pcap_inject(handle[0], pkt,sizeof(struct packet));
	}
}

/*Initial information setup*/

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
    pcap_t *handle_h = (pcap_t*)useless;
    u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
    if(pkt->direction == 'I'){
    	pkt->direction = pkt->sub_direction; /*set the direction*/
        pkt->Vehicle_ID = 0;   /*Vehicle ID*/
        pkt->sub_direction = '-';
        pkt->Lane = SID; /*Lane (Redundant)*/
        pkt->SID = SID; /*Source ID*/
        pkt->DID = 5;     /*Destination ID (Redundant)*/
        printf("INFORMATION PACKET SENT\n");
        int result = pcap_inject(handle_h, pkt,sizeof(struct packet));
    }
    /*Invalid I-node packet*/
    else{
        printf("ERROR: I-NODE INFORMATION INCORRECT!!!!!\n");
        exit(1);
    }
}

/*forwarding thread*/
void* forwarding_thread(void *args){
	pcap_t * handle_h = (pcap_t *)args;
	pcap_loop(handle_h,1,procpkt,(u_char*)handle_h); /*initial information*/
	pcap_loop(handle_h,-1,packet_proc,(u_char*)handle_h); /* for packet forwarding*/
}

int main(int argc, const char * argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n, devNumber = 0;
    char host[NI_MAXHOST], allDevNames[2][5];
    pthread_t thread[2]; 		/*Thread ID*/
	bpf_u_int32 mask[2];		/* Our netmask */
	bpf_u_int32 net[2];		/* Our IP */
	struct bpf_program fp[2];		/* The compiled filter */
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	char errbuf[2][PCAP_ERRBUF_SIZE];	/* Error string */

 	dir1 = argv[1][0]; /* common node direction*/
 	dir2 = argv[2][0]; /*common node direction*/
 	SID = atoi(argv[3]); /* Source ID*/

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
            	strncpy(allDevNames[devNumber],ifa->ifa_name,4);
            	allDevNames[devNumber][4] = '\0';
            	devNumber++;
            }
        }
    }
    
    //free linked list
    freeifaddrs(ifaddr);
    for(int i = 0 ; i<2; i++){
		if (pcap_lookupnet(allDevNames[i], &net[i], &mask[i], errbuf[i]) == -1) {
    	    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", allDevNames[i], errbuf[i]);
        	net[i] = 0;
        	mask[i] = 0;
   	 	}
		if ((handle[i] = pcap_open_live(allDevNames[i], BUFSIZ, 1, 0, errbuf[i])) == NULL) {
  			fprintf(stderr, "ERROR: %s\n", errbuf[i]);
  			exit(1);
		}
        	    /* Compile and apply the filter */
    	if (pcap_compile(handle[i], &fp[i], filter_exp, 0, net[i]) == -1) {
        	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle[i]));
        	exit(0);
    	}
    	if (pcap_setfilter(handle[i], &fp[i]) == -1) {
        	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle[i]));
        	exit(0);
    	}
    }
    /*Update Sniffing thread on each interface */
    for(int i = 0; i < 2;i++){
    	pthread_create(&thread[i],NULL,forwarding_thread,handle[i]);
    }
    for(int i = 0; i < 2;i++){
    	pthread_join(thread[i],NULL);
    }


    return 0;
}