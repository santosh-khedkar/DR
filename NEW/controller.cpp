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
   
char traffic_sig = '-';
u_short updt = 0; /*0000|Q4|Q5|Q6|Q12|Q11|Q10|Q1|Q2|Q3|Q9|Q8|Q7|*/
FILE *fplog;
FILE *fplog1 = fopen("traffic_sig.txt","w");
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
char allDevNames[4][5];


/*Returns the number of vehicles passing through the intersection*/

int get_no_veh_serviced(u_short update){
	u_short state = 0;
	int count = 0;

	if(traffic_sig == 'A'){
		if(update & (1<<11)){    /*check if Q4 bit is set*/
			count++;
		}
		if(update & (1<<6)){  /*check if Q10 bit is set*/
			count++;
		}
		if(update & (1)){  /*check if Q7 bit is set*/
			count++;
		}
		if(update & (1<<5)){  /*check if Q1 bit is set*/
			count++;
		}
		if(update & (1<<4)){  /*check if Q2 bit is set*/
			count++;
		}
		else if(update & (1<<2)){	/*check if Q9 bit is set*/
			count++;
		}
		if(update & (1<<1)){  /*check if Q8 bit is set*/
			count++;
		}
		else if(update & (1<<3)){	/*check if Q3 bit is set*/
			count++;
		}
	}
	else if(traffic_sig=='B'){
		if(update & (1<<11)){ /*check if Q4 bit is set*/
			count++;
		}
		if(update & (1<<6)){	/*check if Q10 bit is set*/
			count++;
		}
		if(update & (1)){	/*check if Q7 bit is set*/
			count++;
		}
		if(update & (1<<2)){	/*check if Q9 bit is set*/
			count++;
		}
		if(update & (1<<3)){	/*check if Q3 bit is set*/
			count++;
		}
		if(update & (1<<5)){	/*check if Q1 bit is set*/
			count++;
		}
	}
	else if(traffic_sig == 'C'){
		if(update & (1)){		/*check if Q7 bit is set*/
			count++;
		}
		if(update & (1<<5)){	/*check if Q1 bit is set*/
			count++;
		}
		if(update & (1<<11)){  /*check if Q4 bit is set*/
			count++;
		}
		if(update & (1<<6)){  /*check if Q10 bit is set*/
			count++;
		}
		if(update & (1<<10)){  /*check if Q5 bit is set*/
			count++;
		}
		else if(update & (1<<8)){	/*check if Q9 bit is set*/
			count++;
		}
		if(update & (1<<7)){  /*check if Q8 bit is set*/
			count++;
		}
		else if(update & (1<<9)){	/*check if Q3 bit is set*/
			count++;
		}
	}
	else if(traffic_sig=='D'){		
		if(update & (1)){		/*check if Q7 bit is set*/
			count++;
		}
		if(update & (1<<5)){	/*check if Q1 bit is set*/
			count++;
		}
		if(update & (1<<6)){	/*check if Q10 bit is set*/
			count++;
		}
		if(update & (1<<8)){	/*check if Q12 bit is set*/
			count++;
		}
		if(update & (1<<9)){	/*check if Q6 bit is set*/
			count++;
		}
		if(update & (1<<11)){	/*check if Q4 bit is set*/
			count++;
		}
	}
	return count;
}


void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	pcap_t *handle = (pcap_t *)useless;
    u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
    if(pkt->direction == 'I'){
        pkt->Vehicle_ID = 0;   /*Vehicle ID*/
        pkt->direction = 'C'; /*Direction N/E/S/W */
        pkt->sub_direction = '-';
        pkt->Lane = 0; 		/*Lane (Redundant)*/
        pkt->SID = 0; 		/*Source ID*/
        pkt->DID = 5;     /*Destination ID (Redundant)*/
        printf("INFORMATION PACKET SENT!!!\n");
        int result = pcap_inject(handle, pkt,sizeof(struct packet));
    }
    /*Invalid I-node packet*/
    else{
        printf("ERROR: I-NODE INFORMATION INCORRECT!!!!!\n");
        exit(1);
    }
}

void snapshot(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct state_t *st = (struct state_t *)(pac);	
	/*Processing South Update*/
	if(st->direction == 'S'){
		pthread_mutex_lock(&m);
		updt = updt & 65528;
		updt = updt | st->state;
		pthread_mutex_unlock(&m);
	}
	/*Processing North Update*/
	else if(st->direction == 'N'){
		pthread_mutex_lock(&m);
		updt = updt & 65479;
		updt = updt | (st->state<<3);
		pthread_mutex_unlock(&m);
	}
	/*Processing West Update*/
	else if(st->direction == 'W'){
		pthread_mutex_lock(&m);
		updt = updt & 65087;
		updt = updt | (st->state<<6);
		pthread_mutex_unlock(&m);
	}
	/*Processing East Update*/
	else if(st->direction == 'E'){
		pthread_mutex_lock(&m);
		updt = updt & 61951;
		updt = updt | (st->state<<9);
		pthread_mutex_unlock(&m);
	}
	/*Processing Faulty Update*/
	else{
		printf("UPDATE LOST\n");
	}
}


/*Send Update thread*/

void* send_update_thread(void *args){
	pcap_t *handle = (pcap_t *)args;
	struct state_t upst;	 /*Current Snapshot of the intersection*/
	int num_of_veh; 	/*No. of vehicles serviced*/
	u_int Transaction = 1; 	/*Transaction ID*/
	while(1){
		upst.direction = traffic_sig; /* Current traffic signal state*/
		upst.state = updt;		/* Snapshot*/
		num_of_veh= get_no_veh_serviced(upst.state); /* num of vehicals serviced based on taffic signal state*/
		/* Injecting update in all directions*/
		int result = pcap_inject(handle,&upst,sizeof(state_t));
		fprintf(fplog,"%d\n",num_of_veh);
		fflush(fplog);
		fprintf(fplog1,"%d\n",(int)upst.direction-65);
		fflush(fplog1);
		upst.direction = '-';
		upst.state = 0;
		Transaction++;
		usleep(1000000);  /*Sleep for 1 sec*/
	}
}
/*Update sniffing thread */

void* update_sniffing_thread(void *args){
	pthread_t send_update;
	pcap_t *handle = (pcap_t *)args;
	pcap_loop(handle,1,procpkt,(u_char*)handle);		
	pthread_create(&send_update,NULL,send_update_thread,handle);
	pcap_loop(handle,-1,snapshot,NULL);
}

/*Traffic Signal thread*/

void* trafficthread(void *args){
	int count=0;
	while(1){
		switch(count){
			case 0: 
				traffic_sig='A';
				usleep(25000000);
				count++;
				break;
			case 1:
				traffic_sig='B';
				usleep(5000000);
				count++;
				break;
			case 2: 
				traffic_sig='C';
				usleep(25000000);
				count++;
				break;
			case 3: 
				traffic_sig='D';
				usleep(5000000);
				count=0;
				break;
			default:
				traffic_sig='-';
				break; 				
		}
	}
}

void* recv_update_thread(void *args){
	pthread_t thread[4]; 		/*Thread ID*/
	pcap_t *handle[4];			/* Session handle */
	bpf_u_int32 mask[4];		/* Our netmask */
	bpf_u_int32 net[4];		/* Our IP */
	struct bpf_program fp[4];		/* The compiled filter */
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	char errbuf[4][PCAP_ERRBUF_SIZE];	/* Error string */
	/* Open Handle for the devices */
	for(int i = 0 ; i<4; i++){
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
    for(int i = 0; i < 4;i++){
    	pthread_create(&thread[i],NULL,update_sniffing_thread,handle[i]);
    }
    for(int i = 0; i < 4;i++){
    	pthread_join(thread[i],NULL);
    }
}





int main(int argc, const char * argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n,result, type, devNumber = 0;
    char host[NI_MAXHOST];

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

    fplog = fopen(argv[1],"w");
	pthread_t traffic_t, recv_update;
	/*Traffic thread*/
	pthread_create(&traffic_t,NULL,trafficthread,NULL);

	/*Update sniffing thread*/
	pthread_create(&recv_update,NULL,recv_update_thread,NULL);
	pthread_join(recv_update,NULL);		
	return 0;
}