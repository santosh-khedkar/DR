#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <queue>
#include "packethdr.h"
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

using namespace std;

char dir; /* direction of the I-node*/
FILE *fplog; /*log file */
FILE *fplog1;
int fwd_int = 0; /*NESW*/ 
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
char allDevNames[5][5]; /*interface names*/
pcap_t *input_h[3],*Fwd_h,*Contrl_h; /*session handles*/

/*input queues*/
queue<packet*> Q1;
queue<packet*> Q2;
queue<packet*> Q3;

int get_no_veh_serviced(u_short update, char signal_t){
    int count = 0;
    int count_N = 0,count_S = 0,count_W = 0,count_E = 0;
    if(signal_t == 'A'){
        if(update & (1<<11)){    /*check if Q4 bit is set*/
            count++;
            count_E++;
        }
        if(update & (1<<6)){  /*check if Q10 bit is set*/
            count++;
            count_W++;
        }
        if(update & (1)){  /*check if Q7 bit is set*/
            count++;
            count_S++;
        }
        if(update & (1<<5)){  /*check if Q1 bit is set*/
            count++;
            count_N++;
        }
        if(update & (1<<4)){  /*check if Q2 bit is set*/
            count++;
            count_N++;
        }
        else if(update & (1<<2)){   /*check if Q9 bit is set*/
            count++;
            count_S++;
        }
        if(update & (1<<1)){  /*check if Q8 bit is set*/
            count++;
            count_S++;
        }
        else if(update & (1<<3)){   /*check if Q3 bit is set*/
            count++;
            count_N++;
        }
    }
    else if(signal_t =='B'){
        if(update & (1<<11)){ /*check if Q4 bit is set*/
            count++;
            count_E++;
        }
        if(update & (1<<6)){    /*check if Q10 bit is set*/
            count++;
            count_W++;
        }
        if(update & (1)){   /*check if Q7 bit is set*/
            count++;
            count_S++;
        }
        if(update & (1<<2)){    /*check if Q9 bit is set*/
            count++;
            count_S++;
        }
        if(update & (1<<3)){    /*check if Q3 bit is set*/
            count++;
            count_N++;
        }
        if(update & (1<<5)){    /*check if Q1 bit is set*/
            count++;
            count_N++;
        }
    }
    else if(signal_t == 'C'){
        if(update & (1)){       /*check if Q7 bit is set*/
            count++;
            count_S++;
        }
        if(update & (1<<5)){    /*check if Q1 bit is set*/
            count++;
            count_N++;
        }
        if(update & (1<<11)){  /*check if Q4 bit is set*/
            count++;
            count_E++;
        }
        if(update & (1<<6)){  /*check if Q10 bit is set*/
            count++;
            count_W++;
        }
        if(update & (1<<10)){  /*check if Q5 bit is set*/
            count++;
            count_E++;
        }
        else if(update & (1<<8)){   /*check if Q12 bit is set*/
            count++;
            count_W++;
        }
        if(update & (1<<7)){  /*check if Q11 bit is set*/
            count++;
            count_W++;
        }
        else if(update & (1<<9)){   /*check if Q6 bit is set*/
            count++;
            count_E++;
        }
    }
    else if(signal_t =='D'){      
        if(update & (1)){       /*check if Q7 bit is set*/
            count++;
            count_S++;
        }
        if(update & (1<<5)){    /*check if Q1 bit is set*/
            count++;
            count_N++;
        }
        if(update & (1<<6)){    /*check if Q10 bit is set*/
            count++;
            count_W++;
        }
        if(update & (1<<8)){    /*check if Q12 bit is set*/
            count++;
            count_W++;
        }
        if(update & (1<<9)){    /*check if Q6 bit is set*/
            count++;
            count_E++;
        }
        if(update & (1<<11)){   /*check if Q4 bit is set*/
            count++;
            count_E++;
        }
    }
    if(dir == 'N'){
        return count_N;
    }
    else if(dir == 'E'){
        return count_E;
    }
    else if(dir == 'S'){
        return count_S;
    }
    else if(dir == 'W'){
        return count_W;
    }
}



/*Update sending thread*/

void *send_update_thread(void *args){
	struct state_t st;
	st.direction=dir;
	st.state=0;
	pcap_t* handle = (pcap_t*) args;
	while(1){
		st.state=0;
        /*calculate state wrt its queues*/
		if(!Q1.empty()){
			st.state=st.state|1;
		}
		if(!Q2.empty()){
			st.state=st.state|2;
		}
		if(!Q3.empty()){
			st.state=st.state|4;
		}
        /*update the controller*/
		int result = pcap_inject(handle,&st,sizeof(state_t));
		usleep(1000000);
	}
}


/*return true if the I-node is forwarder in that specific direction (0000NESW) */
bool check_fwd_int(char direction){
	switch(direction){
		case 'N':
			if(fwd_int & (1<<3)){
				return true;
			}
			else{
				return false;
			}
			break;
		case 'E':
			if(fwd_int & (1<<2)){
				return true;
			}
			else{
				return false;
			}
			break;
		case 'S':
			if(fwd_int & (1<<1)){
				return true;
			}
			else{
				return false;
			}
			break;
		case 'W':
			if(fwd_int & (1)){
				return true;
			}
			else{
				return false;
			}
			break;
		default:
			return false;
			break;
	}
}
/*Take action after upate from the controller*/
void Take_action(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
    struct state_t *st = (struct state_t *)(pac);
    struct packet *pkt;
    int num_of_veh = get_no_veh_serviced(st->state,st->direction);
    fprintf(fplog,"%d ",num_of_veh);
    fflush(fplog);
    fprintf(fplog1,"%d ",(int)st->direction-65); /*0-A, 1-B, 2-C, 4-D*/
    fflush(fplog1);
    u_short state = 0;
    int result;
    /*If north or South I-node*/
    if(dir == 'N' || dir == 'S'){
    	if(st->direction == 'A'){
            /*North I-node*/
    		if(dir == 'N'){
    			if(!Q1.empty()){
    				if(check_fwd_int('W')){ /*check if west I-node is forward I-node*/
    					printf("1: Forwarding packet from Q1:%lu\n",Q1.size());
    					pkt = Q1.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("1: Servicing Q1:%lu\n", Q1.size());
    				}
    				Q1.pop();
    			}
    			if(!Q2.empty()){
    				if(check_fwd_int('S')){ /*check if south I-node is forward I-node*/
    					printf("2: Forwarding packet from Q2:%lu\n",Q2.size());
    					pkt = Q2.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("2: Servicing Q2:%lu\n", Q2.size());
    				}
    				Q2.pop();
    			}
    			if((st->state & (1<<1)) && (!Q3.empty())){ /* if Q8 is not set*/
    				if(check_fwd_int('E')){/*check if east I-node is forward I-node*/
    					printf("3: Forwarding packet from Q3:%lu\n",Q3.size());
    					pkt = Q3.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("3: Servicing Q3:%lu\n", Q3.size());
    				}
    				Q3.pop();
    			}
    		}
            /*South I-node*/
    		else{
    			if(!Q2.empty()){
    				if(check_fwd_int('N')){ /*check if North I-node is forward I-node*/
    					printf("4: Forwarding packet from Q2:%lu\n",Q2.size());
    					pkt = Q2.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("4: Servicing Q2:%lu\n", Q2.size());
    				}
    				Q2.pop();
    			}
    			if(!Q3.empty()){
    				if(check_fwd_int('E')){     /*check if east I-node is forward I-node*/
    					printf("5: Forwarding packet from Q3:%lu\n",Q3.size());
    					pkt = Q3.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("5: Servicing Q3:%lu\n", Q3.size());
    				}
    				Q3.pop();
    			}
    			if((st->state & (1<<4)) && (!Q1.empty())){ /*if Q4 is not set*/
    				if(check_fwd_int('W')){     /*check if west I-node is forward I-node*/
    					printf("6: Forwarding packet from Q1:%lu\n",Q1.size());
    					pkt = Q1.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("6: Servicing Q1:%lu\n", Q1.size());
    				}
    				Q1.pop();
    			}
    		}
    	}
    	else if(st->direction == 'B'){
    		if(!Q1.empty()){
    			if(check_fwd_int('W')){ /*check if west I-node is forward I-node*/
    				printf("7: Forwarding packet from Q1:%lu\n",Q1.size());
    				pkt = Q1.front();
    				result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    			}
    			else{
    				printf("7: Servicing Q1:%lu\n", Q1.size());
    			}
    			Q1.pop();
    		}
    		if(!Q3.empty()){
    			if(check_fwd_int('E')){  /*check if east I-node is forward I-node*/
    				printf("8: Forwarding packet from Q3:%lu\n",Q3.size());
    				pkt = Q3.front();
    				result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    			}
    			else{
    				printf("8: Servicing Q3:%lu\n", Q3.size());
    			}
    			Q3.pop();
    		}
    	}
    	else if(st->direction == 'C' || st->direction == 'D'){
    		if(dir == 'N'){
    			if(!Q1.empty()){
    				if(check_fwd_int('W')){ /*check if west I-node is forward I-node*/
    					printf("9: Forwarding packet from Q1:%lu\n",Q1.size());
    					pkt = Q1.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("9: Servicing Q1:%lu\n", Q1.size());
    				}
    				Q1.pop();
    			}
    		}
    		else{
    			if(!Q3.empty()){
    				if(check_fwd_int('E')){ /*check if east I-node is forward I-node*/
    					printf("10: Forwarding packet from Q3:%lu\n",Q3.size());
    					pkt = Q3.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("10: Servicing Q3:%lu\n", Q3.size());
    				}
    				Q3.pop();
    			}
    		}
    	}
    }
    /*East-West I-node*/
    else if(dir == 'E' || dir == 'W'){
    	if(st->direction == 'C'){
            /*East I-node*/
    		if(dir == 'E'){
    			if(!Q1.empty()){
    				if(check_fwd_int('N')){ /*check if North I-node is forward I-node*/
    					printf("11: Forwarding packet from Q1:%lu\n",Q1.size());
    					pkt = Q1.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("11: Servicing Q1:%lu\n", Q1.size());
    				}
    				Q1.pop();
    			}
    			if(!Q2.empty()){
    				if(check_fwd_int('W')){ /*check if west I-node is forward I-node*/
    					printf("12: Forwarding packet from Q2:%lu\n",Q2.size());
    					pkt = Q2.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("12: Servicing Q2:%lu\n", Q2.size());
    				}
    				Q2.pop();
    			}
    			if((st->state & (1<<7)) && (!Q3.empty())){ /* if Q11 is not set*/
    				if(check_fwd_int('S')){/*check if South I-node is forward I-node*/
    					printf("13: Forwarding packet from Q3:%lu\n",Q3.size());
    					pkt = Q3.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("13: Servicing Q3:%lu\n", Q3.size());
    				}
    				Q3.pop();
    			}
    		}
            /*West I-node*/
    		else{
    			if(!Q2.empty()){
    				if(check_fwd_int('E')){ /*check if east I-node is forward I-node*/
    					printf("14: Forwarding packet from Q2:%lu\n",Q2.size());
    					pkt = Q2.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("14: Servicing Q2:%lu\n", Q2.size());
    				}
    				Q2.pop();
    			}
    			if(!Q3.empty()){
    				if(check_fwd_int('S')){     /*check if south I-node is forward I-node*/
    					printf("15: Forwarding packet from Q3:%lu\n",Q3.size());
    					pkt = Q3.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("15: Servicing Q3:%lu\n", Q3.size());
    				}
    				Q3.pop();
    			}
    			if((st->state & (1<<10)) && (!Q1.empty())){
    				if(check_fwd_int('N')){ /*check if North I-node is forward I-node*/
    					printf("16: Forwarding packet from Q1:%lu\n",Q1.size());
    					pkt = Q1.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("16: Servicing Q1:%lu\n", Q1.size());
    				}
    				Q1.pop();
    			}
    		}
    	}
    	else if(st->direction == 'D'){
    		if(!Q1.empty()){
    			if(check_fwd_int('N')){      /*check if North I-node is forward I-node*/
    				printf("17: Forwarding packet from Q1:%lu\n",Q1.size());
    				pkt = Q1.front();
    				result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    			}
    			else{
    				printf("17: Servicing Q1:%lu\n", Q1.size());
    			}
    			Q1.pop();
    		}
    		if(!Q3.empty()){
    			if(check_fwd_int('S')){      /*check if South I-node is forward I-node*/
    				printf("18: Forwarding packet from Q3:%lu\n",Q3.size());
    				pkt = Q3.front();
    				result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    			}
    			else{
    				printf("18: Servicing Q3:%lu\n", Q3.size());
    			}
    			Q3.pop();
    		}
    	}
    	else if(st->direction == 'A' || st->direction == 'B'){
    		if(dir == 'E'){
    			if(!Q1.empty()){
    				if(check_fwd_int('N')){ /*check if North I-node is forward I-node*/
    					printf("19: Forwarding packet from Q1:%lu\n",Q1.size());
    					pkt = Q1.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("19: Servicing Q1:%lu\n", Q1.size());
    				}
    				Q1.pop();
    			}
    		}
    		else{
    			if(!Q3.empty()){
    				if(check_fwd_int('S')){ /*check if South I-node is forward I-node*/
    					printf("20: Forwarding packet from Q3:%lu\n",Q3.size());
    					pkt = Q3.front();
    					result = pcap_inject(Fwd_h, pkt,sizeof(struct packet));
    				}
    				else{
    					printf("20: Servicing Q3:%lu\n", Q3.size());
    				}
    				Q3.pop();
    			}
    		}
    	}
    }     
}

/*Update receiving thread*/

void *recv_update_thread(void *args){
	pcap_t* handle = (pcap_t*)args;
	pcap_loop(handle,-1,Take_action,NULL);
}

/*Initial packet processing*/
void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	pcap_t *handle = (pcap_t *)useless;
	u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
    /*Control handle*/
    if(pkt->direction == 'C'){
    	Contrl_h = handle;
    }
    /*Forward handle*/
    else if(pkt->direction == 'F'){
    	Fwd_h = handle;
    }
    /*input handles*/
    else if(pkt->direction == 'N' || pkt->direction == 'S' || pkt->direction == 'W' || pkt->direction == 'E'){
    	if(pkt->SID == 1){
    		input_h[0] = handle;
    	}
    	else if(pkt->SID == 2){
    		input_h[1] = handle;
    	}
    	else if(pkt->SID == 3){
    		input_h[2] = handle;
    	}
    }
    else{
    	printf("ERROR: WRONG INFORMATION!!!!\n");
    	exit(0);
    }
}

/*Packet processing*/

void packet_proc(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct packet *pkt = (struct packet *)(pac);
	int result;
    /*If packets comming from an input node*/
	if(pkt->direction == dir){
		if(pkt->SID == 1){
			Q1.push(pkt);
		}
		else if(pkt->SID == 2){
			Q2.push(pkt);
		}
		else if(pkt->SID == 3){
			Q3.push(pkt);
		}
		else{
			printf("ERROR: FAULTY PACKET\n");
		}
	}
    /*Its a forward packet*/
	else{
		printf("FORWARD PACKET!!\n");

        /*Forward to the respective handle depending upon the direction and SID*/
		if(pkt->direction == 'N'){
			if(pkt->SID == 1){
				result = pcap_inject(input_h[0], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 2){
				result = pcap_inject(input_h[1], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 3){
				result = pcap_inject(input_h[0], pkt,sizeof(struct packet));
			}
		}
		else if(pkt->direction == 'E'){
			if(pkt->SID == 1){
				result = pcap_inject(input_h[2], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 2){
				result = pcap_inject(input_h[1], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 3){
				result = pcap_inject(input_h[2], pkt,sizeof(struct packet));
			}
		}
		else if(pkt->direction == 'S'){
			if(pkt->SID == 1){
				result = pcap_inject(input_h[2], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 2){
				result = pcap_inject(input_h[1], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 3){
				result = pcap_inject(input_h[2], pkt,sizeof(struct packet));
			}
		}
		else if(pkt->direction == 'W'){
			if(pkt->SID == 1){
				result = pcap_inject(input_h[0], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 2){
				result = pcap_inject(input_h[1], pkt,sizeof(struct packet));
			}
			else if(pkt->SID == 3){
				result = pcap_inject(input_h[0], pkt,sizeof(struct packet));
			}
		}
	}
}

/*Node_I thread*/

void* nodeI_thread(void *args){
	pcap_t* handle = (pcap_t*)args;
	pthread_t send_update,recv_update;
	struct packet *pkt= (struct packet*)malloc(sizeof(struct packet));
	pkt->Vehicle_ID = 0;   /*Vehicle ID*/
    pkt->direction = 'I'; /*Direction N/E/S/W */
    pkt->sub_direction = dir; /* To distinguish between the I-node*/
    pkt->Lane = 0; 		/*Lane (Redundant)*/
    pkt->SID = 0; 		/*Source ID*/
    pkt->DID = 5;     /*Destination ID (Redundant)*/
	int result = pcap_inject(handle, pkt,sizeof(struct packet));
	pcap_loop(handle,1,procpkt,(u_char*)handle);
    /*Loop for normal packet*/
	if(handle != Contrl_h){
		pcap_loop(handle,-1,packet_proc,NULL);
	}
    /*loop for state packets*/
	else{
		pthread_create(&send_update,NULL,send_update_thread,(u_char*)handle);
		pthread_create(&recv_update,NULL,recv_update_thread,(u_char*)handle);
		pthread_join(send_update,NULL);
		pthread_join(recv_update,NULL);
	}
}


int main(int argc, const char * argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n,result, type, devNumber = 0;
    char host[NI_MAXHOST];
    pthread_t thread[4]; 		/*Thread ID*/
	pcap_t *handle[4];			/* Session handle */
	bpf_u_int32 mask[4];		/* Our netmask */
	bpf_u_int32 net[4];		/* Our IP */
	struct bpf_program fp[4];		/* The compiled filter */
	char filter_exp[]="(ether proto !(0x88cc) and !(stp))"; 	/* The filter expression */
	char errbuf[4][PCAP_ERRBUF_SIZE];	/* Error string */
	fwd_int =atoi(argv[2]);  /*0000NESW*/
	dir = argv[1][0];  /*direction of the I-node*/
	fplog = fopen(argv[3],"w"); /*log file*/
    fplog1 = fopen(argv[4],"w");
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

    /* Open Handle for the devices */
	for(int i = 0 ; i<5; i++){
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
    for(int i = 0; i < 5;i++){
    	pthread_create(&thread[i],NULL,nodeI_thread,handle[i]);
    }
    for(int i = 0; i < 5;i++){
    	pthread_join(thread[i],NULL);
    }

    return 0;
}
