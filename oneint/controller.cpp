#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packethdr.h"
#include <string.h>
#include <unistd.h>
#include <queue>
#include <pthread.h>

using namespace std;

char traffic_sig;
u_char dir=0; /*0000NSWE*/
u_short updt=0; /*0000|Q4|Q5|Q6|Q12|Q11|Q10|Q1|Q2|Q3|Q9|Q8|Q7|*/
u_int Transaction=1;
u_int dir_c=1;

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct state_t *st = (struct state_t *)(pac);
	
	if(st->direction=='S'){
		pthread_mutex_lock(&m);
		printf("UPDATING SOUTH\n");
		updt=updt|st->state;
		dir=dir|4;
		if(dir==15){
			printf("GOT UPDATE FROM EVERYWHERE!\n");
			pthread_cond_broadcast(&cv);
		}
		pthread_mutex_unlock(&m);
	}
	else if(st->direction=='N'){
		pthread_mutex_lock(&m);
		printf("UPDATING NORTH\n");
		updt=updt|(st->state<<3);
		dir=dir|8;
		if(dir==15){
			printf("GOT UPDATE FROM EVERYWHERE!\n");
			pthread_cond_broadcast(&cv);
		}
		pthread_mutex_unlock(&m);
	}
	else if(st->direction=='W'){
		pthread_mutex_lock(&m);
		printf("UPDATING WEST\n");
		updt=updt|(st->state<<6);
		dir=dir|2;
		if(dir==15){
			printf("GOT UPDATE FROM EVERYWHERE!\n");
			pthread_cond_broadcast(&cv);
		}
		pthread_mutex_unlock(&m);
	}
	else if(st->direction=='E'){
		pthread_mutex_lock(&m);
		printf("UPDATING EAST\n");
		updt=updt|(st->state<<9);
		dir=dir|1;
		if(dir==15){
			printf("GOT UPDATE FROM EVERYWHERE!\n");
			pthread_cond_broadcast(&cv);
		}
		pthread_mutex_unlock(&m);
	}
	pthread_mutex_lock(&m);
	while(dir!=15)
		pthread_cond_wait(&cv,&m);
	pthread_mutex_unlock(&m);
}



void* trafficthread(void *args){
	int count=0;
	while(1){
		switch(count){
			case 0: 
				traffic_sig='A';
				usleep(10000000);
				count++;
				break;
			case 1:
				traffic_sig='B';
				usleep(1000000);
				count++;
				break;
			case 2: 
				traffic_sig='C';
				usleep(10000000);
				count++;
				break;
			case 3: 
				traffic_sig='D';
				usleep(1000000);
				count=0;
				break;
			default:
				traffic_sig='-';
				break; 				
		}
	}
}


void* sniffingthread(void *args){
	struct state_t upst;
	const u_char *pack;
	pcap_t *handle;			/* Session handle */
	char *dev=(char*)args;		/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */	
	printf("SNIFFING INTERFACE:%s\n",dev);
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (void*)2;
	}
	pthread_mutex_lock(&m);
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (void*)2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (void*)2;
	}
	pthread_mutex_unlock(&m);
		
	while(1){
		printf("WAITING FOR UPDATE\n");		
		pcap_loop(handle,1,procpkt,NULL);
		upst.direction=traffic_sig;
		upst.state=updt;
		usleep(1000000);
		printf("INJECTING UPDATE\n");
		int result = pcap_inject(handle,&upst,sizeof(state_t));
		pthread_mutex_lock(&m);
		dir_c++;
		if(dir_c==4){
			dir_c=1;
			dir=0;
			updt=0;
			Transaction++;
			printf("END OF TRANSACTION\n");
		}
		pthread_mutex_unlock(&m);
		usleep(1000000);
	}		
		pcap_close(handle);	
}



int main(int argc, char *argv[]){
	pthread_t thread1,thread2,thread3,thread4,traffic_t;
	pthread_create(&thread1,NULL,sniffingthread,argv[1]);
	pthread_create(&thread2,NULL,sniffingthread,argv[2]);
	pthread_create(&thread3,NULL,sniffingthread,argv[3]);
	pthread_create(&thread4,NULL,sniffingthread,argv[4]);
	pthread_create(&traffic_t,NULL,trafficthread,NULL);
	pthread_join(thread1,NULL);		
	pthread_join(thread2,NULL);
	pthread_join(thread3,NULL);
	pthread_join(thread4,NULL);
	return(0);
}
