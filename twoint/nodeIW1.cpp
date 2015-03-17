#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "packethdr.h"
#include <string.h>
#include <queue>
#include <pthread.h>

using namespace std;

queue<packet*> Q10;
queue<packet*> Q11;
queue<packet*> Q12;

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct packet *pkt = (struct packet *)(pac);
	if(pkt->SID==1){
		Q10.push(pkt);
	}
	else if(pkt->SID==2){
		Q11.push(pkt);
	}
	else if(pkt->SID==3){
		Q12.push(pkt);
	}
}

void updatestate(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	memcpy(useless,pack,sizeof(state_t));
}

void* sniffingthread(void *args){
		pcap_t *handle;			/* Session handle */
		char *dev=(char*)args;		/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct bpf_program fp;		/* The compiled filter */
		char *filter_exp=(char*)malloc(sizeof(char)*30); 	/* The filter expression */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */	
		strcpy(filter_exp,"!(ether proto 0x88cc)");
		
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
		
		pcap_loop(handle,-1,procpkt,NULL);
		pcap_close(handle);	
}

void Take_action(struct state_t *st){
	u_short state = 0;
	int PS=0;
	state=state|st->state;
	state=state>>6;
	state=state&63;
	if(st->direction=='A' || st->direction=='B'){
		if(state&1){
			Q10.pop();
		}
	}
	else if(st->direction=='C'){
		if(state==10 || state==11 || state==14 || state==15 || state==42 || state==43 || state==46 || state==47){
			PS=1;
		}
		else if( (state>=26 && state<=31) || (state>=56 && state<=63) ){
			PS=2;
		}
		else if((state>=20 && state<=23) || (state>=52 && state<=55)){
			PS=3;
		}
		if(PS==0 || PS==1){
			if(state&1){
				Q10.pop();
			}
			if(state&(1<<1)){
				Q11.pop();
			}
			if(state&(1<<2)){
				Q12.pop();
			}
		}
		else if(PS==3 || PS==2){
			if(!(state&(1<<4))){
				Q12.pop();
			}
			if(state&(1<<1)){
				Q11.pop();
			}
			if(state&1){
				Q10.pop();
			}
		}		
	}
	if(st->direction=='D'){
		if(state&1){
			Q10.pop();
		}
		if(state&(1<<2)){
			Q12.pop();
		}
	}
}


void *servicethread(void *args){
	struct state_t st;
	st.state=0;
	st.direction='W';
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	device = (char*)args;
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct bpf_program fp;		/* The compiled filter */
		
	char *filter_exp=(char*)malloc(sizeof(char)*30); 	/* The filter expression */
	strcpy(filter_exp,"!(ether proto 0x88cc)");

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
		net = 0;
		mask = 0;
	}
	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
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
	while(1){
		if(!Q10.empty()){
			st.state=st.state|1;
		}
		if(!Q11.empty()){
			st.state=st.state|2;
		}
		if(!Q12.empty()){
			st.state=st.state|4;
		}	
		int result = pcap_inject(handle,&st,sizeof(state_t));
		usleep(100000);
		st.state=0;		
		pcap_loop(handle,1,updatestate,(u_char*)&st);
		Take_action(&st);
	}
}

int main(int argc, char *argv[]){
		pthread_t thread1,thread2,thread3,service_t;
		pthread_create(&thread1,NULL,sniffingthread,argv[1]);
		pthread_create(&thread2,NULL,sniffingthread,argv[2]);
		pthread_create(&thread3,NULL,sniffingthread,argv[3]);
		pthread_create(&service_t,NULL,servicethread,argv[4]);
		pthread_join(thread1,NULL);		
		pthread_join(thread2,NULL);
		pthread_join(thread3,NULL);
		pthread_join(service_t,NULL);
		return(0);
}
