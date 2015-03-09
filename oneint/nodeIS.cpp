#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packethdr.h"
#include <string.h>
#include <queue>
#include <pthread.h>

using namespace std;

queue<packet*> Q9;
queue<packet*> Q8;
queue<packet*> Q7;

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct packet *pkt = (struct packet *)(pac);
	if(pkt->SID==1){
		Q9.push(pkt);
	}
	else if(pkt->SID==2){
		Q8.push(pkt);
	}
	else if(pkt->SID==3){
		Q7.push(pkt);
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

void *servicethread(void *args){
	struct state_t st;
	st.state=0;
	st.direction='N';
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	device = (char*)args;


	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERROR: %s\n", errbuf);
  		exit(1);
	}
	while(1){
		if(!Q7.empty()){
			st.state=st.state|1;
		}
		if(!Q8.empty()){
			st.state=st.state|2;
		}
		if(!Q9.empty()){
			st.state=st.state|4;
		}
		int result = pcap_inject(handle,&st,sizeof(state_t));
		st.state=0;		
		pcap_loop(handle,1,updatestate,(u_char*)&st);
		printf("\nstate:%d",st.state);
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
