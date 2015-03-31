#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packethdr.h"
#include <string.h>
#include <unistd.h>
#include <queue>
#include <pthread.h>


pcap_t *handle1,*handle2;	/*1-E,2-W */		/* Session handle */

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	memcpy(useless,pack,sizeof(packet));
}

void* easttowest(void *args){
	struct packet *pkt = (struct packet *)malloc(sizeof(struct packet));
	while(1){
		pcap_loop(handle1,1,procpkt,(u_char*)pkt);		
		pcap_inject(handle2,pkt,sizeof(struct packet));
	}
}

void* westtoeast(void *args){
	struct packet *pkt = (struct packet *)malloc(sizeof(struct packet));
	while(1){
		pcap_loop(handle2,1,procpkt,(u_char*)pkt);		
		pcap_inject(handle1,pkt,sizeof(struct packet));
	}
}
int main(int argc, char *argv[]){	
	char *dev1=argv[1];		/* The device to sniff on */
	char errbuf1[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask1;		/* Our netmask */
	bpf_u_int32 net1;		/* Our IP */
	struct bpf_program fp1;		/* The compiled filter */
	struct pcap_pkthdr header1;	/* The header that pcap gives us */
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	char *dev2=argv[2];		/* The device to sniff on */
	char errbuf2[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask2;		/* Our netmask */
	bpf_u_int32 net2;		/* Our IP */
	struct bpf_program fp2;		/* The compiled filter */
	struct pcap_pkthdr header2;	/* The header that pcap gives us */
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev1, &net1, &mask1, errbuf1) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev1, errbuf1);
		net1 = 0;
		mask1 = 0;
	}
	if (pcap_lookupnet(dev2, &net2, &mask2, errbuf2) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev2, errbuf2);
		net2 = 0;
		mask2 = 0;
	}
	/* Open the session in promiscuous mode */
	handle1 = pcap_open_live(dev1, BUFSIZ, 1, 1000, errbuf1);
	if (handle1 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev1, errbuf1);
		exit(1);
	}
	handle2 = pcap_open_live(dev2, BUFSIZ, 1, 1000, errbuf2);
	if (handle1 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev2, errbuf2);
		exit(1);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle1, &fp1, filter_exp, 0, net1) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle1));
		exit(1);
	}
	if (pcap_compile(handle2, &fp2, filter_exp, 0, net2) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle2));
		exit(1);
	}
	if (pcap_setfilter(handle1, &fp1) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle1));
		exit(1);
	}
	if (pcap_setfilter(handle2, &fp2) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle2));
		exit(1);
	}
	pthread_t west_t,east_t;
	pthread_create(&east_t,NULL,easttowest,NULL);
	pthread_create(&west_t,NULL,westtoeast,NULL);
	pthread_join(east_t,NULL);		
	pthread_join(west_t,NULL);
	

	return(0);
}
