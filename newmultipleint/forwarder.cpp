#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include "packethdr.h"


using namespace std;
FILE *fp;
int result;
pcap_t *handle1,*handle2,*handle3,*handle4;	/*1-N,2-E,3-S,4-S	/* Session handle */
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct packet *pkt = (struct packet *)(pac);
	
	pthread_mutex_lock(&m);
	fprintf(fp,"Forwarding Packet from %c direction,SID:%d, VID:,%d\n",pkt->direction,pkt->SID,pkt->Vehicle_ID);
	fflush(fp);
	if(pkt->direction=='N'){
		if(pkt->SID==1){
			result = pcap_inject(handle4, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==2){
			result = pcap_inject(handle3, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==3){
			result = pcap_inject(handle2, pkt,sizeof(struct packet));
		}
	}
	else if(pkt->direction=='E'){
		if(pkt->SID==1){
			result = pcap_inject(handle1, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==2){
			result = pcap_inject(handle4, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==3){
			result = pcap_inject(handle3, pkt,sizeof(struct packet));
		}
	}
	else if(pkt->direction=='S'){
		if(pkt->SID==1){
			result = pcap_inject(handle4, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==2){
			result = pcap_inject(handle1, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==3){
			result = pcap_inject(handle2, pkt,sizeof(struct packet));
		}
	}
	else if(pkt->direction=='W'){
		if(pkt->SID==1){
			result = pcap_inject(handle1, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==2){
			result = pcap_inject(handle2, pkt,sizeof(struct packet));
		}
		else if(pkt->SID==3){
			result = pcap_inject(handle3, pkt,sizeof(struct packet));
		}
	}
	else{
		printf("FAULTY PACKET!!!\n");
	}
	pthread_mutex_unlock(&m);
}


void* sniffingthread1(void *args){
	pcap_loop(handle1,-1,procpkt,NULL);
	pcap_close(handle1);	
}
void* sniffingthread2(void *args){
	pcap_loop(handle2,-1,procpkt,NULL);
	pcap_close(handle2);	
}

void* sniffingthread3(void *args){
	pcap_loop(handle3,-1,procpkt,NULL);
	pcap_close(handle3);	
}

void* sniffingthread4(void *args){
	pcap_loop(handle4,-1,procpkt,NULL);
	pcap_close(handle4);	
}



int main(int argc, char *argv[]){
	pthread_t thread1,thread2,thread3,thread4;
	fp = fopen(argv[1],"w");
	char errbuf1[PCAP_ERRBUF_SIZE],errbuf2[PCAP_ERRBUF_SIZE],errbuf3[PCAP_ERRBUF_SIZE],errbuf4[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask1,mask2,mask3,mask4;		/* Our netmask */
	bpf_u_int32 net1,net2,net3,net4;		/* Our IP */
	struct bpf_program fp1,fp2,fp3,fp4;		/* The compiled filter */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
			/* Find the properties for the device */
	if (pcap_lookupnet(argv[2], &net1, &mask1, errbuf1) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[2], errbuf1);
		net1 = 0;
		mask1 = 0;
	}
	/* Open the session in promiscuous mode */
	handle1 = pcap_open_live(argv[2], BUFSIZ, 1, 1000, errbuf1);
	if (handle1 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[2], errbuf1);
		exit(0);
	}
			/* Compile and apply the filter */
	if (pcap_compile(handle1, &fp1, filter_exp, 0, net1) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle1));
		exit(0);
	}
	if (pcap_setfilter(handle1, &fp1) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle1));
		exit(0);
	}
	/*----------------------------------------------------------------------------------------*/
	if (pcap_lookupnet(argv[3], &net2, &mask2, errbuf2) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[3], errbuf2);
		net2 = 0;
		mask2 = 0;
	}
	/* Open the session in promiscuous mode */
	handle2 = pcap_open_live(argv[3], BUFSIZ, 1, 1000, errbuf2);
	if (handle2 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[3], errbuf2);
		exit(0);
	}
			/* Compile and apply the filter */
	if (pcap_compile(handle2, &fp2, filter_exp, 0, net2) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle2));
		exit(0);
	}
	if (pcap_setfilter(handle1, &fp1) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle2));
		exit(0);
	}
	/*----------------------------------------------------------------------------------------*/
	if (pcap_lookupnet(argv[4], &net3, &mask3, errbuf3) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[4], errbuf3);
		net3 = 0;
		mask3 = 0;
	}
	/* Open the session in promiscuous mode */
	handle3 = pcap_open_live(argv[4], BUFSIZ, 1, 1000, errbuf3);
	if (handle3 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[4], errbuf3);
		exit(0);
	}
			/* Compile and apply the filter */
	if (pcap_compile(handle3, &fp3, filter_exp, 0, net3) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle3));
		exit(0);
	}
	if (pcap_setfilter(handle3, &fp3) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle3));
		exit(0);
	}
	/*----------------------------------------------------------------------------------------*/
	if (pcap_lookupnet(argv[5], &net4, &mask4, errbuf4) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[5], errbuf4);
		net4 = 0;
		mask4 = 0;
	}
	/* Open the session in promiscuous mode */
	handle4 = pcap_open_live(argv[5], BUFSIZ, 1, 1000, errbuf4);
	if (handle4 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[5], errbuf4);
		exit(0);
	}
			/* Compile and apply the filter */
	if (pcap_compile(handle4, &fp4, filter_exp, 0, net4) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle4));
		exit(0);
	}
	if (pcap_setfilter(handle4, &fp4) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle4));
		exit(0);
	}
	/*----------------------------------------------------------------------------------------*/
	

	pthread_create(&thread1,NULL,sniffingthread1,NULL);
	pthread_create(&thread2,NULL,sniffingthread2,NULL);
	pthread_create(&thread3,NULL,sniffingthread3,NULL);
	pthread_create(&thread4,NULL,sniffingthread4,NULL);
	pthread_join(thread1,NULL);		
	pthread_join(thread2,NULL);
	pthread_join(thread3,NULL);
	pthread_join(thread4,NULL);

	return(0);
}