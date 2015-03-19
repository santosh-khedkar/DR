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

char traffic_sig='-';
u_short updt=0; /*0000|Q4|Q5|Q6|Q12|Q11|Q10|Q1|Q2|Q3|Q9|Q8|Q7|*/
FILE *fp = fopen("controller.txt","w");
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct state_t *st = (struct state_t *)(pac);	
	if(st->direction=='S'){
		pthread_mutex_lock(&m);
		updt=updt|st->state;
		fprintf(fp,"GOT SOUTH UPDATE:%d\n",updt);
		fflush(fp);
		pthread_mutex_unlock(&m);
	}
	else if(st->direction=='N'){
		pthread_mutex_lock(&m);
		updt=updt|(st->state<<3);
		fprintf(fp,"GOT NORTH UPDATE:%d\n",updt);
		fflush(fp);
		pthread_mutex_unlock(&m);
	}
	else if(st->direction=='W'){
		pthread_mutex_lock(&m);
		updt=updt|(st->state<<6);
		fprintf(fp,"GOT WEST UPDATE:%d\n",updt);
		fflush(fp);
		pthread_mutex_unlock(&m);
	}
	else if(st->direction=='E'){
		pthread_mutex_lock(&m);
		updt=updt|(st->state<<9);
		fprintf(fp,"GOT EAST UPDATE:%d\n",updt);
		fflush(fp);
		pthread_mutex_unlock(&m);
	}
	else{
		printf("UPDATE LOST\n");
	}
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
	pcap_loop(handle,-1,procpkt,NULL);		
	pcap_close(handle);	
}

void* send_update_thread(void *args){
	struct state_t upst;
	const u_char *pack;
	u_int Transaction=1;
	pcap_t *handle1,*handle2,*handle3,*handle4;			/* Session handle */
	char **dev=(char**)args;		/* The device to sniff on */
	char errbuf1[PCAP_ERRBUF_SIZE],errbuf2[PCAP_ERRBUF_SIZE],errbuf3[PCAP_ERRBUF_SIZE],errbuf4[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask1,mask2,mask3,mask4;		/* Our netmask */
	bpf_u_int32 net1,net2,net3,net4;		/* Our IP */
	struct bpf_program fp1,fp2,fp3,fp4;		/* The compiled filter */
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	//-----------------------------------------------------------------------------------------------	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev[1], &net1, &mask1, errbuf1) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev[1], errbuf1);
		net1 = 0;
		mask1 = 0;
	}

	/* Open the session in promiscuous mode */
	handle1 = pcap_open_live(dev[1], BUFSIZ, 1, 1000, errbuf1);
	if (handle1 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev[1], errbuf1);
		return (void*)2;
	}
	
	//----------------------------------------------------------------------------------------------------------------	
	
	//-----------------------------------------------------------------------------------------------	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev[2], &net2, &mask2, errbuf2) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev[2], errbuf2);
		net2 = 0;
		mask2 = 0;
	}

	/* Open the session in promiscuous mode */
	handle2 = pcap_open_live(dev[2], BUFSIZ, 1, 1000, errbuf2);
	if (handle2 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev[2], errbuf2);
		return (void*)2;
	}
	
	//----------------------------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev[3], &net3, &mask3, errbuf3) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev[3], errbuf3);
		net3 = 0;
		mask3 = 0;
	}

	/* Open the session in promiscuous mode */
	handle3 = pcap_open_live(dev[3], BUFSIZ, 1, 1000, errbuf3);
	if (handle3 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev[3], errbuf3);
		return (void*)2;
	}
	
	//----------------------------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev[4], &net4, &mask4, errbuf4) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev[4], errbuf4);
		net4 = 0;
		mask4 = 0;
	}

	/* Open the session in promiscuous mode */
	handle4 = pcap_open_live(dev[4], BUFSIZ, 1, 1000, errbuf4);
	if (handle4 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev[4], errbuf4);
		return (void*)2;
	}
	
	//----------------------------------------------------------------------------------------------------------------
	pthread_mutex_lock(&m);
	/* Compile and apply the filter */
	if (pcap_compile(handle1, &fp1, filter_exp, 0, net1) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle1));
		return (void*)2;
	}
	if (pcap_setfilter(handle1, &fp1) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle1));
		return (void*)2;
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle2, &fp2, filter_exp, 0, net2) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle2));
		return (void*)2;
	}
	if (pcap_setfilter(handle2, &fp2) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle2));
		return (void*)2;
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle3, &fp3, filter_exp, 0, net3) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle3));
		return (void*)2;
	}
	if (pcap_setfilter(handle3, &fp3) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle3));
		return (void*)2;
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle4, &fp4, filter_exp, 0, net4) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle4));
		return (void*)2;
	}
	if (pcap_setfilter(handle4, &fp4) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle4));
		return (void*)2;
	}
	pthread_mutex_unlock(&m);
	while(1){
		upst.direction=traffic_sig;
		upst.state=updt;
		int result1 = pcap_inject(handle1,&upst,sizeof(state_t));
		int result2 = pcap_inject(handle2,&upst,sizeof(state_t));
		int result3 = pcap_inject(handle3,&upst,sizeof(state_t));
		int result4 = pcap_inject(handle4,&upst,sizeof(state_t));
		upst.direction='-';
		upst.state=0;
		pthread_mutex_lock(&m);
		fprintf(fp,"TRANSACTION ID:%d\n",Transaction);
		fflush(fp);
		fprintf(fp,"INJECTING SNAPSHOT UPDATE:%d\n",updt);
		fflush(fp);
		updt=0;
		pthread_mutex_unlock(&m);
		Transaction++;
		usleep(1000000);
	}			
}


int main(int argc, char *argv[]){
	pthread_t thread1,thread2,thread3,thread4,traffic_t,send_update;
	pthread_create(&thread1,NULL,sniffingthread,argv[1]);
	pthread_create(&thread2,NULL,sniffingthread,argv[2]);
	pthread_create(&thread3,NULL,sniffingthread,argv[3]);
	pthread_create(&thread4,NULL,sniffingthread,argv[4]);
	pthread_create(&send_update,NULL,send_update_thread,argv);
	pthread_create(&traffic_t,NULL,trafficthread,NULL);
	pthread_join(thread1,NULL);		
	pthread_join(thread2,NULL);
	pthread_join(thread3,NULL);
	pthread_join(thread4,NULL);
	return(0);
}
