#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "packethdr.h"
#include <string.h>
#include <queue>
#include <pthread.h>

using namespace std;
int fwd_int=0,int_node=0;
queue<packet*> Q1;
queue<packet*> Q2;
queue<packet*> Q3;

int result;
pcap_t *Fwd_handle = NULL,*handle1,*handle2,*handle3;
FILE *fp;

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct packet *pkt = (struct packet *)(pac);
	if(pkt->SID==1 && pkt->direction=='N'){
		Q1.push(pkt);
	}
	else if(pkt->SID==2 && pkt->direction=='N'){
		Q2.push(pkt);
	}
	else if(pkt->SID==3 && pkt->direction=='N'){
		Q3.push(pkt);
	}
	else{
		if(int_node==0){
			fprintf(fp,"Servicing Fwd Packet from %c direction, VID:,%d\n",pkt->direction,pkt->Vehicle_ID);
			fflush(fp);
		}
		else if(int_node==1){
			fprintf(fp,"Forwarding Packet from %c direction, VID:,%d\n",pkt->direction,pkt->Vehicle_ID);
			fflush(fp);
			if(pkt->direction=='W'){
				result = pcap_inject(handle1, pkt,sizeof(struct packet));
			}
			else if(pkt->direction=='S'){
				result = pcap_inject(handle2, pkt,sizeof(struct packet));
			}
			else if(pkt->direction=='E'){
				result = pcap_inject(handle3, pkt,sizeof(struct packet));
			}
		}
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
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */	
		char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */

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

void Take_action(struct state_t *st){
	u_short state = 0;
	int PS=0;
	struct packet *pkt;
	state=state|st->state;
	state=state&63;
	fprintf(fp,"STATE:%d\n",state);
	fflush(fp);
	fprintf(fp,"TRAFFIC STATE:%c\n",st->direction);
	fflush(fp);
	if(st->direction=='C' || st->direction=='D'){
		if(state&(1<<5)){
			if(fwd_int&4){
				pkt=Q1.front();
				int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
				fprintf(fp,"Forwarding Packet from Q1\n");
				fflush(fp);
			}
			else{
				fprintf(fp,"Servicing Q1\n");
				fflush(fp);
			}				
			Q1.pop();
		}
	}
	else if(st->direction=='A'){
		if(state==10 || state==11 || state==14 || state==15 || state==42 || state==43 || state==46 || state==47){
			PS=1;
		}
		else if( (state>=26 && state<=31) || (state>=56 && state<=63) ){
			PS=2;
		}
		else if((state>=20 && state<=23) || (state>=52 && state<=55)){
			PS=3;
		}
		if(PS==0 || PS==3){
			if(state&(1<<3)){
				if(fwd_int&1){
					pkt=Q3.front();
					int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
					fprintf(fp,"Forwarding Packet from Q3\n");
					fflush(fp);
				}
				else{
					fprintf(fp,"Servicing Q3\n");
					fflush(fp);
				}				
				Q3.pop();
			}
			if(state&(1<<4)){
				if(fwd_int&2){
					pkt=Q2.front();
					int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
					fprintf(fp,"Forwarding Packet from Q2\n");
					fflush(fp);
				}
				else{
					fprintf(fp,"Servicing Q2\n");
					fflush(fp);
				}				
				Q2.pop();
			}
			if(state&(1<<5)){
				if(fwd_int&4){
					pkt=Q1.front();
					int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
					fprintf(fp,"Forwarding Packet from Q1\n");
					fflush(fp);
				}
				else{
					fprintf(fp,"Servicing Q1\n");
					fflush(fp);
				}				
				Q1.pop();
			}
		}
		else if(PS==1 || PS==2){
			if(!(state&(1<<1))){
				if(fwd_int&1){
					pkt=Q3.front();
					int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
					fprintf(fp,"Forwarding Packet from Q3\n");
					fflush(fp);
				}
				else{
					fprintf(fp,"Servicing Q3\n");
					fflush(fp);
				}				
				Q3.pop();
			}
			if(state&(1<<4)){
				if(fwd_int&2){
					pkt=Q2.front();
					int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
					fprintf(fp,"Forwarding Packet from Q2\n");
					fflush(fp);
				}
				else{
					fprintf(fp,"Servicing Q2\n");
					fflush(fp);
				}				
				Q2.pop();
			}
			if(state&(1<<5)){
				if(fwd_int&4){
					pkt=Q1.front();
					int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
					fprintf(fp,"Forwarding Packet from Q1\n");
					fflush(fp);
				}
				else{
					fprintf(fp,"Servicing Q1\n");
					fflush(fp);
				}				
				Q1.pop();
			}
		}		
	}
	else if(st->direction=='B'){
		if(state&(1<<3)){
			if(fwd_int&1){
				pkt=Q3.front();
				int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
				fprintf(fp,"Forwarding Packet from Q3\n");
				fflush(fp);
			}
			else{
				fprintf(fp,"Servicing Q3\n");
				fflush(fp);
			}				
			Q3.pop();
		}
		if(state&(1<<5)){
			if(fwd_int&4){
				pkt=Q1.front();
				int result = pcap_inject(Fwd_handle, pkt,sizeof(struct packet));
				fprintf(fp,"Forwarding Packet from Q1\n");
				fflush(fp);
			}
			else{
				fprintf(fp,"Servicing Q1\n");
				fflush(fp);
			}				
			Q1.pop();
		}
	}
}


void *send_update_thread(void *args){
	struct state_t st;
	st.state=0;
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	device = (char*)args;
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct bpf_program fp1;		/* The compiled filter */
		
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
		net = 0;
		mask = 0;
	}
	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERROR: %s\n", errbuf);
  		return (void*)2;
	}
	pthread_mutex_lock(&m);
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp1, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (void*)2;
	}
	if (pcap_setfilter(handle, &fp1) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (void*)2;
	}
	pthread_mutex_unlock(&m);
	while(1){
		st.direction='N';
		st.state=0;
		if(!Q3.empty()){
			st.state=st.state|1;
		}
		if(!Q2.empty()){
			st.state=st.state|2;
		}
		if(!Q1.empty()){
			st.state=st.state|4;
		}
		pthread_mutex_lock(&m);
		fprintf(fp,"INJECTING NORTH UPDATE:%d\n",st.state);
		fflush(fp);	
		pthread_mutex_unlock(&m);
		int result = pcap_inject(handle,&st,sizeof(state_t));
		usleep(1000000);
	}
}


void *recv_update_thread(void *args){
	struct state_t st;
	st.state=0;
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	device = (char*)args;
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct bpf_program fp1;		/* The compiled filter */
		
	char filter_exp[]="!(ether proto 0x88cc)"; 	/* The filter expression */
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
		net = 0;
		mask = 0;
		exit(0);
	}
	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERROR: %s\n", errbuf);
  		exit(1);
	}
	pthread_mutex_lock(&m);
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp1, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(0);
	}
	if (pcap_setfilter(handle, &fp1) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(0);
	}
	pthread_mutex_unlock(&m);
	while(1){
		pcap_loop(handle,1,updatestate,(u_char*)&st);
		pthread_mutex_lock(&m);
		/*fprintf(fp,"GOT SNAPSHOT UPDATE FROM CONTROLLER:%d\n",st.state);	
		fflush(fp);	*/
		Take_action(&st);
		pthread_mutex_unlock(&m);st.state=0;
	}
}

int main(int argc, char *argv[]){
	pthread_t thread1,thread2,thread3,send_update,recv_update,recvfwd_t;
	int_node=atoi(argv[1]);
	fwd_int=atoi(argv[2]);
	fp = fopen(argv[3],"w");
	char errbuf1[PCAP_ERRBUF_SIZE], *device1;
	device1=(char*)argv[7];
	char errbuf2[PCAP_ERRBUF_SIZE], *device2;
	device2=(char*)argv[4];
	char errbuf3[PCAP_ERRBUF_SIZE], *device3;
	device3=(char*)argv[5];
	char errbuf4[PCAP_ERRBUF_SIZE], *device4;
	device4=(char*)argv[6];

	if ((Fwd_handle = pcap_open_live(device1, BUFSIZ, 1, 0, errbuf1)) == NULL) {
  		fprintf(stderr, "ERRO: %s\n", errbuf1);
  		exit(1);
	}
	if ((handle1 = pcap_open_live(device2, BUFSIZ, 1, 0, errbuf2)) == NULL) {
  		fprintf(stderr, "ERRO: %s\n", errbuf2);
  		exit(1);
	}
	if ((handle2 = pcap_open_live(device3, BUFSIZ, 1, 0, errbuf3)) == NULL) {
  		fprintf(stderr, "ERRO: %s\n", errbuf3);
  		exit(1);
	}
	if ((handle3 = pcap_open_live(device4, BUFSIZ, 1, 0, errbuf4)) == NULL) {
  		fprintf(stderr, "ERRO: %s\n", errbuf4);
  		exit(1);
	}

	pthread_create(&thread1,NULL,sniffingthread,argv[4]);
	pthread_create(&thread2,NULL,sniffingthread,argv[5]);
	pthread_create(&thread3,NULL,sniffingthread,argv[6]);
	pthread_create(&recvfwd_t,NULL,sniffingthread,argv[7]);
	pthread_create(&send_update,NULL,send_update_thread,argv[8]);
	pthread_create(&recv_update,NULL,recv_update_thread,argv[8]);
	pthread_join(thread1,NULL);		
	pthread_join(thread2,NULL);
	pthread_join(thread3,NULL);
	pthread_join(send_update,NULL);
	pthread_join(recv_update,NULL);
	return(0);
}
