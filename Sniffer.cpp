#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packethdr.h"
#include <string.h>
#include <pthread.h>

void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
	u_char *pac = (u_char*)pack;
	struct packet *pkt = (struct packet *)(pac);
	printf("VID:%d ", pkt->Vehicle_ID);
	printf("LANE:%d ", pkt->Lane);
	printf("SID:%d ", pkt->SID);
	printf("DID:%d\n", pkt->DID);
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
		
		pcap_loop(handle,10,procpkt,NULL);
		pcap_close(handle);		
}

int main(int argc, char *argv[]){
		pthread_t thread1,thread2,thread3;
		pthread_create(&thread1,NULL,sniffingthread,argv[1]);
		/*pthread_create(&thread2,NULL,sniffingthread,argv[2]);
		pthread_create(&thread3,NULL,sniffingthread,argv[3]);*/
		pthread_join(thread1,NULL);		
		/*pthread_join(thread2,NULL);
		pthread_join(thread3,NULL);*/
		return(0);
	 }
