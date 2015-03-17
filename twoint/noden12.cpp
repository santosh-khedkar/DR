#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include "packethdr.h"


int main(int argc, char* argv[]){

	struct packet *pkt= (struct packet*)malloc(sizeof(struct packet));
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	device=(char*)argv[1];

	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERRO: %s\n", errbuf);
  		exit(1);
	}
	pkt->Vehicle_ID=1;
	pkt->Lane =2;
	pkt->SID=2;
	pkt->DID=5;
	while(1){
		pkt->Vehicle_ID++;
		int halt = rand()%1000000;
		int result = pcap_inject(handle, pkt,sizeof(struct packet));
		usleep(halt);		
	}
	return 0;
}