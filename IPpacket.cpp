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
	char errbuf[PCAP_ERRBUF_SIZE], device[4];
	strncpy(device,argv[1],4);

	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERRO: %s\n", errbuf);
  		exit(1);
	}
	pkt->Vehicle_ID=1;
	pkt->Lane =1;
	pkt->SID=1;
	pkt->DID=5;
	while(1){
		pkt->Vehicle_ID++;
		int halt = rand()%100;
		int result = pcap_inject(handle, pkt,sizeof(struct packet));
		usleep(halt*10000);		
	}
	return 0;
}