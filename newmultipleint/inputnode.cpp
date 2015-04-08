#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include "packethdr.h"



/*argv[1]=SID, argv[2]=direction, argv[3]=interface*/
int main(int argc, char* argv[]){
    int result;
	struct packet *pkt= (struct packet*)malloc(sizeof(struct packet));
	pcap_t *handle = NULL;
	int type;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	device=(char*)argv[4];

	if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
  		fprintf(stderr, "ERROR: %s\n", errbuf);
  		exit(1);
	}
	pkt->Vehicle_ID=1;
	pkt->direction=argv[1][0];
	pkt->Lane =atoi(argv[2]);
	pkt->SID=atoi(argv[2]);
	type=atoi(argv[3]);
	pkt->DID=5;
	while(1){
		pkt->Vehicle_ID++;
		if(type==0){
			usleep(15000000);
		}
		else if(type==1){
			int halt = rand()%100000000;
			usleep(halt);	
		}	
		result = pcap_inject(handle, pkt,sizeof(struct packet));
			
	}
	return 0;
}