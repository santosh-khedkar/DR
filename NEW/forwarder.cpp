#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include "packethdr.h"
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>


using namespace std;

/*direction handles*/
pcap_t *North_h,*South_h,*West_h,*East_h;
FILE *fplog;

/*initial information processing*/
void procpkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
    pcap_t *handle = (pcap_t *)useless;
    u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
    if(pkt->direction == 'I'){
        /*get direction specific handles*/
        if(pkt->sub_direction == 'N'){
            North_h = handle;
        }
        else if(pkt->sub_direction == 'E'){
            East_h = handle;
        }
        else if(pkt->sub_direction == 'S'){
            South_h = handle;
        }
        else if(pkt->sub_direction == 'W'){
            West_h = handle;
        }
        pkt->Vehicle_ID = 0;   /*Vehicle ID*/
        pkt->direction = 'F'; /*Direction N/E/S/W */
        pkt->sub_direction = '-';
        pkt->Lane = 0;      /*Lane (Redundant)*/
        pkt->SID = 0;       /*Source ID*/
        pkt->DID = 5;     /*Destination ID (Redundant)*/
        printf("INFORMATION PACKET SENT!!!\n");
        int result = pcap_inject(handle, pkt,sizeof(struct packet));
    }
    /*Invalid I-node packet*/
    else{
        printf("ERROR: I-NODE INFORMATION INCORRECT!!!!!\n");
        exit(1);
    }
}

/*packet forwarding*/
void fwd_pkt(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* pack){
    u_char *pac = (u_char*)pack;
    struct packet *pkt = (struct packet *)(pac);
    int result;
    if(pkt->direction == 'N'){
        /*N-1 -> West*/
        if(pkt->SID == 1){
            result = pcap_inject(West_h, pkt,sizeof(struct packet));
        }
        /*N-2 -> South*/
        else if(pkt->SID == 2){
            result = pcap_inject(South_h, pkt,sizeof(struct packet));
        }
        /*N-3 -> East*/
        else if(pkt->SID == 3){
            result = pcap_inject(East_h, pkt,sizeof(struct packet));
        }
    }
    else if(pkt->direction == 'E'){
        /*E-1 -> North*/
        if(pkt->SID == 1){
            result = pcap_inject(North_h, pkt,sizeof(struct packet));
        }
        /*E-2 -> West*/
        else if(pkt->SID == 2){
            result = pcap_inject(West_h, pkt,sizeof(struct packet));
        }
        /*E-3 -> South*/
        else if(pkt->SID == 3){
            result = pcap_inject(South_h, pkt,sizeof(struct packet));
        }
    }
    else if(pkt->direction == 'S'){
        /*S-1 -> West*/
        if(pkt->SID == 1){
            result = pcap_inject(West_h, pkt,sizeof(struct packet));
        }
        /*S-2 -> North*/
        else if(pkt->SID == 2){
            result = pcap_inject(North_h, pkt,sizeof(struct packet));
        }
        /*S-3 -> East*/ 
        else if(pkt->SID == 3){
            result = pcap_inject(East_h, pkt,sizeof(struct packet));
        }
    }
    else if(pkt->direction == 'W'){
        /*W-1 -> North*/
        if(pkt->SID == 1){
            result = pcap_inject(North_h, pkt,sizeof(struct packet));
        }
        /*W-2 -> East*/
        else if(pkt->SID == 2){
            result = pcap_inject(East_h, pkt,sizeof(struct packet));
        }
        /*W-3 -> South*/
        else if(pkt->SID == 3){
            result = pcap_inject(South_h, pkt,sizeof(struct packet));
        }
    }
}

/*forward thread*/
void* forward_thread(void *args){
    pcap_t* handle = (pcap_t*)args;
    pcap_loop(handle,1,procpkt,(u_char*)handle); /*initial information setup*/
    pcap_loop(handle,-1,fwd_pkt,NULL); /* loop for the packet to forward*/
}

int main(int argc, const char * argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n,result, type, devNumber = 0;
    char allDevNames[4][5];
    char host[NI_MAXHOST],filter_exp[]="(ether proto !(0x88cc) and !(stp))";
    pthread_t thread[4];        /*Thread ID*/
    pcap_t *handle[4];          /* Session handle */
    bpf_u_int32 mask[4];        /* Our netmask */
    bpf_u_int32 net[4];     /* Our IP */
    struct bpf_program fp[4];       /* The compiled filter */
    char errbuf[4][PCAP_ERRBUF_SIZE];   /* Error string */
    

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    //Walk through the linked list maintaining head pointer for freeing memory
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        //get the interface family from the interface
        family = ifa->ifa_addr->sa_family;
        
        //check for ipv4 addresses only excluding loopback
        if (family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            
            //obtain the host name and check for errors
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            
            if(!(strncmp("192",host,3) == 0)){
            	strncpy(allDevNames[devNumber],ifa->ifa_name,4);
            	allDevNames[devNumber][4] = '\0';
            	devNumber++;
            }
        }
    }
    //free linked list
    freeifaddrs(ifaddr);

    fplog = fopen(argv[1],"w");

    /* Open Handle for the devices */
    for(int i = 0 ; i<4; i++){
        if (pcap_lookupnet(allDevNames[i], &net[i], &mask[i], errbuf[i]) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", allDevNames[i], errbuf[i]);
            net[i] = 0;
            mask[i] = 0;
        }
        if ((handle[i] = pcap_open_live(allDevNames[i], BUFSIZ, 1, 0, errbuf[i])) == NULL) {
            fprintf(stderr, "ERROR: %s\n", errbuf[i]);
            exit(1);
        }
                /* Compile and apply the filter */
        if (pcap_compile(handle[i], &fp[i], filter_exp, 0, net[i]) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle[i]));
            exit(0);
        }
        if (pcap_setfilter(handle[i], &fp[i]) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle[i]));
            exit(0);
        }
    }
    /*Forwarding threads*/
    for(int i = 0; i < 4;i++){
        pthread_create(&thread[i],NULL,forward_thread,handle[i]);
    }
    for(int i = 0; i < 4;i++){
        pthread_join(thread[i],NULL);
    }

    return 0;
}