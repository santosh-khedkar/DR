/*
 	node.cpp
  	Created by Santosh Narayankhedkar on 04/20/2015
 	Copyright (c) 2015 Narayankhedkar. All rights reserved.
 	USAGE: ./<node_name> -d <dist_type> -n <north_node/none> -w <west_node/none> -s <south_node/none> -e <east_node/none>
*/

/*
				   | | | | | | |
 				   |	 |     |
				   | | | | | | |	
				   |	 | 	   |	
				   | | | | | | |
				   |	 | 	   |
___________________| | | | | | |_____________________
_ _ _ _ _ _ _ _ _ _12 	  1 2 3	_ _ _ _ _ _ _ _ _ _ _ 
_ _ _ _ _ _ _ _ _ _11 			_ _ _ _ _ _ _ _ _ _ _ 
___________________10 			_____________________
_ _ _ _ _ _ _ _ _ _ 		   4_ _ _ _ _ _ _ _ _ _ _
_ _ _ _ _ _ _ _ _ _ 		   5_ _ _ _ _ _ _ _ _ _ _
___________________ 9 8	7      6_____________________
				   | | | | | | |
				   | 	 |	   |
				   | | | | | | |
				   | 	 | 	   |
				   | | | | | | |
				   |  	 | 	   |
				   | | | | | | | 
*/


#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <queue>
#include "car.h"
#include <sys/socket.h>
#include <sys/types.h> 
#include <sys/time.h>				   
#include <netinet/in.h>
#include <netdb.h> 

using namespace std;

FILE *TRAF_log;								/*Traffic log*/
FILE *NOCS_log;   							/*No. of Cars Serviced*/
FILE *Q_log;	   						 	/*Size of the queues*/
queue<car*> Q[12];     						/*Input queues*/
u_short kill_state = 0 ; 					/*0000|Q12|Q11|Q10|Q9|Q8|Q7|Q6|Q5|Q4|Q3|Q2|Q1*/
u_short update_serv_state[4]; 				/*Received Update */
unsigned char ser_cli_state = 0; 			/*|EC|SC|WC|NC|ES|SS|WS|NS|*/
char traffic_sig = '-'; 					/*Traffic state (A/B/C/D) */
int dist_type;  							/* 0-CBR, 1-POISSON*/
char *node_name[4],*config_f; 				/*Name of nodes in each direction and config file*/

/*Traffic Signal thread 

Reads the config.txt file (or the name specified on the commmand line to 
parse and create a 4x2 two-dimentional structure called traf

traf[i][0] = Signal state 
traf[i][1] = Time in second

Signal state key: 
0 --> nsg 
1 --> nsy 
2 --> weg 
3 --> wey

*/ 
void* traffic_thread(void *args){
	int count=0,traf[4][2];					
	struct timeval start, end;
	char str[25],*pch;
	FILE *conf = fopen(config_f,"r");
	while(fgets(str,25,conf)!=NULL){
		pch = strtok (str," ");
  		if(strncmp(pch,"nsg",3) == 0){
    		traf[count][0] = 0;
    		pch = strtok (NULL, " ");
    		traf[count][1] = atoi(pch);
    	}
    	else if(strncmp(pch,"nsy",3) == 0){
    		traf[count][0] = 1;
    		pch = strtok (NULL, " ");
    		traf[count][1] = atoi(pch);
    	}
    	else if(strncmp(pch,"weg",3) == 0){
    		traf[count][0] = 2;
    		pch = strtok (NULL, " ");
    		traf[count][1] = atoi(pch);
    	}
    	else if(strncmp(pch,"wey",3) == 0){
    		traf[count][0] = 3;
    		pch = strtok (NULL, " ");
   			traf[count][1] = atoi(pch);
   		}
   		else{
   			cout<<"ERROR: unknown symbol in config file. \n ERROR: Valid traffic state symbols are nsg, nsy, weg, wey \n ERROR: for example: nsg 10" <<endl;
   			exit(1);
   		}
  		count++;
	}
	count = 0;
	gettimeofday(&start,NULL);
	while(1){
		gettimeofday(&end, NULL);
		fprintf(TRAF_log,"%0.2f ",((double)end.tv_sec + (double)end.tv_usec / 1000000) - ((double)start.tv_sec + (double)start.tv_usec / 1000000));
		fflush(TRAF_log);
		fprintf(TRAF_log," %d\n",traf[count][0]);
		fflush(TRAF_log);
		if(traf[count][0] == 0){
			traffic_sig = 'A';
		}
		else if(traf[count][0] == 1){
			traffic_sig = 'B';
		}
		else if(traf[count][0] == 2){
			traffic_sig = 'C';
		}
		else if(traf[count][0] == 3){
			traffic_sig = 'D';
		} 
		usleep(traf[count][1] * 1000000);			
		count++;
		if(count>3)
			count = 0;
	}
}

/*Queue size thread
This thread keeps tracks of the current queue size and prints it every X seconds 

*/
void* queue_size_thread(void *args){
	struct timeval start, end;
	
	/* Start samplng only after the simulation has run for some time (1sec) */ 
	usleep(1000000);
	gettimeofday(&start,NULL);
	while(1){    	
	        gettimeofday(&end, NULL);
	        fprintf(Q_log,"%0.2f ",((double)end.tv_sec + (double)end.tv_usec / 1000000) - ((double)start.tv_sec + (double)start.tv_usec / 1000000));
		fflush(Q_log);
		if(traffic_sig == 'A'){
			fprintf(Q_log,"0 ");
			fflush(Q_log);
		}
		else if(traffic_sig == 'B'){
			fprintf(Q_log,"1 ");
			fflush(Q_log);
		}
		else if(traffic_sig == 'C'){
			fprintf(Q_log,"2 ");
			fflush(Q_log);
		}
		else if(traffic_sig == 'D'){
			fprintf(Q_log,"3 ");
			fflush(Q_log);
		}
		fprintf(Q_log,"%zd %zd %zd %zd %zd %zd %zd %zd %zd %zd %zd %zd\n",Q[0].size(),Q[1].size(),Q[2].size(),Q[3].size(),Q[4].size(),Q[5].size(),Q[6].size(),Q[7].size(),Q[8].size(),Q[9].size(),Q[10].size(),Q[11].size());
    	fflush(Q_log);

	/* Sampling the queue every 0.5 seconds */ 
        usleep(500000);
    }
    return (void*)-1;
}

/*Checks whether var is set at pos bit*/
bool check_set_bit(u_short var,int pos){
	if(var & 1<<pos){
		return true;
	}
	else{
		return false;
	} 
}

/*Input thread: 

Inputs vehicle / packets every 5s if the queue size doesn't exceed LANE LENGTH
i[0]   direction 0 --> n , 1 --> w , 2 --> S and 3 --> E 
i[1] + 1  lane number 1 --> closest to divider, 2 --> central lane , 3 --> right turn lane 

*/
void* input_thread(void *args){
	int *i = (int*)args;
	int lane = i[1] + 1;					/*Lane number*/
	int dir = i[0];							/*Direction*/
	int queue_bit = (dir * 3) + lane - 1;
	unsigned int Vehicle_id = 0;
	while(1){
	        
	  /* used for simulating failures */ 
		if(kill_state & (1<< queue_bit)){
			cout<<"killing thread "<<lane<<endl;
			pthread_exit(NULL);
		}


		struct car* vehicle = (struct car*)malloc(sizeof(struct car));
		Vehicle_id++;
		vehicle->SID = lane;
		vehicle->Vehicle_ID = Vehicle_id;
		vehicle->sleep_time = 0;
		if(dir == 0){
			vehicle->direction = 'N';
		}
		else if(dir == 1){
			vehicle->direction = 'W';
		}
		else if(dir == 2){
			vehicle->direction = 'S';
		}
		else if(dir == 3){
			vehicle->direction = 'E';
		}
		else{
			cout<<"ERROR: Wrong direction!!!!!"<<endl;
			cout<<"DIR:"<<dir<<endl;
		}
		/*Contant bit Rate*/
		if(dist_type == 0){
			/*Sleep for 5 sec*/
			usleep(5000000);
		}
		/*Poisson*/
		else if(dist_type == 1){
			int halt = rand()%1000000;
			usleep(halt);	
		}
		while(Q[queue_bit].size() >= LANE_LENGTH);
		Q[queue_bit].push(vehicle);
	}
}


/*Service thread services those queues which can be served at that instant of traffic signal
 Servicing every 1.5 seconds 


*/ 

void* service_thread(void *args){
	int count,countN,countE,countS,countW;
	struct timeval start, end;

	gettimeofday(&start,NULL);
	while(1){
		count = countN = countE = countS = countW = 0;
		
		/* Service all 12 queues every 1.5 seconds */ 
		usleep(1500000);
		/*Turn lanes always get serviced*/
		if(!Q[2].empty() && !check_set_bit(kill_state,10)){
			Q[2].pop();
			count++;
			countN++;
		}
		if(!Q[11].empty() && !check_set_bit(kill_state,7)){
			Q[11].pop();
			count++;
			countW++;
		}
		if(!Q[8].empty() && !check_set_bit(kill_state,4)){
			Q[8].pop();
			count++;
			countS++;
		}
		if(!Q[5].empty() && !check_set_bit(kill_state,1)){
			Q[5].pop();
			count++;
			countE++;
		}

		if(traffic_sig == 'A'){
			if(!Q[1].empty() && !check_set_bit(kill_state,1)){
				Q[1].pop();
				count++;
				countN++;
			}
			else if(!Q[6].empty() && !check_set_bit(kill_state,10)){
				Q[6].pop();
				count++;
				countS++;
			}
			if(!Q[7].empty() && !check_set_bit(kill_state,7)){
				Q[7].pop();
				count++;
				countS++;
			}
			else if(!Q[0].empty() && !check_set_bit(kill_state,4)){
				Q[0].pop();
				count++;
				countN++;
			}
		}
		else if(traffic_sig == 'B'){
			if(!Q[6].empty() && !check_set_bit(kill_state,10)){
				Q[6].pop();
				count++;
				countS++;
			}
			if(!Q[0].empty() && !check_set_bit(kill_state,4)){
				Q[0].pop();
				count++;
				countN++;
			}
		}
		if(traffic_sig == 'C'){
			if(!Q[4].empty() && !check_set_bit(kill_state,4)){
				Q[4].pop();
				count++;
				countE++;
			}
			else if(!Q[9].empty() && !check_set_bit(kill_state,1)){
				Q[9].pop();
				count++;
				countW++;
			}
			if(!Q[10].empty() && !check_set_bit(kill_state,10)){
				Q[10].pop();
				count++;
				countW++;
			}
			else if(!Q[3].empty() && !check_set_bit(kill_state,7)){
				Q[3].pop();
				count++;
				countE++;
			}
		}
		else if(traffic_sig == 'D'){
			if(!Q[9].empty() && !check_set_bit(kill_state,1)){
				Q[9].pop();
				count++;
				countW++;
			}
			if(!Q[3].empty() && !check_set_bit(kill_state,7)){
				Q[3].pop();
				count++;
				countE++;
			}
		}
		gettimeofday(&end, NULL);
		fprintf(NOCS_log,"%0.2f ",((double)end.tv_sec + (double)end.tv_usec / 1000000) - ((double)start.tv_sec + (double)start.tv_usec / 1000000));
		fflush(NOCS_log);
		if(traffic_sig == 'A'){
			fprintf(NOCS_log,"0 ");
			fflush(NOCS_log);
		}
		else if(traffic_sig == 'B'){
			fprintf(NOCS_log,"1 ");
			fflush(NOCS_log);
		}
		else if(traffic_sig == 'C'){
			fprintf(NOCS_log,"2 ");
			fflush(NOCS_log);
		}
		else if(traffic_sig == 'D'){
			fprintf(NOCS_log,"3 ");
			fflush(NOCS_log);
		}
		fprintf(NOCS_log,"%d ",count);
		fflush(NOCS_log);
		fprintf(NOCS_log,"%d ",countN);
		fflush(NOCS_log);
		fprintf(NOCS_log,"%d ",countE);
		fflush(NOCS_log);
		fprintf(NOCS_log,"%d ",countW);
		fflush(NOCS_log);
		fprintf(NOCS_log,"%d \n",countS);
		fflush(NOCS_log);
	}
	return (void*)-1;
}

/*Server Thread for receiving forwarded vehicles*/
void* server_thread(void *args){
	int *i =(int *)args;
	int portno,n,sockfd, newsockfd,dir = *i,queue_bit;
	socklen_t clilen;
	struct car* veh;
	struct sockaddr_in serv_addr, cli_addr;
	if(dir == 0){
		portno = 10000;
	}
	else if(dir == 1){
		portno = 20000;
	}
	else if(dir == 2){
		portno = 30000;
	}
	else if(dir == 3){
		portno = 40000;
	}
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cout<<"ERROR opening socket"<<endl;
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
              cout<<"ERROR on binding"<<endl;
    }
    listen(sockfd,20);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr,&clilen);
    if (newsockfd < 0){ 
          	cout<<"ERROR on accept"<<endl;
    }
    cout<<"server thread accepted:"<<node_name[dir]<<endl;
    while(1){
    	veh = (struct car*)malloc(sizeof(struct car));
    	n = recv(newsockfd,veh,sizeof(struct car),0);
    	if (n < 0){
    		cout<<"ERROR reading from socket"<<endl;
  		}
  		//cout<<"RECEIVING!"<<endl;
  		if(veh->SID == -1){
    		cout<<"Killing server thread"<<endl;
    		close(newsockfd);
    		close(sockfd);
    		pthread_exit(NULL);
		}
  		usleep(1000000);
  		queue_bit = (dir * 3) + veh->SID - 1;
  		Q[queue_bit].push(veh);
  	}
    return 0; 
}

/*Client thread for forwarding vehicles*/
void* client_thread(void *args){
	char option;
	int *i =(int *)args;
	int sockfd,count ,queue_bit, portno, n, dir = *i,pos;
	struct sockaddr_in serv_addr;
    struct hostent *server;
    struct car* veh;
    if(dir == 0){
		portno = 30000;
	}
	else if(dir == 1){
		portno = 40000;
	}
	else if(dir == 2){
		portno = 10000;
	}
	else if(dir == 3){
		portno = 20000;
	}
   	cout<<"Enter any key and hit enter to start the the client thread:"<<node_name[dir]<<endl;
	cin>>option;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){ 
    	cout<<"ERROR opening socket"<<endl;
    }
   	server = gethostbyname(node_name[dir]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){ 
        cout<<"ERROR connecting"<<endl;
    }
    cout<<"Client thread Connected:"<<node_name[dir]<<endl;
   	while(1){
    	count = 1;
    	if((ser_cli_state & 1<<dir) && Q[3-dir].empty() && Q[7-dir].empty() && Q[11-dir].empty()){
    		veh = (struct car*)malloc(sizeof(struct car));
    		memset(veh,0,sizeof(struct car));
    		veh->SID = -1;
    		n = send(sockfd,veh,sizeof(struct car),0);
			if (n < 0) {
        		cout<<"ERROR writing to socket"<<endl;
    		}
    		cout<<"SENDING FINAL PACKET!"<<endl;
    		usleep(2000000);
    		close(sockfd);
    		cout<<"killing client thread"<<endl;
    		pthread_exit(NULL);
    	}
		while(count != 4){
			queue_bit = (4 * count) - dir - 1;
			if(queue_bit % 3 == 2){ 				/* Turn lane - allways serviced */
				pos = (queue_bit - 3 + 12) % 12;
				if(!Q[queue_bit].empty() && !check_set_bit(update_serv_state[dir],pos)){
					veh = Q[queue_bit].front();
					n = send(sockfd,veh,sizeof(struct car),0);
					if (n < 0) {
        				cout<<"ERROR writing to socket"<<endl;
    				}
    			 	Q[queue_bit].pop();
				}
			}
			else if(queue_bit % 3 == 0){  			/* Signal Turn Lane */
				pos = (queue_bit + 3 + 12) % 12;
				if(!Q[queue_bit].empty() && Q[(queue_bit + 7) % 12].empty() && !check_set_bit(update_serv_state[dir],pos)){
					if(((queue_bit / 3) == 0 && (traffic_sig == 'A' || traffic_sig == 'B')) || ((queue_bit / 3) == 1 && (traffic_sig == 'C' || traffic_sig == 'D')) || ((queue_bit / 3) == 2 && (traffic_sig == 'A' || traffic_sig == 'B')) || ((queue_bit / 3) == 3 && (traffic_sig == 'C' || traffic_sig == 'D'))){
						veh = Q[queue_bit].front();
						n = send(sockfd,veh,sizeof(struct car),0);
						if (n < 0) {
        					cout<<"ERROR writing to socket"<<endl;
    					}
    					Q[queue_bit].pop();
					}
				}
			}
			else if(queue_bit % 3 == 1){		/* Straight lane vehicles */
				pos = queue_bit;
				if(!Q[queue_bit].empty() && !check_set_bit(update_serv_state[dir],pos)){     
					if(((queue_bit / 3) == 0 && traffic_sig == 'A') || ((queue_bit / 3) == 1 && traffic_sig == 'C') || ((queue_bit / 3) == 2 && traffic_sig == 'A') || ((queue_bit / 3) == 3 && traffic_sig == 'C')){
						veh = Q[queue_bit].front();
						n = send(sockfd,veh,sizeof(struct car),0);
						if (n < 0) {
        					cout<<"ERROR writing to socket"<<endl;
    					}
    					Q[queue_bit].pop();
					}
				}
			}
			count++;
		}
		usleep(1500000);
	}
}

/*Control Server Thread*/
void* ctrl_server_thread(void *args){
	int *i =(int *)args;
	u_short state;
	int portno,n,sockfd, newsockfd,dir = *i;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;
	if(dir == 0){
		portno = 15000;
	}
	else if(dir == 1){
		portno = 25000;
	}
	else if(dir == 2){
		portno = 35000;
	}
	else if(dir == 3){
		portno = 45000;
	}
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cout<<"ERROR opening socket"<<endl;
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
              cout<<"ERROR on binding"<<endl;
    }
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr,&clilen);
    if (newsockfd < 0){ 
          	cout<<"ERROR on accept"<<endl;
    }
    cout<<"ctrl server thread accepted:"<<node_name[dir]<<endl;
    while(1){
    	state = 0;
    	n = recv(newsockfd,(void*)&state,sizeof(u_short),0);
    	if (n < 0){
    		cout<<"ERROR reading from socket"<<endl;
  		}
  		if(state == -1){
    		cout<<"Killing ctrl server thread"<<endl;
			close(newsockfd);
    		close(sockfd);
    		pthread_exit(NULL);
    	}
    	update_serv_state[dir] = state;
  	}
    return 0; 
}

/*Control Client Thread*/
void* ctrl_client_thread(void *args){
	char option;
	int *i =(int *)args;
	u_short serv_state = 0;			/*0000|Q12|Q11|Q10|Q9|Q8|Q7|Q6|Q5|Q4|Q3|Q2|Q1*/
	int sockfd,count, portno, n, dir = *i;
	struct sockaddr_in serv_addr;
    struct hostent *server;
    if(dir == 0){
		portno = 35000;
	}
	else if(dir == 1){
		portno = 45000;
	}
	else if(dir == 2){
		portno = 15000;
	}
	else if(dir == 3){
		portno = 25000;
	}
   	cout<<"Enter any key and hit enter to start the the ctrl client thread:"<<node_name[dir]<<endl;
	cin>>option;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){ 
    	cout<<"ERROR opening socket"<<endl;
    }
   	server = gethostbyname(node_name[dir]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){ 
        cout<<"ERROR connecting"<<endl;
    }
    cout<<"Ctrl client thread Connected:"<<node_name[dir]<<endl;
   	while(1){
   		count = 0;
   		serv_state = 0;
   		if(ser_cli_state & 1<<dir){
   			serv_state = -1;
    		n = send(sockfd,(void*)&serv_state,sizeof(u_short),0);
			if (n < 0) {
        		cout<<"ERROR writing to socket"<<endl;
    		}
    		cout<<"SENDING CTRL FINAL PACKET!"<<endl;
    		usleep(2000000);
    		close(sockfd);
    		cout<<"killing ctrl client thread"<<endl;
    		pthread_exit(NULL);
    	}
   		while(count < 12){
   			if(Q[count].size() >= LANE_LENGTH){
   				serv_state = serv_state | (1<<count);
   			}
   			count++;
   		}
   		n = send(sockfd,(void *)&serv_state,sizeof(u_short),0);
		if (n < 0) {
        	cout<<"ERROR writing to socket"<<endl;
    	}
    	usleep(500000);
	}
}

int main(int argc, char * argv[]) {
	int c, err = 0; 
	extern char *optarg;

	/* input_arg is a 1-dim array with direction, lane */ 
	int option,count = 2,input_arg[2],len,dir;

	static char usage[] = "./<node_name> -d <dist_type> -f <config_file> -n <north_node/none> -w <west_node/none> -s <south_node/none> -e <east_node/none>\n\n";
	char TRAF_str[25],NOCS_str[25],Q_str[25];			/*File names*/
	pthread_t traffic_t,Qsize_t,service_t;
	pthread_t input_t[4][3];  				/*Input threads for for each direction*/
	pthread_t socket_t[4][2]; 				/*socket threads for each direction*/
	pthread_t ctrl_socket_t[4][2]; 			/*socket threads for each direction*/

	while ((c = getopt(argc, argv, "d:f:n:w:s:e:")) != -1)
		switch (c) {
		case 'd':
			dist_type = atoi(optarg);
		case 'f':
			config_f = optarg;
		case 'n':
			node_name[0] = optarg;
			break;
		case 'w':
			node_name[1] = optarg;
			break;
		case 's':
			node_name[2] = optarg;
			break;
		case 'e':
			node_name[3] = optarg;
			break;
		case '?':
			err = 1;
			break;
		default :
			err = 1;
			break; 
		}
	if (err) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}


	/*Log files
	  Name the log files based on the node name
	 */
	len = strlen(argv[0]);
	for(int i = 2; i<len;i++){
		TRAF_str[i-2] = argv[0][i];
		NOCS_str[i-2] = argv[0][i];
		Q_str[i-2] = argv[0][i];
	}
	TRAF_str[len - 2] = '\0';
	NOCS_str[len - 2] = '\0';
	Q_str[len - 2] = '\0';
	strcat(TRAF_str,"TRAF_log.txt");
	strcat(NOCS_str,"NOCS_log.txt");
	strcat(Q_str,"Q_log.txt");
	TRAF_log = fopen(TRAF_str,"w"); 		/*Traffic log*/
	NOCS_log = fopen(NOCS_str,"w");   	/*No. of Cars Serviced*/
	Q_log = fopen(Q_str,"w");  /*Size of the queues*/	
	
	
	/*Traffic thread*/
	pthread_create(&traffic_t,NULL,traffic_thread,NULL);


	/*Queue Size thread*/
	pthread_create(&Qsize_t,NULL,queue_size_thread,NULL);

	/*Service threads*/
	pthread_create(&service_t,NULL,service_thread,NULL);


	/*Input threads*/


	/* if input_arg[0] = 0 --> direction north 
	      input_arg[0] =1  --> direction is west 
	      input_arg[0] =2 --> direction is south 
	      input_arg[0] =3 --> direction is east 

	 */ 
	count = 2 
	while(count != 6){

	  /* if there is no connection intersections then there is a "none" 
	     if there is then we need to setup communication with sockets */ 

		if(strncmp(node_name[count-2],"none",4) == 0){
		  /* generate three input queue thread for each direction. The direction value is in "count-2" 
		     the lane number is "i+1" */ 
			for(int i = 0; i < 3; i++){
				input_arg[0] = count - 2;   /* Direction*/
				input_arg[1] = i;	/*Lane*/
				/* 8-bit vector for inter-intersection connections ESWN (client) ESWN (server) */ 
				ser_cli_state = ser_cli_state | 1<<(count - 2);
				ser_cli_state = ser_cli_state | 1<<((count - 2) + 4);
				pthread_create(&input_t[count-2][i],NULL,input_thread,(void*)&input_arg);
				/* 0.1 second for sync */ 
				usleep(100000);
			}
		}
		else{
		  /* 12 -bit vector to  where a 3-bit clustering indicate a position/presence of an intersection */ 
			kill_state = kill_state | 7 << (count - 2) * 3;
			dir = count - 2;
			pthread_create(&socket_t[dir][0],NULL,server_thread,(void*)&dir);
			usleep(5000);
			pthread_create(&socket_t[dir][1],NULL,client_thread,(void*)&dir);
			usleep(100000);
			pthread_create(&ctrl_socket_t[dir][0],NULL,ctrl_server_thread,(void*)&dir);
			usleep(5000);
			pthread_create(&ctrl_socket_t[dir][1],NULL,ctrl_client_thread,(void*)&dir);
			usleep(100000);
		}
		count++;
	}
	cout<<"Enter your choice"<<endl;
	cout<<"1: Kill thread"<<endl;
	cout<<"2: QUIT"<<endl;
	cin>>option;
	if(option == 1){
		while(kill_state != 4095){
			cout<<"Enter the thread u want to kill (1-12)"<<endl;
			cin>>option;
			if(option>0 && option<13){
				count = ((option - 1) / 3);
				if((kill_state & (1<<(option-1))) == 0){
					kill_state = kill_state | (1<<(option-1));
					cout<<"kill_state:"<<kill_state<<endl;
					option = (option - 1) % 3;
					pthread_join(input_t[count][option],NULL);
				}
				else if((ser_cli_state & (1<<count)) == 0){
					ser_cli_state = ser_cli_state | 1<<count;
					ser_cli_state = ser_cli_state | 1<<(count + 4);
					printf("ser_cli_state:%d\n",ser_cli_state);
					pthread_join(socket_t[count][0],NULL);
					pthread_join(ctrl_socket_t[count][0],NULL);
					pthread_join(socket_t[count][1],NULL);
					pthread_join(ctrl_socket_t[count][1],NULL);
				}
				else{
					cout<<"Thread already killed"<<endl;				
				}
			}
			else{
				cout<<"WRONG OPTION"<<endl;
			}
		}
	}
	else if(option == 2){ 
		cout<<"QUITINGGGG!!!"<<endl;
		exit(0);
	}
	else{
		cout<<"WRONG OPTION"<<endl;
		exit(0);
	}
	while(Q[0].empty() && Q[1].empty() && Q[2].empty() && Q[3].empty() && Q[4].empty() && Q[5].empty() && Q[6].empty() && Q[7].empty() && Q[8].empty() && Q[9].empty() && Q[10].empty() && Q[11].empty());
	cout<<"SHUTTING DOWN SHORTLY"<<endl;

	/* Sleep to ensure all the queues are serviced and empty before quitting */ 
	usleep(60000000);
	return 0;
}

