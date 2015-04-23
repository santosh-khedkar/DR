/*
 	node.cpp
  	Created by Santosh Narayankhedkar on 04/20/2015
 	Copyright (c) 2015 Narayankhedkar. All rights reserved.
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
#include <netinet/in.h>
#include <netdb.h> 

using namespace std;
FILE *TRAF_log = fopen("traffic.txt","w"); 		/*Traffic log*/
FILE *NOCS_log = fopen("throughput.txt","w");   /*No. of Cars Serviced*/
FILE *NOCSN_log = fopen("throughputN.txt","w");   /*No. of Cars Serviced in North direction*/
FILE *NOCSE_log = fopen("throughputE.txt","w");   /*No. of Cars Serviced in East direction*/
FILE *NOCSS_log = fopen("throughputS.txt","w");   /*No. of Cars Serviced in South direction*/
FILE *NOCSW_log = fopen("throughputW.txt","w");   /*No. of Cars Serviced in West direction*/

/*Input queues*/
queue<car*> Q[12];

/*Bit Vector for kill state */
u_short kill_state = 0 ; 		/*0000|Q12|Q11|Q10|Q9|Q8|Q7|Q6|Q5|Q4|Q3|Q2|Q1*/
u_short queue_state = 0 ; 		/*0000|Q12|Q11|Q10|Q9|Q8|Q7|Q6|Q5|Q4|Q3|Q2|Q1*/
unsigned char ser_cli_state = 0; 		/*|WC|SC|EC|NC|WS|SS|ES|NS|*/

char traffic_sig = '-'; 		/*Traffic state (A/B/C/D) */
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int dist_type;
char *node_name[4];

/*Traffic Signal thread*/

void* traffic_thread(void *args){
	int count=0;
	while(1){
		switch(count){
			case 0: 
				traffic_sig='A'; 		/*N-S Green*/
				//printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
				usleep(25000000); 		/*sleep for 25s*/
				count++;
				break;
			case 1:
				traffic_sig='B';		/*N-S Yellow*/
				//printf("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
				usleep(5000000); 		/*sleep for 5s*/
				count++;
				break;
			case 2: 
				traffic_sig='C';		/*E-W Green*/
				//printf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n");
				usleep(25000000);		/*sleep for 25s*/
				count++;
				break;
			case 3: 
				traffic_sig='D';		/*E-W Yellow*/
				//printf("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n");
				usleep(5000000);		/*sleep for 5s*/
				count=0;
				break;
			default:
				traffic_sig='-';
				break; 				
		}
	}
}

bool check_set_bit(u_short var,int pos){
	if(var & 1<<pos){
		return true;
	}
	else{
		return false;
	} 

}
/*Queue size thread*/
void* queue_size_thread(void *args){
    while(1){
    	cout<<"--------------------------------------"<<endl;
    	cout<<"Q1 SIZE = "<<Q[0].size()<<endl;
        cout<<"Q2 SIZE = "<<Q[1].size()<<endl;
        cout<<"Q3 SIZE = "<<Q[2].size()<<endl;
        cout<<"Q4 SIZE = "<<Q[3].size()<<endl;
        cout<<"Q5 SIZE = "<<Q[4].size()<<endl;
        cout<<"Q6 SIZE = "<<Q[5].size()<<endl;
        cout<<"Q7 SIZE = "<<Q[6].size()<<endl;
        cout<<"Q8 SIZE = "<<Q[7].size()<<endl;
        cout<<"Q9 SIZE = "<<Q[8].size()<<endl;
        cout<<"Q10 SIZE = "<<Q[9].size()<<endl;
        cout<<"Q11 SIZE = "<<Q[10].size()<<endl;
        cout<<"Q12 SIZE = "<<Q[11].size()<<endl;
        usleep(500000);
    }
}

void* input_thread(void *args){
	int *i = (int*)args;
	int lane = i[1] + 1;
	int dir = i[0];
	int queue_bit = (dir * 3) + lane - 1;
	unsigned int Vehicle_id = 0;
	while(1){
		if(kill_state & (1<< queue_bit)){
			cout<<"killing thread "<<lane<<endl;
			pthread_exit(NULL);
		}
		struct car* vehicle = (struct car*)malloc(sizeof(struct car));
		Vehicle_id++;
		vehicle->SID = lane;
		vehicle->Vehicle_ID = Vehicle_id;
		Q[queue_bit].push(vehicle);
		if( lane == 1 || lane == 2 || lane == 3){
			vehicle->direction = 'N';
		}
		else if( lane == 4 || lane == 5 || lane == 6){
			vehicle->direction = 'E';
		}
		else if( lane == 7 || lane == 8 || lane == 9){
			vehicle->direction = 'S';
		}
		else if( lane == 10 || lane == 11 || lane == 12){
			vehicle->direction = 'W';
		}
		else{
			cout<<"ERROR: Wrong lane!!!!!"<<endl;
			cout<<"LANE:"<<lane;
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
	}
}

void* service_thread(void *args){
	int count,countN,countE,countS,countW;
	while(1){
		count = countN = countE = countS = countW = 0;
		usleep(1500000);
		/*Turn lanes always get serviced*/
		if(!Q[2].empty() && !check_set_bit(kill_state,2)){
			Q[2].pop();
			count++;
			countN++;
		}
		if(!Q[11].empty() && !check_set_bit(kill_state,11)){
			Q[11].pop();
			count++;
			countW++;
		}
		if(!Q[8].empty() && !check_set_bit(kill_state,8)){
			Q[8].pop();
			count++;
			countS++;
		}
		if(!Q[5].empty() && !check_set_bit(kill_state,5)){
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
			else if(!Q[6].empty() && !check_set_bit(kill_state,6)){
				Q[6].pop();
				count++;
				countS++;
			}
			if(!Q[7].empty() && !check_set_bit(kill_state,7)){
				Q[7].pop();
				count++;
				countS++;
			}
			else if(!Q[0].empty() && !check_set_bit(kill_state,0)){
				Q[0].pop();
				count++;
				countN++;
			}
		}
		else if(traffic_sig == 'B'){
			if(!Q[6].empty() && !check_set_bit(kill_state,6)){
				Q[6].pop();
				count++;
				countS++;
			}
			if(!Q[0].empty() && !check_set_bit(kill_state,0)){
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
			else if(!Q[9].empty() && !check_set_bit(kill_state,9)){
				Q[9].pop();
				count++;
				countW++;
			}
			if(!Q[10].empty() && !check_set_bit(kill_state,10)){
				Q[10].pop();
				count++;
				countW++;
			}
			else if(!Q[3].empty() && !check_set_bit(kill_state,3)){
				Q[3].pop();
				count++;
				countE++;
			}
		}
		else if(traffic_sig == 'D'){
			if(!Q[9].empty() && !check_set_bit(kill_state,9)){
				Q[9].pop();
				count++;
				countW++;
			}
			if(!Q[3].empty() && !check_set_bit(kill_state,3)){
				Q[3].pop();
				count++;
				countE++;
			}
		}
		if(traffic_sig == 'A'){
			fprintf(TRAF_log,"0 ");
			fflush(TRAF_log);
		}
		else if(traffic_sig == 'B'){
			fprintf(TRAF_log,"1 ");
			fflush(TRAF_log);
		}
		else if(traffic_sig == 'C'){
			fprintf(TRAF_log,"2 ");
			fflush(TRAF_log);
		}
		else if(traffic_sig == 'D'){
			fprintf(TRAF_log,"3 ");
			fflush(TRAF_log);
		}
		fprintf(NOCS_log,"%d ",count);
		fflush(NOCS_log);
		fprintf(NOCSN_log,"%d ",countN);
		fflush(NOCSN_log);
		fprintf(NOCSE_log,"%d ",countE);
		fflush(NOCSE_log);
		fprintf(NOCSW_log,"%d ",countW);
		fflush(NOCSW_log);
		fprintf(NOCSS_log,"%d ",countS);
		fflush(NOCSS_log);
	}
}

void* server_thread(void *args){
	int *i =(int *)args;
	int portno,n,sockfd, newsockfd,dir = *i;
	cout<<"SERVER THREAD CREATED:"<<dir<<endl;
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
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr,&clilen);
    if (newsockfd < 0){ 
          	cout<<"ERROR on accept"<<endl;
    }
    cout<<"accepted"<<endl;
    while(1){
    	if(ser_cli_state & 1<<dir){
    		cout<<"Killing server thread"<<endl;
    		pthread_exit(NULL);
    	}
    	veh = (struct car*)malloc(sizeof(struct car));
    	n = recv(newsockfd,veh,sizeof(struct car),0);
    	if (n < 0){
    		cout<<"ERROR reading from socket"<<endl;
  		}
  		cout<<"RECEIVING!"<<endl;
  		Q[(dir*3) + veh->SID - 1].push(veh);
  	}
    close(newsockfd);
    close(sockfd);
    return 0; 
}


void* client_thread(void *args){
	char option;
	int *i =(int *)args;
	int sockfd,count ,queue_bit, portno, n, dir = *i;
	struct sockaddr_in serv_addr;
    struct hostent *server;
    struct car* veh;
    cout<<"CLIENT THREAD CREATED:"<<dir<<endl;
	cout<<"Enter any key and hit enter to start the the client"<<endl;
	cin>>option;
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
    cout<<"Connected"<<endl;
   	while(1){
    	count = 1;
    	if((ser_cli_state & 1<<dir) && Q[4-dir].empty() && Q[8-dir].empty() && Q[12-dir].empty()){
    		cout<<"killing client thread"<<endl;
    		pthread_exit(NULL);
    	}
    	usleep(1500000);
		while(count != 4){
			queue_bit = (4 * count) - dir; 
			if(!Q[queue_bit].empty()){
				veh = Q[queue_bit].front();
				n = send(sockfd,veh,sizeof(struct car),0);
				if (n < 0) {
        			cout<<"ERROR writing to socket"<<endl;
    			}
    			cout<<"SENDING!"<<endl;
				Q[queue_bit].pop();
			}
			count ++;
		}
	}
    close(sockfd);
}


/*1 - Input Distribution Type*/

int main(int argc, const char * argv[]) {
	dist_type = atoi(argv[1]);
	int option,count = 2,input_arg[2],len,dir;
	pthread_t traffic_t,Qsize_t,service_t;
	pthread_t input_t[4][3];  /*Input threads for for each direction*/
	pthread_t socket_t[4][2];
	if(argc != 6){
		cout<<"NOT ENOUGH ARGUMENT"<<endl;
		exit(0);
	}
	while(count != 6){
		len = strlen(argv[count]);
		node_name[count - 2] = (char *)malloc(sizeof(char)* (len + 1));
		strncpy(node_name[count - 2],argv[count],len);
		node_name[count - 2][len] = '\0';
		count++;
	}
	count = 2;
	/*Traffic thread*/
	pthread_create(&traffic_t,NULL,traffic_thread,NULL);
	/*Queue Size thread*/
	//pthread_create(&Qsize_t,NULL,queue_size_thread,NULL);
	/*Service threads*/
	pthread_create(&service_t,NULL,service_thread,NULL);
	/*Input threads*/
	while(count != 6){
		if(strncmp(argv[count],"none",4) == 0){
			for(int i = 0; i < 3; i++){
				input_arg[0] = count - 2;
				input_arg[1] = i;
				ser_cli_state = ser_cli_state | 1<<(count - 2);
				ser_cli_state = ser_cli_state | 1<<((count - 2) + 4);
				pthread_create(&input_t[count-2][i],NULL,input_thread,(void*)&input_arg);
				usleep(100000);
			}
		}
		else{
			kill_state = kill_state | 7 << (count - 2) * 3;
			dir = count - 2;
			pthread_create(&socket_t[dir][0],NULL,server_thread,(void*)&dir);
			usleep(5000);
			pthread_create(&socket_t[dir][1],NULL,client_thread,(void*)&dir);
			usleep(100000);
		}
		count++;
	}
	cout<<"Enter your choice"<<endl;
	cout<<"1: Kill thread"<<endl;
	cout<<"2: Blow up the queues"<<endl;
	cout<<"3: QUIT"<<endl;
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
					cout<<"ser_cli_state:"<<ser_cli_state<<endl;
					pthread_join(socket_t[count][0],NULL);
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
		cout<<"Enter the queue u want to blow up (1-12)"<<endl;
		cin>>option;
		if(option>0 && option<13){
			if((queue_state & (1<<(option-1))) == 0){
				queue_state = queue_state | (1<<(option-1));
				cout<<"queue_state:"<<queue_state<<endl;
				count = ((option - 1) / 3);
				option = (option - 1) % 3;
				pthread_join(input_t[count][option],NULL);
			}
			else{
				cout<<"Queue Bit already set"<<endl;				
			}
		}
		else{
			cout<<"WRONG OPTION"<<endl;
		}
	}
	else if(option == 3){ 
		cout<<"QUITINGGGG!!!"<<endl;
		exit(0);
	}
	else{
		cout<<"WRONG OPTION"<<endl;
		exit(0);
	}
	cout<<"SHUTTING DOWN SHORTLY"<<endl;
	usleep(60000000);
	return 0;
}

