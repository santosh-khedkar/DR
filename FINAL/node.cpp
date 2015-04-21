#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <queue>
#include "car.h"
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <signal.h>

using namespace std;

/*Input queues*/
queue<car*> Q[12];


/*Bit Vector for kill state */
u_short kill_state = 0 ; /*0000|Q12|Q11|Q10|Q9|Q8|Q7|Q6|Q5|Q4|Q3|Q2|Q1*/

char traffic_sig = '-'; 		/*Traffic state (A/B/C/D) */
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int dist_type;

/*Traffic Signal thread*/

void* traffic_thread(void *args){
	int count=0;
	while(1){
		switch(count){
			case 0: 
				traffic_sig='A'; 		/*N-S Green*/
				printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
				usleep(25000000); 		/*sleep for 25s*/
				count++;
				break;
			case 1:
				traffic_sig='B';		/*N-S Yellow*/
				printf("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
				usleep(5000000); 		/*sleep for 5s*/
				count++;
				break;
			case 2: 
				traffic_sig='C';		/*E-W Green*/
				printf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n");
				usleep(25000000);		/*sleep for 25s*/
				count++;
				break;
			case 3: 
				traffic_sig='D';		/*E-W Yellow*/
				printf("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n");
				usleep(5000000);		/*sleep for 5s*/
				count=0;
				break;
			default:
				traffic_sig='-';
				break; 				
		}
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
	int lane = *i + 1;
	unsigned int Vehicle_id = 0;
	while(1){
		if(kill_state & (1<<(lane-1))){
			cout<<"killing thread "<<lane<<endl;
			pthread_exit(NULL);
		}
		struct car* vehicle = (struct car*)malloc(sizeof(struct car));
		Vehicle_id++;
		vehicle->SID = lane;
		vehicle->Vehicle_ID = Vehicle_id;
		Q[lane - 1].push(vehicle);
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
	while(1){
		/*Turn lanes always get serviced*/
		usleep(1000000);
		if(!Q[2].empty()){
			Q[2].pop();
		}
		if(!Q[11].empty()){
			Q[11].pop();
		}
		if(!Q[8].empty()){
			Q[8].pop();
		}
		if(!Q[5].empty()){
			Q[5].pop();
		}
		if(traffic_sig == 'A'){
			if(!Q[1].empty()){
				Q[1].pop();
			}
			else if(!Q[6].empty()){
				Q[6].pop();
			}
			if(!Q[7].empty()){
				Q[7].pop();
			}
			else if(!Q[0].empty()){
				Q[0].pop();
			}
		}
		else if(traffic_sig == 'B'){
			if(!Q[6].empty()){
				Q[6].pop();
			}
			if(!Q[0].empty()){
				Q[0].pop();
			}
		}
		if(traffic_sig == 'C'){
			if(!Q[4].empty()){
				Q[4].pop();
			}
			else if(!Q[9].empty()){
				Q[9].pop();
			}
			if(!Q[10].empty()){
				Q[10].pop();
			}
			else if(!Q[3].empty()){
				Q[3].pop();
			}
		}
		else if(traffic_sig == 'D'){
			if(!Q[9].empty()){
				Q[9].pop();
			}
			if(!Q[3].empty()){
				Q[3].pop();
			}
		}
	}
}


/*1 - Input Distribution Type*/

int main(int argc, const char * argv[]) {
	dist_type = atoi(argv[1]);
	int option;
	pthread_t traffic_t,Qsize_t,service_t;
	pthread_t input_t[12];  /*Input threads for 12 queues*/
	/*Traffic thread*/
	pthread_create(&traffic_t,NULL,traffic_thread,NULL);
	/*Queue Size thread*/
	//pthread_create(&Qsize_t,NULL,queue_size_thread,NULL);
	/*Service threads*/
	pthread_create(&service_t,NULL,service_thread,NULL);
	/*Input threads*/
	for(int i = 0; i < 12; i++){
		pthread_create(&input_t[i],NULL,input_thread,(void*)&i);
		usleep(100000);
	}
	while(kill_state != 4095){
		do{
			cout<<"Enter the thread u want to kill (1-12)"<<endl;
			cin>>option;
			if((kill_state & (1<<(option-1))) == 0){
				kill_state = kill_state | (1<<(option-1));
				pthread_join(input_t[option-1],NULL);
			}
			else{
				cout<<"Thread already killed"<<endl;
				exit(0);
			}
		}while(option>0 && option<13);
	}
	return 0;
}

