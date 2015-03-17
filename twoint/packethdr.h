
struct packet{
	
	u_short Vehicle_ID; /*Vehicle no*/
	u_short Lane; 	/*Which Lane i correspond to*/
	u_short SID,DID; /* source and destination ID*/
};


struct state_t{
	char direction;
	u_short state;
};