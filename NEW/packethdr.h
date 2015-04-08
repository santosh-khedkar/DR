
struct packet{
	char direction; /*N,E,S,W */
	char sub_direction;
	u_short Vehicle_ID; /*Vehicle no*/
	u_short Lane; 	/*Which Lane i correspond to*/
	u_short SID,DID; /* source and destination ID*/
};


struct state_t{
	char direction; /*N,E,S,W */
	u_short state;
};