/*
 	node.cpp
  	Created by Santosh Narayankhedkar on 04/20/2015
 	Copyright (c) 2015 Narayankhedkar. All rights reserved.
*/

#define MAX_SPEED 25
#define LANE_LENGTH 10
 	
struct car{
	char direction; /*N,E,S,W */
	u_short Vehicle_ID; /*Vehicle no*/
	int sleep_time; /*sleep time at the intersection*/
	u_short SID; /* Source ID*/
};
