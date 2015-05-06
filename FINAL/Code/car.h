/*
 	node.cpp
  	Created by Santosh Narayankhedkar on 04/20/2015
 	Copyright (c) 2015 Narayankhedkar. All rights reserved.
*/

#define MAX_SPEED 25
#define LANE_LENGTH 10
 	
struct car{
	char direction; /*N,E,S,W */
	char intersection[25];  /*Name of the intersection*/
	u_short Vehicle_ID; /*Vehicle no*/
	u_short SID; /* Source ID*/
};
