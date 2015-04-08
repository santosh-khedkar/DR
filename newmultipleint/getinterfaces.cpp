//
//  getinterfaces.cpp
//  get interfaces
//
//  Created by MatthewZera on 4/1/15.
//  Copyright (c) 2015 Zera. All rights reserved.
//

#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, const char * argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];
    
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
            
            //print interface name and host
            printf("%-8s %s\n", ifa->ifa_name, host);
            }
        }
    }
    
    //free linked list
    freeifaddrs(ifaddr);
    exit(EXIT_SUCCESS);
    
    return 0;
}



