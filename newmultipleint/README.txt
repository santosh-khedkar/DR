README:

*C=Compilation
*R=Run

1. Inputnode:
C = g++ -o <nodename> inputnode.cpp -lpcap -lpthread
R = ./<nodename> <direction> <SID> <TYPE> <Interface>

*direction: In caps (N/S/E/W) 
*SID: 1/2/3
*TYPE: CBR(0), Poisson(1)
*Interface: ether interface

2. Forwarder:
C = g++ -o <forwarder> forwarder.cpp -lpcap -lpthread
R = ./<forwarder> <textfile.txt> <N_int> <E_int> <S_int> <W_int> 

*textfile: forwarder.txt
*N_int : North interface
*S_int : South interface
*E_int : East interface
*W_int : West interface

3. Controller:
C = g++ -o <controller> controller.cpp -lpcap -lpthread
R = ./<controller> <textfile.txt> <logfile.txt> <N_int> <E_int> <S_int> <W_int>

*textfile: controller.txt
*logfile: logfile
*N_int : North interface
*S_int : South interface
*E_int : East interface
*W_int : West interface

4. E-W nodes:
C = g++ -o <nodeEW> nodeEW.cpp -lpcap -lpthread
R = ./<nodeEW> <E_int> <W_int>

*E_int : East interface
*W_int : West interface

5. N-S nodes:
C = g++ -o <nodeNS> nodeNS.cpp -lpcap -lpthread
R = ./<nodeNS> <N_int> <S_int>

*N_int : North interface
*S_int : South interface

6. I-nodes:

C = g++ -o <nodeI*> nodeI*.cpp -lpcap -lpthread
R = ./<nodeI*> <int_node> <fwd_int> <textfile> <INT1> <INT2> <INT3> <fwder_int> <controller_int>

*int_node : True(1) if its an interection node, False(0) if not.
*fwd_int: North: 00000WSE, South: 00000WNE, East: 00000NWS, West: 00000NES
*INT1: interface corresponding to node1 
*INT2: interface corresponding to node2
*INT3: interface corresponding to node3
*fwder_int: interface corresponding to forwarder
*controller_int: interface corresponding to controller




