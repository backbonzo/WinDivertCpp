#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <windows.h>
#include <string.h>
#include "windivert.h"
#include "DivertManager.h"
#include <iostream>

#define MAXBUF 0xFFFF

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, * PTCPPACKET;


int main(int argc, char* argv[])
{
	//INT16 priority = 0;
	//HANDLE handle;          // WinDivert handle
	//WINDIVERT_ADDRESS addr; // Packet address
	//char packet[MAXBUF];    // Packet buffer
	//UINT packetLen;
	//PWINDIVERT_IPHDR ipHdr;
	//PWINDIVERT_TCPHDR tcpHr;
	//PWINDIVERT_UDPHDR udpHDR;

	//handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_RECV_ONLY||WINDIVERT_FLAG_SEND_ONLY);
	//if (handle == INVALID_HANDLE_VALUE)
	//{
	//	printf("error : WinDivertOpen()\n");
	//	return 0;
	//}

	DivertManager dm("chrome.exe", true);

	dm.startThreads();
	UINT32 yea;
	std::cin >> yea;
		
	while (yea != -1) {
		dm.addPortToList(yea);
		std::cin >> yea;
	}
	return 0;
}