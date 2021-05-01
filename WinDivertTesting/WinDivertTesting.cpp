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

	//while (true)
	//{

		dm.startThreads();
		int yea;
		std::cin >> yea;

		dm.~DivertManager();
		////std::cout << WinDivertRecv(handle, pPacket, sizeof(pPacket), &len, &addr) << "\n";

	//	if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr))
	//	{
	//		printf("error : WinDivertRecv()\n");
	//		continue;
	//	}

	//	//char RemoteAddr[128];
	//	//char LocalAddr[128];
	//	//WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(WinDivertHelperNtohl(*(addr.Flow.RemoteAddr))), RemoteAddr, sizeof(RemoteAddr));
	//	//WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(WinDivertHelperNtohl(*(addr.Flow.LocalAddr))), LocalAddr, sizeof(LocalAddr));

	//	//std::cout << "pid: " << addr.Flow.ProcessId << ", srcPort: " << addr.Flow.LocalPort << " srcAddr:" << LocalAddr << ", dstPort: " << addr.Flow.RemotePort << " dstAddr:" << RemoteAddr << std::endl;
	//	char buffer[128];
	//	WinDivertHelperParsePacket(&packet, packetLen, &ipHdr, NULL, NULL,
	//								NULL, NULL, &tcpHr, &udpHDR, NULL,
	//								NULL, NULL, NULL);

	//	if (tcpHr == NULL) {
	//		if (!WinDivertSend(handle, packet, packetLen, &packetLen, &addr))
	//		{
	//			printf("error : WinDviertSend()\n");
	//			continue;
	//		}
	//		continue;
	//	}


	//	WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(ipHdr->DstAddr), buffer, sizeof(buffer));

	//	std::cout << ntohs(tcpHr->SrcPort) << std::endl;


	//	if (!WinDivertSend(handle, packet, packetLen, &packetLen, &addr))
	//	{
	//		printf("error : WinDviertSend()\n");
	//		continue;
	//	}

	//}

	return 0;
}