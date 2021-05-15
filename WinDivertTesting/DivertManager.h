#pragma once
#include <thread>
#include <windivert.h>
#include <mutex>
#include <queue>
#include <Psapi.h>
#include <memory>
#include <map>

#define MAXBUF 0xFFFF


struct netData
{
	
	PWINDIVERT_IPHDR ip_header = nullptr;
	PWINDIVERT_IPV6HDR ipv6_header = nullptr;
	PWINDIVERT_UDPHDR udp_header = nullptr;
	PWINDIVERT_TCPHDR tcp_header = nullptr;
	PWINDIVERT_ICMPHDR icmp_header = nullptr;
	PWINDIVERT_ICMPV6HDR icmpv6_header = nullptr;

	char packet[MAXBUF];
	UINT packetLen;
	UINT8 protocol;
	UINT32 ProcessId;
	WINDIVERT_ADDRESS addr;
};


class DivertManager
{
public:
	DivertManager(std::string, bool);
	~DivertManager();

	void addPortToList(UINT32);

	std::string getProcessNameByPid(UINT32);
	void startThreads();

private:
	void sendPacketFromQueues();
	void filterPacketIntoQueues();
	void packetsRequester();
	void resetData(netData&);
	std::thread th_senderWorker, th_getterWorker, th_reqWorker;
	std::mutex Mutex;
	netData senderData, recvData, reqData;
	std::string prioProcName;
	bool th_running = true;
	HANDLE mainHandle;
	std::queue<netData> normalPacketQueue, HighPrioPacketQueue;
	std::map<UINT32, bool> listOfPorts;
	int counter = 0, resetAt = 500;
};
