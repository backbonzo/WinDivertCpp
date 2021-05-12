#pragma once
#define MAXBUFFER 0xFFFF

struct NetworkTuple
{
	bool IsMatching(const NetworkTuple& other) const;

	bool operator==(const NetworkTuple& other) const;

	std::string srcAddress = "";
	UINT16 srcPort = 0;
	std::string dstAddress = "";
	UINT16 dstPort = 0;
	UINT8 protocol = 0;
};

struct NetworkData
{
	NetworkTuple tuple;
	unsigned long processID = 0;
	std::wstring processPath = L"";
};

struct netData
{

	PWINDIVERT_IPHDR ip_header = nullptr;
	PWINDIVERT_IPV6HDR ipv6_header = nullptr;
	PWINDIVERT_UDPHDR udp_header = nullptr;
	PWINDIVERT_TCPHDR tcp_header = nullptr;
	PWINDIVERT_ICMPHDR icmp_header = nullptr;
	PWINDIVERT_ICMPV6HDR icmpv6_header = nullptr;

	char packet[MAXBUFFER];
	UINT packetLen;
	UINT8 protocol;
	UINT32 ProcessId;
	WINDIVERT_ADDRESS addr;

	std::string src;
	std::string dst;

	UINT16 srcPort;
	UINT16 dstPort;
};

class Packet
{
public:	
	Packet() = default;
	Packet(const Packet& other) = delete;
	Packet& operator=(const Packet& other) = delete;

	const char* GetData() const;
	unsigned int GetSize() const;
	unsigned int GetLength() const;
	const WINDIVERT_ADDRESS& GetAddress() const;
	const std::wstring& GetProcessPath() const;
	void SetProcessPath(std::wstring& path);
	const DWORD GetProcessId() const;
	void SetProcessId(DWORD processId);
	const NetworkData& GetNetworkData() const;
	// Will check if the NetworkTuples are the same.
	bool IsMatching(const Packet& other) const;
	bool IsMatching(const NetworkTuple& other) const;

	// Use only in PacketManager GatherProcessData!
	NetworkData&& PilferNetworkData();

private:
	friend class Divert;

	char packetData[MAXBUFFER];
	unsigned int packetSize = MAXBUFFER;
	unsigned int packetLength = 0;
	WINDIVERT_ADDRESS address;
	NetworkData networkData;
};
