#include "pch.h"
#include "Divert.h"

Divert::Divert()
	:
	Divert("true", WINDIVERT_LAYER_NETWORK)
{
}

Divert::Divert(const std::string& filter,const WINDIVERT_LAYER layer, int priority, unsigned int flags)
	:
	layer(layer)
{
	/*HANDLE WinDivertOpen(
		__in const char* filter,
		__in WINDIVERT_LAYER layer,
		__in INT16 priority,
		__in UINT64 flags
	);*/
	divertHandle = WinDivertOpen(filter.c_str(), layer, priority, flags);

	if (divertHandle == INVALID_HANDLE_VALUE)
	{
		using namespace BandwidthPriority;
		Log::log(LogLevel::Fatal, "Divert handle not opened.");
		LogError(GetLastError());
		initialized = false;
	}
	else
	{
		using namespace BandwidthPriority;
		Log::log(LogLevel::Info, "Divert handle opened.");
		initialized = true;
	}
}

Divert::~Divert()
{
	initialized = false;
	WinDivertClose(divertHandle);
	using namespace BandwidthPriority;
	Log::log(LogLevel::Info, "Divert handle closed.");
}

bool Divert::IsInitialized() const
{
	return initialized;
}

std::unique_ptr<WINDIVERT_ADDRESS> Divert::GetPacketAddress() const
{
	// Read a matching packet address.
	auto address = std::make_unique <WINDIVERT_ADDRESS>();
	if (!WinDivertRecv(divertHandle, nullptr, 0,nullptr,address.get()))
	{
		using namespace BandwidthPriority;
		Log::log(LogLevel::Error, "Failed to receive packet.");
		LogError(GetLastError());
	}
	return std::move(address);
}

std::unique_ptr<netData> Divert::GetPacket()
{
	/*BOOL WinDivertRecv(
	__in HANDLE handle,
		__out_opt PVOID pPacket,
		__in UINT packetLen,
		__out_opt UINT* pRecvLen,
		__out_opt WINDIVERT_ADDRESS* pAddr
		);*/
	auto packet = std::make_unique<netData>();
	if (layer == WINDIVERT_LAYER_FLOW)
	{
		if (!WinDivertRecv(divertHandle, nullptr, 0, nullptr, &packet->addr))
		{
			using namespace BandwidthPriority;
			Log::log(LogLevel::Error, "Failed to receive packet.");
			LogError(GetLastError());
		}

		// Set source and destination based on outbound
		const UINT32* src, * dest;
		UINT16 srcPort, destPort;
		if (packet->addr.Outbound == 1)
		{
			src = packet->addr.Flow.LocalAddr;
			dest = packet->addr.Flow.RemoteAddr;

			srcPort = packet->addr.Flow.LocalPort;
			destPort = packet->addr.Flow.RemotePort;
		}
		else
		{
			src = packet->addr.Flow.RemoteAddr;
			dest = packet->addr.Flow.LocalAddr;

			srcPort = packet->addr.Flow.RemotePort;
			destPort = packet->addr.Flow.LocalPort;
		}
		packet->src = GetIPAddress(src);
		packet->srcPort = srcPort;
		packet->dst = GetIPAddress(dest);
		packet->dstPort = destPort;
		packet->protocol = packet->addr.Flow.Protocol;
		// Set processID
		packet->ProcessId = packet->addr.Flow.ProcessId;
	}
	else if (layer == WINDIVERT_LAYER_NETWORK)
	{
		if (!WinDivertRecv(divertHandle, packet->packet, sizeof(packet->packet), &packet->packetLen, &packet->addr))
		{
			using namespace BandwidthPriority;
			Log::log(LogLevel::Error, "Failed to receive packet.");
			LogError(GetLastError());
		}
		Header header(*packet);

		packet->src = header.GetSource();
		packet->srcPort = header.GetSourcePort();
		packet->dst = header.GetDestination();
		packet->dstPort = header.GetDestinationPort();
		packet->protocol = header.protocol;
	}
	
	return std::move(packet);
}

bool Divert::SendPacket(netData& packet)
{
	/*BOOL WinDivertSend(
		__in HANDLE handle,
		__in const VOID * pPacket,
		__in UINT packetLen,
		__out_opt UINT * pSendLen,
		__in const WINDIVERT_ADDRESS * pAddr
	);*/
	if (layer == WINDIVERT_LAYER_NETWORK || layer == WINDIVERT_LAYER_NETWORK_FORWARD)
	{
		if (!WinDivertSend(divertHandle, packet.packet, sizeof(packet.packet), &packet.packetLen, &packet.addr))
		{
			using namespace BandwidthPriority;
			Log::log(LogLevel::Error, "Failed to reinject packet");
			LogError(GetLastError());
			return false;
		}
	}
	else
	{
		using namespace BandwidthPriority;
		Log::log(LogLevel::Warning, "Handle layer is not a layer you can send packets.");
		return false;
	}
	
	return true;
}

WINDIVERT_LAYER Divert::GetLayer() const
{
	return layer;
}

std::string Divert::GetIPAddress(UINT32 address)
{
	char buffer[128];
	WinDivertHelperFormatIPv4Address(address, buffer, sizeof(buffer));
	return std::move(std::string(buffer));
}

std::string Divert::GetIPAddress(const UINT32* address)
{
	char buffer[128];
	WinDivertHelperFormatIPv6Address(address, buffer, sizeof(buffer));
	return std::move(std::string(buffer));
}

void Divert::LogError(const DWORD& errorCode) const
{
	switch (errorCode)
	{
		using namespace BandwidthPriority;
		//WinDivertOpen
	case ERROR_FILE_NOT_FOUND:
		Log::log(LogLevel::Fatal, "The driver files WinDivert32.sys or WinDivert64.sys were not found.");
		break;
	case ERROR_ACCESS_DENIED:
		Log::log(LogLevel::Fatal, "You need Administrator privileges to run this application.");
		break;
	case ERROR_INVALID_PARAMETER:
		Log::log(LogLevel::Error, "Failed to start filtering: invalid filter syntax.");
		break;
	case ERROR_INVALID_IMAGE_HASH:
		Log::log(LogLevel::Fatal, "The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature.");
		break;
	case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:
		Log::log(LogLevel::Fatal, "An incompatible version of the WinDivert driver is currently loaded.");
		break;
	case ERROR_SERVICE_DOES_NOT_EXIST:
		Log::log(LogLevel::Error, "The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the WinDivert driver is not already installed.");
		break;
	case ERROR_DRIVER_BLOCKED:
		Log::log(LogLevel::Fatal, "Failed to open the WinDivert device because the driver was blocked.");
		break;
	case EPT_S_NOT_REGISTERED:
		Log::log(LogLevel::Error, "The Base Filtering Engine service has been disabled.");
		break;
		// WinDivertRecv
	case ERROR_INSUFFICIENT_BUFFER:
		Log::log(LogLevel::Error, "The captured packet is larger than the packet buffer.");
		break;
	case ERROR_NO_DATA:
		Log::log(LogLevel::Error, "The handle has been shutdown using WinDivertShutdown() and the packet queue is empty.");
		break;
		// WinDivertSend
	case ERROR_HOST_UNREACHABLE:
		Log::log(LogLevel::Warning, "An impostor packet is injected and the ip.TTL or ipv6.HopLimit field is 0.");
		Log::log(LogLevel::Warning, "Refused to send to not get stuck in a infinite loop caused by impostor packets.");
		break;
	default:
		Log::log(LogLevel::Error, "An unknown error occured.");
		std::cerr << "An unknown error occured (code:" << errorCode << ").\n" << std::endl;
		break;
	}
}

Header::Header(const netData& packet)
{
	//BOOL WinDivertHelperParsePacket(
	//	__in PVOID pPacket,
	//	__in UINT packetLen,
	//	__out_opt PWINDIVERT_IPHDR * ppIpHdr,
	//	__out_opt PWINDIVERT_IPV6HDR * ppIpv6Hdr,
	//	__out_opt UINT8 * pProtocol,
	//	__out_opt PWINDIVERT_ICMPHDR * ppIcmpHdr,
	//	__out_opt PWINDIVERT_ICMPV6HDR * ppIcmpv6Hdr,
	//	__out_opt PWINDIVERT_TCPHDR * ppTcpHdr,
	//	__out_opt PWINDIVERT_UDPHDR * ppUdpHdr,
	//	__out_opt PVOID * ppData,
	//	__out_opt UINT * pDataLen,
	//	__out_opt PVOID * ppNext,
	//	__out_opt UINT * pNextLen
	//);
	WinDivertHelperParsePacket(packet.packet, packet.packetLen, &ip_header, &ipv6_header, &protocol,
		&icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);
}

std::string Header::GetSource()
{
	if (ip_header)
	{
		return Divert::GetIPAddress(WinDivertHelperNtohl(ip_header->SrcAddr));
	}
	if (ipv6_header)
	{
		UINT32 srcAddr[4];
		WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, srcAddr);
		return Divert::GetIPAddress(srcAddr);
	}
	return std::string();
}

std::string Header::GetDestination()
{
	if (ip_header)
	{
		return Divert::GetIPAddress(WinDivertHelperNtohl(ip_header->DstAddr));
	}
	if (ipv6_header)
	{
		UINT32 dstAddr[4];
		WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dstAddr);
		return Divert::GetIPAddress(dstAddr);
	}
	return std::string();
}

UINT16 Header::GetSourcePort()
{
	if (tcp_header)
	{
		return ntohs(tcp_header->SrcPort);
	}
	if (udp_header)
	{
		return ntohs(udp_header->SrcPort);
	}
	return 0;
}

UINT16 Header::GetDestinationPort()
{
	if (tcp_header)
	{
		return ntohs(tcp_header->DstPort);
	}
	if (udp_header)
	{
		return ntohs(udp_header->DstPort);
	}
	return 0;
}

UINT8 Header::GetVersion()
{
	if (ip_header)
	{
		return ip_header->Version;
	}
	if (ipv6_header)
	{
		return ipv6_header->Version;
	}
	return 0;
}

UINT16 Header::GetLength()
{
	if (ip_header)
	{
		return ip_header->Length;
	}
	if (ipv6_header)
	{
		return ipv6_header->Length;
	}
	return 0;
}