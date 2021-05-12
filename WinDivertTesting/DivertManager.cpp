#include "DivertManager.h"
#include <string>
#include <iostream>
#include <vector>




DivertManager::DivertManager(std::string prioProcName, bool th_running) {

	this->prioProcName = prioProcName;
	this->th_running = th_running;

}

DivertManager::~DivertManager() {
	this->th_running = false;

    Sleep(2500);

}

void DivertManager::startThreads() {


    th_reqWorker = std::thread(&DivertManager::packetsRequester, this);
    this->th_reqWorker.detach();
    th_getterWorker = std::thread(&DivertManager::filterPacketIntoQueues, this);
    this->th_getterWorker.detach();
    th_senderWorker = std::thread(&DivertManager::sendPacketFromQueues, this);
    this->th_senderWorker.detach();
}

void DivertManager::resetData(netData& data) {
    data.ip_header = nullptr;
    data.ipv6_header = nullptr;
    data.udp_header = nullptr;
    data.tcp_header = nullptr;
    data.icmp_header = nullptr;
    data.icmpv6_header = nullptr;

    data.packet[MAXBUF] = NULL;
    data.packetLen = NULL;
    data.protocol = NULL;
    data.ProcessId = NULL;
    data.addr;
}


void DivertManager::filterPacketIntoQueues() {

    HANDLE RECVHND = WinDivertOpen("remotePort != 53", WINDIVERT_LAYER_NETWORK, 50, WINDIVERT_FLAG_RECV_ONLY);

    if (RECVHND == INVALID_HANDLE_VALUE)
    {
        std::cerr << ("error : WinDivertOpen()\n");
        return;
    }

    while (th_running) {

        netData packet;

        if (!WinDivertRecv(RECVHND, packet.packet, sizeof(packet.packet), &packet.packetLen, &packet.addr))
        {
            std::cerr << ("error : WinDivertRecv()\n");
            continue;
        }

        WinDivertHelperParsePacket(packet.packet, packet.packetLen, &packet.ip_header, &packet.ipv6_header,
            &packet.protocol, &packet.icmp_header, &packet.icmpv6_header,
            &packet.tcp_header, &packet.udp_header,
            NULL, NULL, NULL, NULL);

        

        //if (listOfPorts.size() != 0) {
        //    for (auto &port: listOfPorts)
        //    {
        //        if(port.first == ntohs(recvData.addr.Outbound))
        //    }
        //}

        UINT32 tempPort = -1;
        
        if(packet.tcp_header != NULL) {
            if (packet.addr.Outbound || packet.addr.Loopback)
                tempPort = ntohs(packet.tcp_header->SrcPort);
            else
                tempPort = ntohs(packet.tcp_header->DstPort);
        }
        else if (packet.udp_header != NULL) {
            if (packet.addr.Outbound || packet.addr.Loopback)
                tempPort = ntohs(packet.udp_header->SrcPort);
            else
                tempPort = ntohs(packet.udp_header->DstPort);
        }

        if(tempPort != -1 && listOfPorts[tempPort]){
            Mutex.lock();
            HighPrioPacketQueue.push(packet);
            Mutex.unlock();
        } else {
            Mutex.lock();
            normalPacketQueue.push(packet);
            Mutex.unlock();
        }
    }

}

void DivertManager::sendPacketFromQueues() {

    HANDLE SENDHND = WinDivertOpen("remotePort != 53", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);

    if (SENDHND == INVALID_HANDLE_VALUE)
    {
        std::cerr << ("error : WinDivertOpen()\n");
        return;
    }

    while (th_running) {
        while(!HighPrioPacketQueue.empty()){

            Mutex.lock();
            netData temp =HighPrioPacketQueue.front();
            HighPrioPacketQueue.pop();
            Mutex.unlock();

            //std::cout << "sending prio\r\n";
            if (!WinDivertSend(SENDHND, (temp).packet, (temp).packetLen, &(temp).packetLen, &(temp).addr))
            {
        	    printf("error : WinDviertSend()\n");
        	    continue;
            }

        }
        while(!normalPacketQueue.empty() && HighPrioPacketQueue.empty()) {

            //std::cout << "sending normal\r\n";
            Mutex.lock();
            netData temp =normalPacketQueue.front();
            normalPacketQueue.pop();
            Mutex.unlock();

            if (!WinDivertSend(SENDHND, (temp).packet, (temp).packetLen, &(temp).packetLen, &(temp).addr))
            {
                printf("error : WinDviertSend()\n");
                continue;
            }

        }
        

    }

}


void DivertManager::packetsRequester() {
    HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 100, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    
    if (handle == INVALID_HANDLE_VALUE)
    {
        std::cerr << ("error : WinDivertOpen()\n");
        return;
    }

    while (th_running) {
        counter++;

        if (!WinDivertRecv(handle, reqData.packet, sizeof(reqData.packet), &reqData.packetLen, &reqData.addr))
        {
            std::cerr << ("error : WinDivertRecv()\n");
            continue;
        }


        std::string temp = getProcessNameByPid(reqData.addr.Flow.ProcessId);
        //std::cout << temp << " " << temp.length() <<"\r\n";

        if (temp == prioProcName){ 
            
            listOfPorts[reqData.addr.Flow.LocalPort] = true;


        }
        if (counter > resetAt) {
            //std::cout << temp << "reseted " <<"\r\n";
            counter = 0;
            listOfPorts.clear();
        }
        //char RemoteAddr[128];
        //char LocalAddr[128];
        //WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(WinDivertHelperNtohl(*(reqData.addr.Flow.RemoteAddr))), RemoteAddr, sizeof(RemoteAddr));
        //WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(WinDivertHelperNtohl(*(reqData.addr.Flow.LocalAddr))), LocalAddr, sizeof(LocalAddr));

        //std::cout << "pid: " << getProcessNameByPid(reqData.addr.Flow.ProcessId) << ", srcPort: " << reqData.addr.Flow.LocalPort << " srcAddr:" << LocalAddr << ", dstPort: " << reqData.addr.Flow.RemotePort << " dstAddr:" << RemoteAddr << std::endl;

    }


    if (!WinDivertClose(handle))
        std::cerr << ("could not close handle");
    
}



std::string DivertManager::getProcessNameByPid(UINT32 pid) {

    std::string res = "";
    std::vector<char> tempVect;

    HANDLE Handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid /* This is the PID, you can find one from windows task manager */
    );
    if (Handle)
    {
        
        WCHAR Buffer[MAX_PATH];
        if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
        {
            std::size_t startF = std::string::npos;
            std::size_t exePos = std::string::npos;
            std::size_t diff = 0;

            // At this point, buffer contains the full path to the executable
            for (int i = 0; i < MAX_PATH; i++) {

                if ((char)Buffer[i] == '\\') {

                    startF = i;
                }

                if ( MAX_PATH >= i+3 && (char)Buffer[i] == '.' && (char)Buffer[i+1] == 'e' && (char)Buffer[i+2] == 'x' && (char)Buffer[i+3] == 'e'){

                    exePos = i;
                    break;
                }
            }

            if (startF != std::string::npos && exePos != std::string::npos) {
                diff = exePos - startF;

                //std::cout << "startF " << startF <<" exepos: " << exePos << " diff " << diff << "\r\n";

                for (int i = startF+1; i <= startF+diff+3; i++)
                {
                    //std::cout << (char)Buffer[i];
                    res.push_back((char)Buffer[i]);
                }

                //std::cout << "\r\n";

            }


        }
        else
        {
            // You better call GetLastError() here
        }
        CloseHandle(Handle);
    }
    return res;
}