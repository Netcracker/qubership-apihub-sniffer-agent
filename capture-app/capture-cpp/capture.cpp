// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include "appConfig.h"
#if defined(_MSC_VER) || defined(__BORLANDC__)
#include <cerrno>
#else   // defined(_MSC_VER) || defined(__BORLANDC__)
#include <ctime>
#include <unistd.h>
#ifndef errno_t
#define errno_t int
#endif // errno_t
#define CLOCKID CLOCK_REALTIME
#define SIG SIGRTMIN
/**
 * an implementation of "secured" freopen() for cross-compilation
 * @param _Stream receives new FILE* value
 * @param _FileName name of the file receiving output
 * @param _Mode open mode w|a
 * @param _OldStream currently opened stream
 * @return 
 */
errno_t freopen_s(FILE** Stream, char const* FileName, char const* Mode, FILE* OldStream)
{
    *Stream = freopen(FileName, Mode, OldStream);
    if (*Stream == nullptr) {
        return errno;
    }
    return 0;
}
#endif // defined(_MSC_VER) || defined(__BORLANDC__)

/**
 * re-opens streams on SIGHUP
 */
void reopenStreams()
{
    std::string sLogName("nohup.out.");
    //FILE* fo;
    FILE* fe;
    //freopen_s(&fo, sLogName.c_str(), "w", stdout);
    freopen_s(&fe, sLogName.c_str(), "w", stderr);
}
pcap_t* handle = nullptr;
static long packet_count = -1;
static bool binFile = false;
static long capturedCount = 0;
static long byteCount = 0;
extern "C"  {
    typedef struct phdr {
        uint32_t s;
        uint32_t u;
        uint32_t c;
        uint32_t o;
    }PHDR;
    void print_dump(const unsigned char* buf, int data_len)
    {
        int i;
        if(data_len>8)  {
            data_len = 16;
        }
        for(i=0; i<data_len; i++)   {
            printf(" %02X", buf[i]);
        }
    }

    void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
    {
        static int expected = sizeof(PHDR);
        if(binFile) {
            PHDR ph;
            ph.s = pkthdr->ts.tv_sec;
            ph.u = pkthdr->ts.tv_usec;
            ph.c = ph.s = pkthdr->caplen;
            ph.o = ph.s = pkthdr->len;
            if(write(1, &ph, expected)!=expected)    {
                perror("unable to write packet header");
                if(handle!=NULL) {
                    pcap_breakloop(handle);
                }
                return;
            }
            byteCount += expected;
            if(write(1, packet, pkthdr->caplen)!=pkthdr->caplen)    {
                perror("unable to write packet data");
                if(handle!=NULL) {
                    pcap_breakloop(handle);
                }
                return;
            }
            byteCount += pkthdr->caplen;
        }
        else {
            printf("%10ld.%010ld, %9u, %9u", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);
            print_dump(packet, pkthdr->caplen);
            puts("");
        }
        // at the end of
        capturedCount ++;
        if(packet_count>0l && capturedCount>=packet_count)  {
            if(handle!=NULL) {
                pcap_breakloop(handle);
            }
        }
    }
    /**
     * signal handling function
     * @param sigNo signal received (one of SIG*)
     */
    void sig_fun(int sigNo) {
        switch (sigNo) {
        case SIGHUP:
        case SIGPIPE:
            reopenStreams();
            break;
        case SIGABRT:
        case SIGALRM:
        case SIGSTOP:
        case SIGINT:
        case SIGKILL:
        case SIGTSTP:
        case SIGTERM:
        case SIGQUIT:
            fprintf(stderr, "Caught signal %d\n", sigNo);
            if(handle!=NULL) {
                pcap_breakloop(handle);
            }
            break;
        default:
            if(sigNo!=SIG)  {
                fprintf(stderr, "Caught unexpected signal %d\n", sigNo);
            }
            else {
                fprintf(stderr, "Caught timer %d\n", sigNo);
            }
            if(handle!=NULL) {
                pcap_breakloop(handle);
            }
            break;
        }
    }

}
template <std::size_t SIZE>
std::string bitMaskToString(unsigned bitMask, std::array<unsigned,SIZE> bits, const char* dispChars)
{
    std::string ret;
    for(size_t i=0; i<SIZE; i++)  {
        if((bitMask & bits[i]) == bits[i])  {
            ret += *dispChars;
        }
        dispChars ++;
    }
    return ret;
}
bool hasAnAddress(const struct pcap_addr* addr) {
    while (addr!=nullptr)
    {
        if(addr->addr!=nullptr && (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6)) {
            //print_dump((unsigned const char*)addr->addr, sizeof(struct sockaddr));
            return true;
        }
        addr = addr->next;
    }
    return false;
}
/**
 * @brief list interfaces
 * 
 * @param ifaceName required interface name or NULL
 * @param mask mask storage
 * @param net  net address storage
 * @param name acquired interface name
 * @param bPrint log into stdout
 * @return int EXIT_FAILURE | EXIT_SUCCESS
 */
int listInterfaces(const char* ifaceName, bpf_u_int32& mask,bpf_u_int32& net, std::string& name, bool bPrint = false)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devices = nullptr;

    if(pcap_findalldevs(&devices, errbuf) == PCAP_ERROR)   {
        std::cerr << "unable to get device name. Error: " <<  errbuf << std::endl;
        return EXIT_FAILURE;
    }
    else {
        auto pdev = devices;
        bool bFound = false;
        bool bName = (ifaceName!=NULL && strlen(ifaceName)>0);
        while (pdev != NULL)
        {
            constexpr auto FLAGS= (PCAP_IF_UP|PCAP_IF_RUNNING|PCAP_IF_CONNECTION_STATUS_CONNECTED);
            if((pdev->flags & PCAP_IF_LOOPBACK) != PCAP_IF_LOOPBACK && 
                (pdev->flags & FLAGS) == FLAGS &&
                hasAnAddress(pdev->addresses) &&
                (!bName || strcmp(ifaceName,pdev->name)==0))
            {
                bFound = true;
                name.assign(pdev->name);
                if(bPrint)  {
                    std::cout << " " << name;
                }
                if(bPrint)  {
                    std::array<unsigned,4> aiftypes {PCAP_IF_LOOPBACK, PCAP_IF_UP, PCAP_IF_RUNNING, PCAP_IF_WIRELESS};
                    std::cout << "    " << bitMaskToString<4>(pdev->flags & 0xf, aiftypes, "LURW");
                    std::array<unsigned,3> aifstatus {PCAP_IF_CONNECTION_STATUS_CONNECTED, PCAP_IF_CONNECTION_STATUS_DISCONNECTED, PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE};
                    std::cout << bitMaskToString<3>(pdev->flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE, aifstatus, "CD?") << "    ";
                }
                if(pdev->flags & PCAP_IF_LOOPBACK) 
                if(pdev->addresses->netmask!=nullptr)   {
                    sockaddr_in *p = (sockaddr_in*)(pdev->addresses->netmask);
                    mask = p->sin_addr.s_addr;
                }
                if(pdev->addresses->broadaddr!=nullptr)   {
                    sockaddr_in *p = (sockaddr_in*)(pdev->addresses->broadaddr);
                    net = p->sin_addr.s_addr;
                }
                if(bPrint)  {
                    std::cout << "    descr:'" << (pdev->description==NULL?appConfig::EMPTY_STR:pdev->description) << "'";
                    std::cout << std::endl;
                    std::cout.flush();
                }
                else    {
                    break;
                }
            }
            pdev = pdev->next;
            /* code */
        }
        pcap_freealldevs(devices);
        if(!bFound) {
            std::cerr << "no interface";
            if(ifaceName!=NULL)
                std::cerr << " with name '" << ifaceName << "'";
            else
            std::cerr << " can be used to capture packets" << std::endl;
        }
    }
    return EXIT_SUCCESS;
}

/**
 * @brief Set the signals handlers and timer
 * 
 * @param cfg program configuration
 */
void setSignals(appConfig& cfg)
{
    // set signals
    struct sigaction sa { {0} };
    struct sigaction so { {0} };
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = sig_fun;
    std::array<int, 8> sigList{ 
        SIGABRT, SIGINT, SIGHUP, SIGKILL, SIGTSTP, SIGTERM, SIGPIPE, SIGQUIT
    };
    for (int sig : sigList) {
        sigaction(sig, &sa, &so);
    }
    if(cfg.hasValueFor(appConfig::OPT_TIME))    {
        timer_t            timerid;
        sigset_t           mask;
        struct sigevent    sev;
        struct itimerspec  its;
        sigaction(SIG, &sa, &so);
        sigemptyset(&mask);
        sigaddset(&mask, SIG);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)    {
            perror("sigprocmask");
        }
        else {
            sev.sigev_notify = SIGEV_SIGNAL;
            sev.sigev_signo = SIG;
            sev.sigev_value.sival_ptr = &timerid;

            if (timer_create(CLOCKID, &sev, &timerid) == -1)    {
                perror("timer_create");
            }
            else {
                its.it_value.tv_sec = cfg.getOptNum(appConfig::OPT_TIME);
                its.it_value.tv_nsec = 1;
                its.it_interval.tv_sec = its.it_value.tv_sec;
                its.it_interval.tv_nsec = its.it_value.tv_nsec;
                if (timer_settime(timerid, 0, &its, NULL) == -1)    {
                    perror("timer_settime");
                }
                if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
                    perror("sigprocmask");
            }
        }
    }
}

int writeFileHeaders(appConfig& cfg)   {
    if(cfg.hasValueFor(appConfig::OPT_OUTFL))   {
        FILE* f;
        if(freopen_s(&f, cfg.getOpt(appConfig::OPT_OUTFL).c_str(), "w", stdout)!=0) {
            perror("unable to open output file");
        }
        else {
            binFile = true;
            pcap_file_header file_header;
            file_header.magic = 0xA1B23C4D;
            file_header.version_major = 2;
            file_header.version_minor = 4;
            file_header.thiszone = 0;
            file_header.sigfigs = 0;
            file_header.snaplen = cfg.getOptNum(appConfig::OPT_SIZE);
            file_header.linktype = 1;//LINKTYPE_ETHERNET;
            int expected = sizeof(pcap_file_header);
            if(write(1, &file_header, expected)!=expected)  {
                return EXIT_FAILURE;
            }
        }
    }
    return EXIT_SUCCESS;
}

/**
 * @brief program entry function
 * 
 * @param argc argument count
 * @param argv argument values
 * @return int EXIT_SUCCESS | EXIT_FAILURE
 */
int main(int argc, char* argv[])
{
    auto cfg = appConfig::getInstance();
    int nRet = cfg.parseCmdLine(argc,argv);
    if(nRet!=EXIT_FAILURE)  {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        // if(pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)==PCAP_ERROR)  {
        //     std::cerr << "unable to initialize library. Error:" << errbuf << std::endl;
        //     return EXIT_FAILURE;
        // }
        bpf_u_int32 mask = 0;
        bpf_u_int32 net = 0;
        const char* ifaceName = NULL;
        if(cfg.hasValueFor(appConfig::OPT_IFACE))   {
            ifaceName = cfg.getOpt(appConfig::OPT_IFACE).c_str();
            if(strlen(ifaceName)<1) {
                ifaceName = NULL;
            }
        }
        std::string i_name;
        bool bPrint = cfg.hasValueFor(appConfig::OPT_LIST);
	if(ifaceName!=NULL &&  cfg.getOpt(appConfig::OPT_IFACE).compare("any")!=0) {
        if(listInterfaces(
                ifaceName,
                mask,
                net,
                i_name, 
                bPrint) == EXIT_SUCCESS) {
            cfg.setOpt(appConfig::OPT_IFACE, i_name);
        }
	}
        if(bPrint)  {
            return EXIT_SUCCESS;
        }
	const char* pName = NULL;
	if(cfg.getOpt(appConfig::OPT_IFACE).compare("any")!=0)	{
		pName = cfg.getOpt(appConfig::OPT_IFACE).c_str();
	}
        handle = pcap_open_live(pName,int(cfg.getOptNum(appConfig::OPT_SIZE)),0,-1,errbuf);
        if(handle == NULL)   {
            std::cerr << "unable to open interface '" << cfg.getOpt(appConfig::OPT_IFACE) << "'. Error: " <<  errbuf << std::endl;
            return EXIT_FAILURE;
        }
        if(cfg.hasValueFor(appConfig::OPT_FILT))    {
            struct bpf_program fp;
            if (pcap_compile(handle, &fp, cfg.getOpt(appConfig::OPT_FILT).c_str(), 0, net) == PCAP_ERROR) {
                std::cerr << "unable to compile filter expression '" << cfg.getOpt(appConfig::OPT_IFACE) << "'. Error: " <<  pcap_geterr(handle) << std::endl;
            }
            else    {
                if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
                    std::cerr << "unable to use compiled filter. Error: " <<  pcap_geterr(handle) << std::endl;
                }
            }
        }
        if(cfg.hasValueFor(appConfig::OPT_COUNT))   {
            packet_count = cfg.getOptNum(appConfig::OPT_COUNT);
        }
        std::cerr << "Capturing " << packet_count << " packets on " << cfg.getOpt(appConfig::OPT_IFACE) << "..." << std::endl;
        // set signals
        setSignals(cfg);
        // set packet count limit
        writeFileHeaders(cfg);
        printf("    Seconds.Timestamp,  Captured,  Original\n");
        // capture loop
        pcap_loop(handle,int(cfg.getOptNum(appConfig::OPT_COUNT)),my_callback,NULL);
        fflush(stdout);
        auto ll = lseek64(1, 0, SEEK_END);
        close(1);
        std::cerr << "Capture at " << cfg.getOpt(appConfig::OPT_IFACE) << " finished." << std::endl;
        std::cerr << "Packets captured " << capturedCount << std::endl;
        std::cerr << "Bytes captured " << byteCount << "/" << ll << std::endl;
        if(handle!=nullptr) {
            pcap_close(handle);
            handle = nullptr;
        }
    }
    return nRet;
}
