#ifndef FOXFS_FILESYSTEM_H
#define FOXFS_FILESYSTEM_H

#include <string>
#include <map>

#include "Archive.h"

#include <cryptopp/md5.h>

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
#pragma warning(disable : 4996)
#include <windows.h>      
#include <intrin.h>       
#include <iphlpapi.h>   
#else
#include <stdio.h>
#include <string.h>
#include <unistd.h>          
#include <errno.h>           
#include <sys/types.h>       
#include <sys/socket.h>      
#include <sys/ioctl.h>  
#include <sys/resource.h>    
#include <sys/utsname.h>       
#include <netdb.h>           
#include <netinet/in.h>      
#include <netinet/in_systm.h>                 
#include <netinet/ip.h>      
#include <netinet/ip_icmp.h> 
#include <linux/if.h>        
#include <linux/sockios.h>  
#include <pthread.h>
#include <arpa/inet.h>
#endif

namespace FoxFS
{

	class FileSystem
	{
	private:
		struct KeyInfo
		{
			unsigned char key[32];
			unsigned char iv[32];
		};

	public:
		FileSystem();
		~FileSystem();

		int setKeyServer(const char* host, unsigned int port);

		int load(const wchar_t* filename);
		int unload(const wchar_t* filename);

		unsigned int size(const char* filename) const;
		int exists(const char* filename) const;
		int get(const char* filename, void* buffer, unsigned int maxsize, unsigned int* outsize) const;

		static inline const unsigned char* getMachineName()
		{
			static unsigned char machine[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			if (machine[0] == 0 && machine[1] == 0 && machine[2] == 0 && machine[3] == 0 && machine[12] == 0 && machine[13] == 0 && machine[14] == 0 && machine[15] == 0)
			{
				char name[256] = { 0 };
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
				DWORD len = 256;
				GetComputerNameA(name, &len);
#else
				struct utsname u;
				if (uname(&u) < 0)
				{
					return machine;
				}
				strcpy(name, u.nodename);
				unsigned int len = strlen(name);
#endif
				CryptoPP::MD5 md5;
				md5.CalculateDigest(machine, reinterpret_cast<unsigned char*>(name), len);
			}
			return machine;
		}
		static inline const unsigned char* getMacAddress()
		{
			static unsigned char mac[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[12] == 0 && mac[13] == 0 && mac[14] == 0 && mac[15] == 0)
			{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
				IP_ADAPTER_INFO adapters[32];
				DWORD dwlen = sizeof(adapters);
				DWORD dwstatus = GetAdaptersInfo(adapters, &dwlen);

				if (dwstatus != ERROR_SUCCESS)
				{
					return mac;
				}

				CryptoPP::MD5 md5;
				md5.CalculateDigest(mac, reinterpret_cast<unsigned char*>(adapters[0].Address), adapters[0].AddressLength);
#else
				int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
				if (sock < 0)
				{
					return mac;
				}

				struct ifconf conf;
				char ifconfbuf[128 * sizeof(struct ifreq)] = { 0 };
				conf.ifc_buf = ifconfbuf;
				conf.ifc_len = sizeof(ifconfbuf);
				if (ioctl(sock, SIOCGIFCONF, &conf))
				{
					close(sock);
					return mac;
				}

				for (struct ifreq* ifr = conf.ifc_req; reinterpret_cast<char*>(ifr) < reinterpret_cast<char*>(conf.ifc_req + conf.ifc_len); ++ifr)
				{
					if (ifr->ifr_addr.sa_data == (ifr + 1)->ifr_addr.sa_data)
					{
						continue;
					}

					if (ioctl(sock, SIOCGIFFLAGS, ifr))
					{
						continue;
					}
					if (ioctl(sock, SIOCGIFHWADDR, ifr) == 0)
					{
						CryptoPP::MD5 md5;
						md5.CalculateDigest(mac, reinterpret_cast<unsigned char*>(&(ifr->ifr_addr.sa_data)), 6);
						break;
					}
				}
#endif
			}
			return mac;
		}
		static inline bool genHardwareId(unsigned char* buffer, unsigned int* len)
		{
			const unsigned char* machine = getMachineName();
			const unsigned char* mac = getMacAddress();

			unsigned int l = 0;
			if (machine)
			{
				buffer[l++] = 'N';
				memcpy(&buffer[l], machine, 16);
				l += 16;
			}
			if (mac)
			{
				buffer[l++] = 'M';
				memcpy(&buffer[l], mac, 16);
				l += 16;
			}
			*len = l;
			return l != 0;
		}

	private:
		std::map<std::basic_string<wchar_t>, Archive*> archives;

		char hostname[260];
		unsigned int port;
		std::map<std::string, KeyInfo> keys;

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		mutable CRITICAL_SECTION mutex;
#else
		mutable pthread_mutex_t mutex;
#endif
	};

}

#endif