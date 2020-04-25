/*
  Unity Capture
  Copyright (c) 2018 Bernhard Schelling

  Based on UnityCam
  https://github.com/mrayy/UnityCam
  Copyright (c) 2016 MHD Yamen Saraiji
*/

#define _HAS_EXCEPTIONS 0
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <initguid.h>
#include <stdint.h>
#include <stdlib.h>
#include <AclAPI.h>

#define MAX_SHARED_IMAGE_SIZE (1920 * 1080 * 4 * sizeof(short)) //4K (RGBA max 16bit per pixel)

#if _DEBUG
#define UCASSERT(cond) ((cond) ? ((void)0) : *(volatile int*)0 = 0xbad|(OutputDebugStringA("[FAILED ASSERT] " #cond "\n"),1))
#else
#define UCASSERT(cond) ((void)0)
#endif

struct SharedImageMemory
{
	SharedImageMemory(int32_t CapNum)
	{
		memset(this, 0, sizeof(*this));
		m_CapNum = CapNum;
	}

	~SharedImageMemory()
	{
		if (m_hMutex) CloseHandle(m_hMutex);
		if (m_hWantFrameEvent) CloseHandle(m_hWantFrameEvent);
		if (m_hSentFrameEvent) CloseHandle(m_hSentFrameEvent);
		if (m_hSharedFile) CloseHandle(m_hSharedFile);
		if (m_pSharedBuf) UnmapViewOfFile(m_pSharedBuf);
	}

	int32_t GetCapNum() { return m_CapNum; }
	enum { MAX_CAPNUM = ('z' - '0') }; //see Open() for why this number
	enum { RECEIVE_MAX_WAIT = 200 }; //How many milliseconds to wait for new frame
	enum EFormat { FORMAT_UINT8, FORMAT_FP16_GAMMA, FORMAT_FP16_LINEAR };
	enum EResizeMode { RESIZEMODE_DISABLED = 0, RESIZEMODE_LINEAR = 1 };
	enum EMirrorMode { MIRRORMODE_DISABLED = 0, MIRRORMODE_HORIZONTALLY = 1 };
	enum EReceiveResult { RECEIVERES_CAPTUREINACTIVE, RECEIVERES_NEWFRAME, RECEIVERES_OLDFRAME };
	enum ESendResult { SENDRES_TOOLARGE, SENDRES_WARN_FRAMESKIP, SENDRES_OK };

	typedef void (*ReceiveCallbackFunc)(int width, int height, int stride, EFormat format, EResizeMode resizemode, EMirrorMode mirrormode, int timeout, uint8_t* buffer, void* callback_data);

	EReceiveResult Receive(ReceiveCallbackFunc callback, void* callback_data)
	{
		if (!Open(true) || !m_pSharedBuf->width)
		{
			return RECEIVERES_CAPTUREINACTIVE;
		}

		SetEvent(m_hWantFrameEvent);
		bool IsNewFrame = (WaitForSingleObject(m_hSentFrameEvent, RECEIVE_MAX_WAIT) == WAIT_OBJECT_0);

		WaitForSingleObject(m_hMutex, INFINITE); //lock mutex
		callback(m_pSharedBuf->width, m_pSharedBuf->height, m_pSharedBuf->stride, (EFormat)m_pSharedBuf->format, (EResizeMode)m_pSharedBuf->resizemode, (EMirrorMode)m_pSharedBuf->mirrormode, m_pSharedBuf->timeout, m_pSharedBuf->data, callback_data);
		ReleaseMutex(m_hMutex); //unlock mutex

		return (IsNewFrame ? RECEIVERES_NEWFRAME : RECEIVERES_OLDFRAME);
	}

	bool SendIsReady()
	{
		return Open(false);
	}

	ESendResult Send(int width, int height, int stride, DWORD DataSize, EFormat format, EResizeMode resizemode, EMirrorMode mirrormode, int timeout, const uint8_t* buffer)
	{
		UCASSERT(buffer);
		UCASSERT(m_pSharedBuf);
		if (DataSize > MAX_SHARED_IMAGE_SIZE)
		{
			return SENDRES_TOOLARGE;
		}

		WaitForSingleObject(m_hMutex, INFINITE); //lock mutex
		m_pSharedBuf->width = width;
		m_pSharedBuf->height = height;
		m_pSharedBuf->stride = stride;
		m_pSharedBuf->format = format;
		m_pSharedBuf->resizemode = resizemode;
		m_pSharedBuf->mirrormode = mirrormode;
		m_pSharedBuf->timeout = timeout;
		memcpy(m_pSharedBuf->data, buffer, DataSize);
		ReleaseMutex(m_hMutex); //unlock mutex

		SetEvent(m_hSentFrameEvent);
		bool DidSkipFrame = (WaitForSingleObject(m_hWantFrameEvent, 0) != WAIT_OBJECT_0);

		return (DidSkipFrame ? SENDRES_WARN_FRAMESKIP : SENDRES_OK);
	}

private:
	//Allow UWP apps access to named objects:
	//https://docs.microsoft.com/en-us/windows/win32/api/securityappcontainer/nf-securityappcontainer-getappcontainernamedobjectpath#examples

	BOOL GetLogonSid(PSID* ppsid)
	{
		HANDLE hToken = NULL;
		BOOL bSuccess = FALSE;
		DWORD dwLength = 0;
		PTOKEN_GROUPS ptg = NULL;

		// Verify the parameter passed in is not NULL.
		if (NULL == ppsid)
		{
			goto Cleanup;
		}

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			goto Cleanup;
		}

		// Get required buffer size and allocate the TOKEN_GROUPS buffer.

		if (!GetTokenInformation(
			hToken,         // handle to the access token
			TokenLogonSid,    // get information about the token's groups 
			(LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
			0,              // size of buffer
			&dwLength       // receives required buffer size
		))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				goto Cleanup;

			ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY, dwLength);

			if (ptg == NULL)
				goto Cleanup;
		}

		// Get the token group information from the access token.

		if (!GetTokenInformation(
			hToken,         // handle to the access token
			TokenLogonSid,    // get information about the token's groups 
			(LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
			dwLength,       // size of buffer
			&dwLength       // receives required buffer size
		) || ptg->GroupCount != 1)
		{
			goto Cleanup;
		}

		// Found the logon SID; make a copy of it.

		dwLength = GetLengthSid(ptg->Groups[0].Sid);
		*ppsid = (PSID)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);
		if (*ppsid == NULL)
			goto Cleanup;
		if (!CopySid(dwLength, *ppsid, ptg->Groups[0].Sid))
		{
			HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
			goto Cleanup;
		}

		bSuccess = TRUE;

	Cleanup:

		// Free the buffer for the token groups.

		if (hToken)
			CloseHandle(hToken);

		if (ptg != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

		return bSuccess;
	}

	BOOL CreateObjectSecurityDescriptor(PSECURITY_DESCRIPTOR* ppSD, DWORD permissions)
	{
		PSID pLogonSid = NULL;
		BOOL bSuccess = FALSE;
		DWORD dwRes;
		PSID pAllAppsSID = NULL;
		PACL pACL = NULL;
		PSECURITY_DESCRIPTOR pSD = NULL;
		EXPLICIT_ACCESS ea[2];
		SID_IDENTIFIER_AUTHORITY ApplicationAuthority = SECURITY_APP_PACKAGE_AUTHORITY;

		if (!GetLogonSid(&pLogonSid))
		{
			goto Cleanup;
		}

		// Create a well-known SID for the all appcontainers group.
		if (!AllocateAndInitializeSid(&ApplicationAuthority,
			SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT,
			SECURITY_APP_PACKAGE_BASE_RID,
			SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE,
			0, 0, 0, 0, 0, 0,
			&pAllAppsSID))
		{
			goto Cleanup;
		}

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow LogonSid generic all access
		ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = permissions;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
		ea[0].Trustee.ptstrName = (LPTSTR)pLogonSid;

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow the all appcontainers execute permission
		ea[1].grfAccessPermissions = permissions;
		ea[1].grfAccessMode = SET_ACCESS;
		ea[1].grfInheritance = NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[1].Trustee.ptstrName = (LPTSTR)pAllAppsSID;

		// Create a new ACL that contains the new ACEs.
		dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
		if (ERROR_SUCCESS != dwRes)
		{
			goto Cleanup;
		}

		// Initialize a security descriptor.  
		pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
			SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (NULL == pSD)
		{
			goto Cleanup;
		}

		if (!InitializeSecurityDescriptor(pSD,
			SECURITY_DESCRIPTOR_REVISION))
		{
			goto Cleanup;
		}

		// Add the ACL to the security descriptor. 
		if (!SetSecurityDescriptorDacl(pSD,
			TRUE,     // bDaclPresent flag   
			pACL,
			FALSE))   // not a default DACL 
		{
			goto Cleanup;
		}

		*ppSD = pSD;
		pSD = NULL;
		bSuccess = TRUE;

	Cleanup:
		if (pLogonSid)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pLogonSid);
		if (pAllAppsSID)
			FreeSid(pAllAppsSID);
		if (pACL)
			LocalFree(pACL);
		if (pSD)
			LocalFree(pSD);

		return bSuccess;
	}

	bool Open(bool ForReceiving)
	{
		if (m_pSharedBuf)
		{
			return true; //already open
		}

		UCASSERT(m_CapNum <= MAX_CAPNUM);
		if (m_CapNum > MAX_CAPNUM)
		{
			m_CapNum = MAX_CAPNUM;
		}

		char CSCapNumChar = (m_CapNum ? '0' + m_CapNum : '\0'); //use NULL terminator for CapNum 0 to be compatible with old filter DLLs before multi cap
		char CS_NAME_MUTEX[] = "UnityCapture_Mutx0";
		CS_NAME_MUTEX[sizeof(CS_NAME_MUTEX) - 2] = CSCapNumChar;
		char CS_NAME_EVENT_WANT[] = "UnityCapture_Want0";
		CS_NAME_EVENT_WANT[sizeof(CS_NAME_EVENT_WANT) - 2] = CSCapNumChar;
		char CS_NAME_EVENT_SENT[] = "UnityCapture_Sent0";
		CS_NAME_EVENT_SENT[sizeof(CS_NAME_EVENT_SENT) - 2] = CSCapNumChar;
		char CS_NAME_SHARED_DATA[] = "UnityCapture_Data0";
		CS_NAME_SHARED_DATA[sizeof(CS_NAME_SHARED_DATA) - 2] = CSCapNumChar;

		size_t converted;
		wchar_t CS_NAME_SHARED_DATA_W[19];
		mbstowcs_s(&converted, CS_NAME_SHARED_DATA_W, CS_NAME_SHARED_DATA, 19);

		if (!m_hMutex)
		{
			if (ForReceiving)
			{
				PSECURITY_DESCRIPTOR pSd = NULL;
				if (CreateObjectSecurityDescriptor(&pSd, STANDARD_RIGHTS_ALL | MUTEX_ALL_ACCESS))
				{
					SECURITY_ATTRIBUTES SecurityAttributes;
					SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
					SecurityAttributes.bInheritHandle = TRUE;
					SecurityAttributes.lpSecurityDescriptor = pSd;

					m_hMutex = CreateMutexA(&SecurityAttributes, FALSE, CS_NAME_MUTEX);

					LocalFree(pSd);
				}
				else
				{
					m_hMutex = CreateMutexA(NULL, FALSE, CS_NAME_MUTEX);
				}
			}
			else
			{
				m_hMutex = OpenMutexA(SYNCHRONIZE, FALSE, CS_NAME_MUTEX);
			}
			if (!m_hMutex) { return false; }
		}

		WaitForSingleObject(m_hMutex, INFINITE); //lock mutex

		struct UnlockAtReturn
		{
			~UnlockAtReturn()
			{
				ReleaseMutex(m);
			}
			HANDLE m;
		} cs = { m_hMutex };

		if (!m_hWantFrameEvent)
		{
			if (ForReceiving)
			{
				PSECURITY_DESCRIPTOR pSd = NULL;
				if (CreateObjectSecurityDescriptor(&pSd, STANDARD_RIGHTS_ALL | EVENT_ALL_ACCESS))
				{
					SECURITY_ATTRIBUTES SecurityAttributes;
					SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
					SecurityAttributes.bInheritHandle = TRUE;
					SecurityAttributes.lpSecurityDescriptor = pSd;

					m_hWantFrameEvent = CreateEventA(&SecurityAttributes, FALSE, FALSE, CS_NAME_EVENT_WANT);

					LocalFree(pSd);
				}
				else
				{
					m_hWantFrameEvent = CreateEventA(NULL, FALSE, FALSE, CS_NAME_EVENT_WANT);
				}
			}
			else
			{
				m_hWantFrameEvent = OpenEventA(SYNCHRONIZE, FALSE, CS_NAME_EVENT_WANT);
			}
			if (!m_hWantFrameEvent) { return false; }
		}

		if (!m_hSentFrameEvent)
		{
			if (ForReceiving)
			{
				PSECURITY_DESCRIPTOR pSd = NULL;
				if (CreateObjectSecurityDescriptor(&pSd, STANDARD_RIGHTS_ALL | EVENT_ALL_ACCESS))
				{
					SECURITY_ATTRIBUTES SecurityAttributes;
					SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
					SecurityAttributes.bInheritHandle = TRUE;
					SecurityAttributes.lpSecurityDescriptor = pSd;

					m_hSentFrameEvent = CreateEventA(&SecurityAttributes, FALSE, FALSE, CS_NAME_EVENT_SENT);

					LocalFree(pSd);
				}
				else
				{
					m_hSentFrameEvent = CreateEventA(NULL, FALSE, FALSE, CS_NAME_EVENT_SENT);
				}
			}
			else
			{
				m_hSentFrameEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, CS_NAME_EVENT_SENT);
			}
			if (!m_hSentFrameEvent) { return false; }
		}

		if (!m_hSharedFile)
		{
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#define CreateMap CreateFileMappingW
#define OpenMap OpenFileMappingW
#else
#define CreateMap CreateFileMappingFromApp
#define OpenMap OpenFileMappingFromApp
#endif
			if (ForReceiving)
			{
				PSECURITY_DESCRIPTOR pSd = NULL;
				if (CreateObjectSecurityDescriptor(&pSd, STANDARD_RIGHTS_ALL | FILE_MAP_ALL_ACCESS))
				{
					SECURITY_ATTRIBUTES SecurityAttributes;
					SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
					SecurityAttributes.bInheritHandle = TRUE;
					SecurityAttributes.lpSecurityDescriptor = pSd;

					m_hSharedFile = CreateMap(
						INVALID_HANDLE_VALUE,
						&SecurityAttributes,
						PAGE_READWRITE,
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
						NULL,
#endif
						sizeof(SharedMemHeader) + MAX_SHARED_IMAGE_SIZE,
						CS_NAME_SHARED_DATA_W);

					LocalFree(pSd);
				}
				else
				{
					m_hSharedFile = CreateMap(
						INVALID_HANDLE_VALUE,
						NULL,
						PAGE_READWRITE,
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
						NULL,
#endif
						sizeof(SharedMemHeader) + MAX_SHARED_IMAGE_SIZE,
						CS_NAME_SHARED_DATA_W);
				}
			}
			else
			{
				m_hSharedFile = OpenMap(FILE_MAP_WRITE, FALSE, CS_NAME_SHARED_DATA_W);
			}
			if (!m_hSharedFile) { return false; }

#undef CreateMap
#undef OpenMap
		}

		m_pSharedBuf = (SharedMemHeader*)MapViewOfFile(m_hSharedFile, FILE_MAP_WRITE, 0, 0, 0);
		if (!m_pSharedBuf) { return false; }

		return true;
	}

	struct SharedMemHeader
	{
		int width;
		int height;
		int stride;
		int format;
		int resizemode;
		int mirrormode;
		int timeout;
		uint8_t data[1];
	};

	int32_t m_CapNum;
	HANDLE m_hMutex;
	HANDLE m_hWantFrameEvent;
	HANDLE m_hSentFrameEvent;
	HANDLE m_hSharedFile;
	SharedMemHeader* m_pSharedBuf;
};
