// MaxDBServer.cpp : Defines the entry point for the console application.
//

#include "pch.h"
#include "MaxDBServer.h"
#include "SDDL.h"

bool g_bRegistration = false;
CMaxDBCache g_objDBCache;
HANDLE g_hServerRunningEvent = 0;
CMaxProcessReg g_objMaxProcRegister(ALL_REG);
CMaxCommunicator g_objWDMaxCommunicator(_NAMED_PIPE_WATCHDOG_PROCESSES, false);
CMaxCommunicatorServer g_objCommServer(_NAMED_PIPE_DBCLIENT_TO_DBSERVER, CMaxDBCache::OnDataReceivedCallBack, sizeof(MAX_PIPE_DATA_REG));

bool RegisterWithWD()
{
	g_bRegistration = false;
	for(int iCtr = 0; iCtr < 10; iCtr++)
	{
		if(g_objMaxProcRegister.WDRegisterProcess(eMaxDBServer, WD_StartingApp, &g_objWDMaxCommunicator))
		{
			g_bRegistration = true;
			break;
		}
		Sleep(500);
	}
	return g_bRegistration;
}

int Server()
{
	g_hServerRunningEvent = CreateEvent(0, FALSE, FALSE, 0);
	if(!g_hServerRunningEvent)
	{
		AddLogEntry(L"Creating event object failed, so exiting DBServer");
		return -1;
	}

	//start the server
	if(!g_objCommServer.Run())
	{
		AddLogEntry(L"start server failed, so exiting DBServer");
		CloseHandle(g_hServerRunningEvent);
		g_hServerRunningEvent = NULL;
		return -1;
	}

	//wait for any of the clients to signal the server to stop
	WaitForSingleObject(g_hServerRunningEvent, INFINITE);

	//stop the server
	g_objCommServer.StopServer();

	//clean up
	CloseHandle(g_hServerRunningEvent);
	g_hServerRunningEvent = NULL;
	return 0;
}

bool IsThisFirstInstance()
{
	LPCTSTR szGUID = _T("Global\\{ED28C8DD-BD95-4d66-BA3C-D56C8886BFBA}");
	HANDLE hMutex = NULL;
	SECURITY_ATTRIBUTES stSA = {0};
	LPCTSTR szDACL = _T("D:(A;OICI;GA;;;BG)(A;OICI;GA;;;AN)(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)");

	stSA.bInheritHandle = FALSE;
	stSA.nLength = sizeof(SECURITY_ATTRIBUTES);
	if(0 == ConvertStringSecurityDescriptorToSecurityDescriptor(szDACL, SDDL_REVISION_1,&stSA.lpSecurityDescriptor, NULL))
	{
		if(stSA.lpSecurityDescriptor)
		{
			LocalFree(stSA.lpSecurityDescriptor);	
		}

		AddLogEntry(L"ERROR StringToSID failed in AuDBServer");
		return true;
	}

	hMutex = ::CreateMutex(&stSA, TRUE, szGUID);

	if(stSA.lpSecurityDescriptor)
	{
		LocalFree(stSA.lpSecurityDescriptor);
	}

	if(!hMutex)
	{
		AddLogEntry(L"Mutex creation failed in AuDBServer");
		return true;
	}

	if(GetLastError() == ERROR_ALREADY_EXISTS)
	{
		AddLogEntry(L"Not first instance of AuDBServer, quitting server", 0, 0, true, LOG_DEBUG);
		CloseHandle(hMutex);
		return false;
	}

	AddLogEntry(L"First instance of AuDBServer, running server", 0, 0, true, LOG_DEBUG);
	return true;
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	if(!IsThisFirstInstance())
	{
		return 0;
	}

	CMaxProtectionMgr objMaxProtectionMgr;
	objMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXDSRV);

	g_objDBCache.InitialSettings();

	if(RegisterWithWD())
	{
		g_bRegistration = true;
	}

	int nRetCode = 0;
	if (!AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0))
	{
		nRetCode = -1;
		AddLogEntry(_T("Fatal Error: MFC initialization failed, hence not running DBServer"));
	}
	else
	{
		nRetCode = Server();
	}

	if(g_bRegistration)
	{
		g_objMaxProcRegister.WDRegisterProcess(eMaxDBServer, WD_StoppingApp, &g_objWDMaxCommunicator);
	}

	return nRetCode;
}
