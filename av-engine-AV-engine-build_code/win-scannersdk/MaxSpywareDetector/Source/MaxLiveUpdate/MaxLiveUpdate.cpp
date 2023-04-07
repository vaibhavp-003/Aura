// MaxLiveUpdate.cpp : Defines the initialization routines for the DLL.
//

#include "pch.h"
#include "MaxLiveUpdate.h"
#include "MaxExceptionFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// The one and only CMaxLiveUpdateApp object
CMaxLiveUpdateApp theApp;

extern "C" __declspec(dllexport) void MaxSecureDispatcher(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.ProcessMessage(lpDispatchMessage, lpVoid);
}

// CMaxLiveUpdateApp
BEGIN_MESSAGE_MAP(CMaxLiveUpdateApp, CWinApp)
END_MESSAGE_MAP()

// CMaxLiveUpdateApp construction
CMaxLiveUpdateApp::CMaxLiveUpdateApp()
{
}

// CMaxLiveUpdateApp initialization
BOOL CMaxLiveUpdateApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();
	LoadLoggingLevel();
	return TRUE;
}

int CMaxLiveUpdateApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}

void CMaxLiveUpdateApp::ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	//Max Merger Messages
	if(lpDispatchMessage->eDispatch_Type >= eLoadMerger && lpDispatchMessage->eDispatch_Type <= eUnLoadMerger)
	{
		m_oMaxMergerWrapper.ProcessMessage(lpDispatchMessage, lpVoid);
	}
	//Max Liveupdate Messages
	else if(lpDispatchMessage->eDispatch_Type == eStartLiveUpdate)
	{
		m_oMaxLiveUpdateWrapper.ProcessMessage(lpDispatchMessage, lpVoid);
	}
}