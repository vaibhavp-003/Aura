// MaxSecure.cpp : Defines the initialization routines for the DLL.
//

#include "pch.h"
#include "MaxSecure.h"
#include "MaxExceptionFilter.h"
#include "UserTrackingSystem.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// The one and only CMaxSecureApp object
CMaxSecureApp theApp;

extern "C" __declspec(dllexport) void MaxSecureDispatcher(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.ProcessMessage(lpDispatchMessage, lpVoid);
}

extern "C" __declspec(dllexport) void MaxSecureCmdLog(LPVOID lpVoid)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.ProcessCmdLog(lpVoid);
}

// CMaxSecureApp
BEGIN_MESSAGE_MAP(CMaxSecureApp, CWinApp)
END_MESSAGE_MAP()

// CMaxSecureApp construction
CMaxSecureApp::CMaxSecureApp()
{
}

// CMaxSecureApp initialization
BOOL CMaxSecureApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();
	LoadLoggingLevel();
	m_oFileShredder.InitializeDll();

	// Static function to set product key only once!
	CUserTrackingSystem oUserTrackingSystem;
	oUserTrackingSystem.SetProductKey(CSystemInfo::m_csProductName);

	return TRUE;
}

int CMaxSecureApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}

void CMaxSecureApp::ProcessCmdLog(LPVOID lpVoid)
{
	m_oMaxSecureScanner.ProcessCmdLog(lpVoid);
}
void CMaxSecureApp::ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	if(lpDispatchMessage->eDispatch_Type >= eStartScanning && lpDispatchMessage->eDispatch_Type <= eSpyDTypeEnd)
	{
		m_oMaxSecureScanner.ProcessMessage(lpDispatchMessage, lpVoid);
	}
}

CRegistryCleaner* CMaxSecureApp::GetRegistryCleaner()
{
	return &m_oRegistryCleaner;
}