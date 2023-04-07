#include "pch.h"
#include "SrvOpt.h"
#include "SrvOptDlg.h"
#include "MaxExceptionFilter.h"
#include "MaxProtectionMgr.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CSrvOptApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

// CSrvOptApp construction
/*--------------------------------------------------------------------------------------
Function       : CSrvOptApp
In Parameters  : 
Out Parameters : 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
CSrvOptApp::CSrvOptApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

CSrvOptApp theApp;

/*--------------------------------------------------------------------------------------
Function       : InitInstance
In Parameters  : 
Out Parameters : BOOL 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
BOOL CSrvOptApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();

	if(IsAnotherInstancePresent())
	{
		return FALSE;
	}

	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MIGRATESD);

	CSrvOptDlg dlg;
	m_pMainWnd = &dlg;
	dlg.DoModal();
	return FALSE;
}

int CSrvOptApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}

bool CSrvOptApp::IsAnotherInstancePresent()
{
	LPCTSTR szInstanceGUID = _T("Global\\{C668DB3C-E262-4854-906C-B9ECF1665984}");

	if(NULL == CreateMutex(NULL, TRUE, szInstanceGUID))
	{
		return false;
	}

	if(GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return true;
	}

	return false;
}