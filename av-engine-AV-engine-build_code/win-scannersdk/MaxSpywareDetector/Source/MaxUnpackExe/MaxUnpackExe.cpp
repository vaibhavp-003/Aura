
// MaxUnpackExe.cpp : Defines the class behaviors for the application.
//

#include "pch.h"
#include "MaxUnpackExe.h"
#include "MaxUnpackExeDlg.h"
#include "MaxProtectionMgr.h"
#include "MaxPipes.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

enum
{
	NOT_PACKED = 0,
	UNPACK_SUCCESS,
	UNPACK_FAILED,
	UNPACK_EXPECTION
};
// CMaxUnpackExeApp

BEGIN_MESSAGE_MAP(CMaxUnpackExeApp, CWinAppEx)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CMaxUnpackExeApp construction

CMaxUnpackExeApp::CMaxUnpackExeApp():m_objMaxCommunicatorServer(_NAMED_PIPE_SCANNER_TO_UNPACKER,
												CMaxUnpackExeApp::OnDataReceivedCallBack,
												sizeof(SHARED_UNPACKER_SWITCH_DATA))
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CMaxUnpackExeApp object

CMaxUnpackExeApp theApp;
HANDLE	CMaxUnpackExeApp::m_hUnpckSignal = NULL;


// CMaxUnpackExeApp initialization

bool CMaxUnpackExeApp::SingleInstance()
{

	CString csGUID = _T("Global\\{F71D449D-E461-43aa-B51A-4825EEA94A2F}}");

	HANDLE hMutex = NULL;
	hMutex = ::CreateMutex(NULL, TRUE, csGUID);
	if(!hMutex)
	{
		return false;
	}

	if(GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(hMutex);
		return false;
	}
	return true;
}

BOOL CMaxUnpackExeApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinAppEx::InitInstance();

	AfxEnableControlContainer();

	CMaxProtectionMgr	objProtectionMgr;

	objProtectionMgr.RegisterProcessID(MAX_PROC_SDFRAUDTOOLFIX);

	if(SingleInstance() ==  false)
	{
		return TRUE;
	}

	m_hAppStopEvent = NULL;
	m_hAppStopEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);

	m_hUnpckSignal = NULL;
	m_hUnpckSignal = ::CreateEvent(NULL, TRUE, FALSE, NULL);

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	/*******************************************************************************/
	TCHAR		szAppPath[1024] = {0x00},*pTemp = NULL;
	TCHAR		szLogLine[1024] = {0x00};
	TCHAR		szSettingFolPath[1024] = {0x00};
		
	m_bIsUIProduct = FALSE;
	m_dwWaitRetryCnt = 0x00;

	GetModuleFileName(NULL,szAppPath,1024);
	pTemp = _tcsrchr(szAppPath,L'\\');
	if (pTemp != NULL)
	{
		*pTemp = '\0';
		_stprintf(szSettingFolPath,L"%s\\",szAppPath);
		_tcscat(szAppPath,L"\\UPack32\\AuUnpacker32.dll");
	}
	else
	{
		_stprintf(szSettingFolPath,L"%s",szAppPath);
		_tcscpy(szAppPath,L"UPack32\\AuUnpacker32.dll");
	}

	/*
	_tcscat(szSettingFolPath,L"Setting\\SDKSettings.ini");

	if (PathFileExists(szSettingFolPath) == FALSE)
	{
		m_bIsUIProduct = TRUE;
	}
	else
	{
		UINT iValue = GetPrivateProfileInt(L"ProductSetting", L"UIProduct", 0, szSettingFolPath);
		if (iValue == 0x01)
		{
			m_bIsUIProduct = TRUE;
		}
	}
	*/
	m_bIsUIProduct = TRUE;

	_tcscpy(m_szUpakLibPath, szAppPath);

	LoadUpackLib();
	/********************************************************************************/

	m_objMaxCommunicatorServer.Run();

	if (m_bIsUIProduct == TRUE)
	{
		WaitForSingleObject(m_hAppStopEvent, INFINITE);
	}
	else
	{
		while(m_dwWaitRetryCnt < 0x05)
		{
			DWORD  dwRetVal = WaitForSingleObject(m_hAppStopEvent, 4000);
			if (dwRetVal == WAIT_TIMEOUT)
			{
				m_dwWaitRetryCnt++;
			}
			else
			{
				break;
			}
		}
	}

	return FALSE;
}

int CMaxUnpackExeApp::LoadUpackLib()
{
	int		iRetValue = 0x00;

	m_hUnpacker32 = NULL;
	m_lpfnUnpackFileNew32 = NULL;
	m_hUnpacker32 = LoadLibrary(m_szUpakLibPath);
	if (m_hUnpacker32)
	{
		m_lpfnUnpackFileNew32 = (LPFNUnpackFile)GetProcAddress(m_hUnpacker32, "UnPackFile");
	}

	return iRetValue;
}
int CMaxUnpackExeApp::UnLoadUpackLib()
{
	int		iRetValue = 0x00;

	FreeLibrary(m_hUnpacker32);
	m_hUnpacker32 = NULL;
	m_lpfnUnpackFileNew32 = NULL;

	return iRetValue;
}

int CMaxUnpackExeApp::UnpackFile(LPCTSTR pszInFile,LPTSTR pszOutFile)
{
	int		iReturn = 0x00;

	if (m_hUnpacker32 == NULL || m_lpfnUnpackFileNew32 == NULL)
	{
		return iReturn;
	}
	iReturn = m_lpfnUnpackFileNew32(pszInFile, pszOutFile);

	return iReturn;
}

void CMaxUnpackExeApp::OnDataReceivedCallBack(LPVOID lpMaxParam)
{
	
	//WaitForSingleObject(theApp.m_hUnpckSignal, INFINITE);
	//SetEvent(theApp.m_hUnpckSignal);

	if (lpMaxParam == NULL)
	{
		//ResetEvent(theApp.m_hUnpckSignal);
		return;
	}

	LPSHARED_UNPACKER_SWITCH_DATA sMaxPipeData = (SHARED_UNPACKER_SWITCH_DATA*)lpMaxParam;

	if (sMaxPipeData->szFile2Unpack == NULL || sMaxPipeData->szUnpackedFileName  == NULL)
	{
		//ResetEvent(theApp.m_hUnpckSignal);
		return; 
	}
	
	TCHAR	szDummyFName[1024] = {0x00};
	int iRetValue = theApp.UnpackFile(sMaxPipeData->szFile2Unpack,szDummyFName);

	_tcscpy(sMaxPipeData->szUnpackedFileName,szDummyFName);
	
	
	if ( theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData))
	{
	}
	else
	{
	}

	if (iRetValue == UNPACK_EXPECTION)
	{
		/*theApp.UnLoadUpackLib();
		Sleep(100);
		theApp.LoadUpackLib();*/
		SetEvent(theApp.m_hAppStopEvent);

	}

	Sleep(10);

	if (theApp.m_bIsUIProduct == FALSE)
	{
		SetEvent(theApp.m_hAppStopEvent);
		CloseHandle(theApp.m_hAppStopEvent);
		theApp.m_hAppStopEvent = NULL;
	}

	//ResetEvent(theApp.m_hUnpckSignal);
	return;
}
