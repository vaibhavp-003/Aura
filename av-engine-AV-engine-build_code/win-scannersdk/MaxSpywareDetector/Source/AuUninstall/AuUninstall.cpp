// AuUninstall.cpp : Defines the initialization routines for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "AuUninstall.h"
#include "Registry.h"
#include "UltraAVInstaller.h"
#include <strsafe.h>
#include <msiquery.h>
#include <wcautil.h>
#include "MaxProtectionMgr.h"
#include "EnumProcess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO: If this DLL is dynamically linked against the MFC DLLs,
//		any functions exported from this DLL which call into
//		MFC must have the AFX_MANAGE_STATE macro added at the
//		very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

// CAuUninstallApp

BEGIN_MESSAGE_MAP(CAuUninstallApp, CWinApp)
END_MESSAGE_MAP()


// CAuUninstallApp construction

CAuUninstallApp::CAuUninstallApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}




// The one and only CAuUninstallApp object

CAuUninstallApp theApp;


// CAuUninstallApp initialization

BOOL CAuUninstallApp::InitInstance()
{
	CWinApp::InitInstance();
    theApp.m_pSendMessageToUI = NULL;
	return TRUE;
}
/*--------------------------------------------------------------------------------------
Function       : UninstallProduct
In Parameters  :
Out Parameters : bool
Description    : Call to uninstall product
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool UninstallProduct(SENDUNINSTALLMESSAGETOUI pSendMessageToUI)
{
    theApp.m_pSendMessageToUI = pSendMessageToUI;
    theApp.StartUninstallationProcess();
    return true;
}

/*--------------------------------------------------------------------------------------
Function       : UninstallProcessStart
In Parameters  :
Out Parameters : bool
Description    : Call to cleanup driver and service data
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool UninstallProcessStart()
{
 	OutputDebugString(L"UninstallProcessStart");
    CRegistry objReg;
    CString csAppPath = L"";
    if (objReg.KeyExists(ULTRAAV_REG_KEY), HKEY_LOCAL_MACHINE)
    {
        CMaxProtectionMgr oMaxProtectionMgr;
        oMaxProtectionMgr.RegisterProcessSetup(MAX_PROC_MAXAVSETUP);
        CUltraAVInstaller objUltraAVInstaller;
        objUltraAVInstaller.UninstalltionStart();
    }
    return true;
}
/*--------------------------------------------------------------------------------------
Function       : CleanUpProduct
In Parameters  : 
Out Parameters : bool
Description    : Call to cleanup remaining folder and files
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool CleanUpProduct()
{
	OutputDebugString(L"CleanUpProduct");
    CRegistry objReg;
    CString csAppPath = L"";
    if (objReg.KeyExists(ULTRAAV_REG_KEY), HKEY_LOCAL_MACHINE)
    {
        CUltraAVInstaller objUltraAVInstaller;
        objUltraAVInstaller.StartCleanUp();
    }
    return true;
}

/*--------------------------------------------------------------------------------------
Function       : ShutdownRebootSystem
In Parameters  : int iStatus
Out Parameters : void
Description    : Shutdown or reboot system
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ShutdownRebootSystem(int iStatus)
{
    CEnumProcess objEnumProcess;
    objEnumProcess.RebootSystem(iStatus);			//0: Reboot, 1: Shutdown, 2:Logoff
}

/*--------------------------------------------------------------------------------------
Function       : IniUninstallProcessStart
In Parameters  :
Out Parameters : MSIHANDLE
Description    : Called from MSI to start uninstallation 
--------------------------------------------------------------------------------------*/
UINT __stdcall IniUninstallProcessStart(MSIHANDLE hInstall)
{
    OutputDebugString(L"Inside IniUninstallProcessStart");

    TCHAR szFilePath[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    OutputDebugString(szFilePath);
    HRESULT hr = S_OK;
    UINT er = ERROR_SUCCESS;

    hr = WcaInitialize(hInstall, "SetIniRegistriesEx");
    ExitOnFailure(hr, "Failed to initialize");
    bool bRet = theApp.IniUninstall();
    UINT iRet = 0;
    if (bRet == false)
    {
        iRet = 1;
    }
LExit:
    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return iRet;

}

/*--------------------------------------------------------------------------------------
Function       : IniUninstallCleanUpProduct
In Parameters  :
Out Parameters : MSIHANDLE
Description    : Called from MSI to finish uninstallation
--------------------------------------------------------------------------------------*/
UINT __stdcall IniUninstallCleanUpProduct(MSIHANDLE hInstall)
{
    OutputDebugString(L"Inside IniUninstallCleanUpProduct");
    TCHAR szFilePath[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    OutputDebugString(szFilePath);
    HRESULT hr = S_OK;
    UINT er = ERROR_SUCCESS;

    hr = WcaInitialize(hInstall, "SetIniRegistriesEx");
    ExitOnFailure(hr, "Failed to initialize");
    bool bRet = theApp.FinishUninstall();
    UINT iRet = 0;
    if (bRet == false)
    {
        iRet = 1;
    }

LExit:
    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return iRet;

}

/*--------------------------------------------------------------------------------------
Function       : IniUninstall
In Parameters  :
Out Parameters : bool
Description    : Call to cleanup driver and service data
--------------------------------------------------------------------------------------*/
bool CAuUninstallApp::IniUninstall()
{
	CRegistry objReg;
    CString csAppPath = L"";

    //Check Product registry path
	if (objReg.KeyExists(ULTRAAV_REG_KEY), HKEY_LOCAL_MACHINE)
	{
		objReg.Get(ULTRAAV_REG_KEY, _T("AppFolder"), csAppPath, HKEY_LOCAL_MACHINE);
	}

    // Check path is empty or not
    if (!csAppPath.IsEmpty())
    {
        typedef bool (*LPUNINSTALLPROCESSSTART)();
        LPUNINSTALLPROCESSSTART	lpUninProcess;
        HMODULE			hUninstallDll = NULL;
        if (hUninstallDll == NULL)
        {
            CString csDllPath = L"";
            csDllPath.Format(_T("%s%s"), csAppPath, (CString)UNINSTALL_PROCESS);
            hUninstallDll = LoadLibrary(csDllPath);
            if (hUninstallDll == NULL)
            {
                return false;
            }
            else
            {
                lpUninProcess = (LPUNINSTALLPROCESSSTART)GetProcAddress(hUninstallDll, "UninstallProcessStart");
                if (lpUninProcess == NULL)
                {
                    FreeLibrary(hUninstallDll);
                    hUninstallDll = NULL;
                    lpUninProcess = NULL;
                    return false;
                }
                else
                {
                    bool bRet = false;
                    bRet = lpUninProcess();
                    FreeLibrary(hUninstallDll);
                    hUninstallDll = NULL;
                    lpUninProcess = NULL;
                    return bRet;
                }
            }
        }
    }
	return true;
}
/*--------------------------------------------------------------------------------------
Function       : FinishUninstall
In Parameters  :
Out Parameters : bool
Description    : Call to cleanup remaining folder and files
--------------------------------------------------------------------------------------*/
bool CAuUninstallApp::FinishUninstall()
{
    CRegistry objReg;
    CString csAppPath = L"";

    //Check Product registry path
    if (objReg.KeyExists(ULTRAAV_REG_KEY), HKEY_LOCAL_MACHINE)
    {
        objReg.Get(ULTRAAV_REG_KEY, _T("AppFolder"), csAppPath, HKEY_LOCAL_MACHINE);
    }

    // Check path is empty or not
    if (!csAppPath.IsEmpty())
    {
        typedef bool (*LPCLEANUPPRODUCT)();
        LPCLEANUPPRODUCT	lpUninProcess;
        HMODULE			hUninstallDll = NULL;
        if (hUninstallDll == NULL)
        {
            CString csDllPath = L"";
            csDllPath.Format(_T("%s%s"), csAppPath, (CString)UNINSTALL_PROCESS);
            hUninstallDll = LoadLibrary(csDllPath);
            if (hUninstallDll == NULL)
            {
                return false;
            }
            else
            {
                lpUninProcess = (LPCLEANUPPRODUCT)GetProcAddress(hUninstallDll, "CleanUpProduct");
                if (lpUninProcess == NULL)
                {
                    FreeLibrary(hUninstallDll);
                    hUninstallDll = NULL;
                    lpUninProcess = NULL;
                    return false;
                }
                else
                {
                    bool bRet = false;
                    bRet = lpUninProcess();
                    FreeLibrary(hUninstallDll);
                    hUninstallDll = NULL;
                    lpUninProcess = NULL;
                    return bRet;
                }
            }
        }
    }
return true;
}

/*--------------------------------------------------------------------------------------
Function       : StartUninstallationProcess
In Parameters  :
Out Parameters : bool
Description    : Call to cleanup folder and files
--------------------------------------------------------------------------------------*/
bool CAuUninstallApp::StartUninstallationProcess()
{
    CRegistry objReg;
    memset(&m_objUninstallStatus,0,sizeof(UninstallStatusInfo));
    if (objReg.KeyExists(ULTRAAV_REG_KEY), HKEY_LOCAL_MACHINE)
    {
        CMaxProtectionMgr oMaxProtectionMgr;
        oMaxProtectionMgr.RegisterProcessSetup(MAX_PROC_MAXAVSETUP);
        CUltraAVInstaller objUltraAVInstaller;
        objUltraAVInstaller.UninstalltionStart();
        objUltraAVInstaller.StartCleanUp();
    }
    return true;
}
/*--------------------------------------------------------------------------------------
Function       : ShowStatus
In Parameters  :
Out Parameters : bool
Description    : Show uninstallation status
--------------------------------------------------------------------------------------*/
bool CAuUninstallApp::ShowStatus(int iMsgId, int iPer)
{
    if (theApp.m_pSendMessageToUI != NULL)
    {
        m_objUninstallStatus.iMessageId = iMsgId;
        m_objUninstallStatus.iPercentage = iPer;
        theApp.m_pSendMessageToUI(m_objUninstallStatus);
    }
    return true;
}