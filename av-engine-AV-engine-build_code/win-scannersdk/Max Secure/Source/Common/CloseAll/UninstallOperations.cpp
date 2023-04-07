/*======================================================================================
   FILE				: CloseAll.cpp
   ABSTRACT			: MFC Extension DLL starter file.
   DOCUMENTS		: 
   AUTHOR			: Apte Sunil
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   NOTE				:
   VERSION HISTORY	: 	Dec2007 : Sandip : Ported to VS2005 with Unicode and X64 bit Compatability.		
=======================================================================================*/
#include "UninstallOperations.h"
#include "ExecuteProcess.h"
#include "MaxProtectionMgr.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/*-------------------------------------------------------------------------------------
Function		: UnInstallPage
In Parameters	: CString csParam
Out Parameters	: int
Purpose			: Dispaly the Uninstall html page depend on param
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
int CUninstallOperations::UnInstallPage(CString csParam, CString csCommandLine)
{
	CString csVendorName, csInstDate, csIEWithPath, csProgPath;
	CSDCloseAll objSDCloseAll;
	CRegistry objRegistry;
	DWORD dwData;

	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("VendorName"), csVendorName, HKEY_LOCAL_MACHINE);	//Get vendore Name
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("InstallationDate"), csInstDate, HKEY_LOCAL_MACHINE);	//Get Installation Date

	CString csUnReg = _T("0");
	if(objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwData, HKEY_LOCAL_MACHINE))
	{
		csUnReg.Format(_T("%d"), dwData);
	}

	objSDCloseAll.GetIEWithPath(csIEWithPath); //Get IE PAth
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AppFolder"), csProgPath, HKEY_LOCAL_MACHINE);	//Get AppFolder Path

	dwData = 0;
	if(csParam == _T("UNINSTALL"))
	{
		if(objRegistry.KeyExists(CSystemInfo::m_csProductRegKey, HKEY_LOCAL_MACHINE))
		{
			if(!objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("Uninst"), dwData, HKEY_LOCAL_MACHINE))
			{
				CRemoteService objRemoteSrc;
				dwData = 1;
				objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("Uninst"), dwData, HKEY_LOCAL_MACHINE);
			}
			else
			{
				return 0;
			}

			dwData = 0;
			if(!objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("IsUninst"), dwData, HKEY_LOCAL_MACHINE))
			{
				dwData = 0;
			}

			if(dwData == 0)
			{
				ShellExecute(NULL, NULL, csIEWithPath, csCommandLine+csVendorName+_T("&UnReg=") +csUnReg, NULL, SW_SHOWNORMAL);
			}
		}
	}
	else if(csParam == _T("UNINST"))
	{
		ShellExecute(NULL, NULL, csIEWithPath, csCommandLine+csVendorName+_T("&UnReg=") +csUnReg, NULL, SW_SHOWNORMAL);
		return 0;
	}
	else if(csParam == _T("-1"))
	{
		CString csINIFile, csCount;
		TCHAR buff[MAX_PATH];
		csINIFile =  csProgPath + _T("\\") + WORMSCOUNTINI;
		GetPrivateProfileString(_T("summary"), _T("ScannedWormCount"), _T(""), buff, 
			MAX_PATH, csINIFile);
		int		iWormCount = _wtoi(buff);
		csCount.Format(_T("%d"), iWormCount);
		ShellExecute(NULL, NULL, csIEWithPath, csCommandLine+csVendorName+_T("&Cnt=")+csCount+_T("&Dt=") +csInstDate+_T("&UnReg=") +csUnReg, NULL, SW_SHOWNORMAL);
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
Function		: QuarantineFolderRemove
In Parameters	: -
Out Parameters	: -
Purpose			: Delete all entries in Quarantine folder
Author			:
--------------------------------------------------------------------------------------*/
void CUninstallOperations::QuarantineFolderRemove(CString csParam)
{
	CString csProgPath;
	CRegistry objRegistry;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AppFolder"), csProgPath, HKEY_LOCAL_MACHINE);
	
	CFileFind fFile;
	
	BOOL bRet = fFile.FindFile(csProgPath + (CString)QUARANTINEFOLDER + _T("\\*.tmp"));
	
	fFile.Close();
	CString csClosallPath;
	csClosallPath = csProgPath + _T("ausrvopt.exe");
	DWORD dwLastError = 0;
	CFileOperation objFileOperation;
	csProgPath = csProgPath + _T("*.*");

	if(bRet)
	{
		CString csStringToDisPlay;
		csStringToDisPlay = L"There are some files in the Quarantined folder.\nDo you want to remove them now?";
		int iRet = MessageBox(NULL, csStringToDisPlay, CSystemInfo::m_csProductName, MB_YESNO|MB_TOPMOST);
		if(iRet == IDYES)
		{
			objFileOperation.DeleteFolderTree(csProgPath, true, true, dwLastError, _T(""), _T(""), _T("ausrvopt.exe"), true);
		}
		else
		{
			objFileOperation.DeleteFolderTree(csProgPath, true, true, dwLastError, QUARANTINEFOLDER, _T(""), _T("ausrvopt.exe"), true);
		}
	}
	else
	{
		objFileOperation.DeleteFolderTree(csProgPath, true, true, dwLastError, _T(""), _T(""), _T("ausrvopt.exe"), true);
	}
	UnInstallPage(_T("-1"), csParam);

	CEnumProcess objEnumProc;
	objEnumProc.IsProcessRunning(csClosallPath, true);
	::DeleteFile(csClosallPath);
}

/*-------------------------------------------------------------------------------------
Function		: AddProcessesInArray
In Parameters	: CStringArray &arrProcesses
Out Parameters	: -
Purpose			: Add the Process name in a array and return array
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
void CUninstallOperations::AddProcessesInArray(CStringArray &arrProcesses)
{
	arrProcesses.Add(UI_EXENAME);
	arrProcesses.Add(LIVEUPDATE_EXE);
	arrProcesses.Add(MAXWATCHDOG_SVC_EXE);
	arrProcesses.Add(MAX_SCANNER);
	arrProcesses.Add(ACT_MON_TRAY_EXE);
	arrProcesses.Add(ACTMON_SVC_NAME);
	arrProcesses.Add(MAXMERGER_SVC_EXE);
	arrProcesses.Add(_T("AUDBServer.exe"));
	arrProcesses.Add(_T("AUMAILPROXY.EXE"));
}

/*-------------------------------------------------------------------------------------
Function		: DeleteSDFiles
In Parameters	: CString csSysPath
Out Parameters	: -
Purpose			: Delete SD files in the system directory
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
void CUninstallOperations::DeleteSDFiles(CString csSysPath)
{
	DeleteFile(csSysPath + _T("\\") + WIN_BACKUP);
	DeleteFile(csSysPath + _T("\\") + IE_BACKUP);
	DeleteFile(csSysPath + _T("\\") + WIN_INI);
	DeleteFile(csSysPath + _T("\\") + SYS_INI);
	DeleteFile(csSysPath + _T("\\") + KEYS_BACKUP);
	DeleteFile(csSysPath + _T("\\") + LIVEUPDATE_LOG);
}

/*-------------------------------------------------------------------------------------
Function		: PauseSDSelfProtection
In Parameters	: -
Out Parameters	: BOOL
Purpose			: Pause the  protection
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
BOOL CUninstallOperations::PauseSDSelfProtection(bool bPause)
{
	HANDLE hDriver;
	DWORD dw;
	hDriver = CreateFile(MAXMGR_DRIVE_SYMBOLIC, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if(hDriver == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if(bPause)
	{
		if(!DeviceIoControl(hDriver, IOCTL_PAUSE_SELFPROTECTION, 0, 0, 0, 0, &dw, 0))
		{
			CloseHandle(hDriver);
			hDriver = NULL;
			return FALSE;
		}
	}
	else
	{
		if(!DeviceIoControl(hDriver, IOCTL_CONTINUE_SELFPROTECTION, 0, 0, 0, 0, &dw, 0))
		{
			CloseHandle(hDriver);
			hDriver = NULL;
			return FALSE;
		}
	}
	CloseHandle(hDriver);
	hDriver = NULL;
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CloseAllExeFunction
In Parameters  : int iExeCheck, 
Out Parameters : BOOL
Description    : Close all running application list
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CUninstallOperations::CloseAllExeFunction(int iExeCheck)
{
	CStringArray arrProcesses;
	BOOL bRet = TRUE;
	CSDCloseAll objSdCloseAll;
	CRemoteService objRemoteSrc;
	//objSdCloseAll.CloseApplicationandStopService();
	objRemoteSrc.DeleteRemoteService(MAXWATCHDOG_SVC_NAME);
	objRemoteSrc.DeleteRemoteService(MAXMERGER_SVC_NAME);
	Sleep(1000);

	arrProcesses.Add(_T("AUMAINUI.EXE"));
	arrProcesses.Add(_T("AUUSB.EXE"));
	arrProcesses.Add(_T("AUFWPNP.EXE"));
	arrProcesses.Add(_T("AUTRAY.EXE"));
	arrProcesses.Add(_T("
		.EXE"));
	arrProcesses.Add(_T("AUSCANNER.EXE"));
	arrProcesses.Add(_T("AUACTMON.EXE"));
	arrProcesses.Add(_T("AUDSRV.EXE"));
	arrProcesses.Add(_T("AUMERGER.EXE"));
	arrProcesses.Add(_T("AUDBSERVER.EXE"));
	arrProcesses.Add(_T("AUMAILPROXY.EXE"));
	arrProcesses.Add(_T("AUFWPNP.EXE"));

	if(iExeCheck == 1)
	{
		arrProcesses.Add(LIVEUPDATE_EXE);
	}

	if(!objSdCloseAll.KillProcesses(arrProcesses, iExeCheck))
	{
		bRet = FALSE;
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: InstallationOperations
In Parameters	: -
Out Parameters	: -
Purpose			: call this function for install or uninstall or Reinstall operation
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
int CUninstallOperations::UnInstallationOperations(CString csCommandLine, CString csParam)
{
	CSDCloseAll objSDCloseAll;
	CStringArray arrProcesses;
	const CString szTemp = CSystemInfo::m_strSysDir;

	AddProcessesInArray(arrProcesses);//Add processes in array to kill

	if(csCommandLine != BLANKSTRING)
	{
		if(csCommandLine == _T("CLOSEALLEXE"))
		{
			CloseAllExeFunction(1);
			return 1;
		}
		if(csCommandLine == _T("CLOSESOMEEXE"))
		{
			CloseAllExeFunction(2);
			return 1;
		}
		if(csCommandLine == _T("UNINST"))
		{
			//OutputDebugString (_T("Parameter UNINST :: UnInstallPage"));
			UnInstallPage(_T("UNINST"), csParam);

			CCPUInfo objCpuInfo;
			bool is64Bit = (objCpuInfo.isOS64bit()?true:false);
			return 0;
		}
		if(csCommandLine != _T("INSTALL"))// to kill one EXE
		{
			arrProcesses.RemoveAll();
			arrProcesses.Add(csCommandLine);
		}
		else // for Reinstall
		{
			CRemoteService objRemoteSrc;
			objRemoteSrc.StopRemoteService(MAXMGR_DRIVE_TITLE);//SERVICE_NAME
			Sleep(3000);
			objRemoteSrc.DeleteRemoteService(MAXWATCHDOG_SVC_NAME);
			Sleep(1000);
			objRemoteSrc.DeleteRemoteService(MAXMERGER_SVC_NAME);
			Sleep(1000);
		}
		objSDCloseAll.KillProcesses(arrProcesses);
	}
	else // For Uninstall
	{
		CRemoteService objRemoteSrc;

		CMaxProtectionMgr oMaxProtectionMgr;
		oMaxProtectionMgr.RemoveProtection();

		CRegistry objRegistry;
		DWORD dwData = 1;
		objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("IsUninst"), dwData, HKEY_LOCAL_MACHINE);
		
		//To set key to Remove Native Scanner
		CStringArray csAValue;
		csAValue.Add(_T("autocheck autochk *"));		
		objRegistry.Set(BOOT_EXECUTE_REG_KEY, _T("BootExecute"), csAValue, HKEY_LOCAL_MACHINE);	

		objRemoteSrc.StopRemoteService(_T("SBAMSvc"), false);
	
		objRemoteSrc.StopRemoteService(MAXMGR_DRIVE_TITLE);

		objRemoteSrc.DeleteRemoteService(MAXWATCHDOG_SVC_NAME);
		objRemoteSrc.DeleteRemoteService(MAXMERGER_SVC_NAME);

		objSDCloseAll.KillProcesses(arrProcesses);//Kill Processes

		objRemoteSrc.StopRemoteService(_T("AuDSrv"),false);
		CExecuteProcess objExecute;
		CCPUInfo objSystem;
#ifdef WIN64
		CString csAppPath = objSystem.GetProgramFilesDirX64 ();
		objExecute.ExecuteCommand( csAppPath + _T("\\") + CSystemInfo::m_csProductName +  _T("\\AuDSrv.exe"), _T("/UnRegServer"),true);
		
		objRemoteSrc.DeleteRemoteService(_T("AuDSrv"));
#else
		objExecute.ExecuteCommand( CSystemInfo::m_strAppPath + _T("\\AuDSrv.exe"), _T("/UnRegServer"),true);
		objRemoteSrc.DeleteRemoteService(_T("AuDSrv"));
#endif

		
		
		QuarantineFolderRemove(csParam);

		
	}
	return 1;
}