/*======================================================================================
FILE             : CommonFunctions.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura.	

CREATION DATE    : 05/18/2009 11:18:03 AM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
Date			 :	30-04-2010
					Change by Tejas K. to uninstall SD enterprise edition.

======================================================================================*/
#include "CommonFunctions.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "S2S.h"
#include "HardDiskManager.h"
#include "ExecuteProcess.h"
#include "CommonFileIntegrityCheck.h"
#include "RemoveProductsDlg.h"
#include "MaxProtectionMgr.h"
#include "MSIOperations.h"
#include "DirectoryManager.h"
#include <fcntl.h>
#include <sys\stat.h>
#include <AclAPI.h>
#include <sddl.h>

typedef void (*LPDLLREGISTER)(void);
bool CCommonFunctions::m_bRestartRequired = false;
/*--------------------------------------------------------------------------------------
Function       : CCommonFunctions
In Parameters  : void
Out Parameters :
Description    : constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CCommonFunctions::CCommonFunctions(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CCommonFunctions
In Parameters  : void
Out Parameters :
Description    : destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CCommonFunctions::~CCommonFunctions(void)
{
}

/*-----------------------------------------------------------------------------
Function		: CheckFor64bitOS
In Parameters	:
Out Parameters	:
Purpose			: To check whether operating system is 64 bit and do the operations accordingly
Author		`	: Milind Shete
-----------------------------------------------------------------------------*/
bool CCommonFunctions::Is64bitOS(CString csDownLoadLink, 
								 BOOL bIs64Setup, CString csProductName)
{
	try
	{
		CCPUInfo objSystem;
		CString csOS = objSystem.GetOSVerTag();
		/*CMessageBox objMessaageBox;
		objMessaageBox.m_Title = csProductName;*/
		BOOL bOs64bit = objSystem.isOS64bit();
		if(bOs64bit == TRUE)
		{
			if(bIs64Setup == false)
			{	
				/*objMessaageBox.m_Text.LoadStringW(IDS_OS_COMPAT_MSG);
				objMessaageBox.m_Link = csDownLoadLink;
				objMessaageBox.DoModal();*/
				return true;
			}
			/*else
			{
				CRegistry objRegistry;
				CString csSpyPath;
				objRegistry.Get(PRODUCT_REG, _T("AppPath"), csSpyPath, HKEY_LOCAL_MACHINE);
				csSpyPath.MakeLower();
				if((csSpyPath.Find(_T("spyware")) != -1))
				{
					objMessaageBox.m_Text = L"Product is installed on this system.Please uninstall it first and then try installing this.";
					objMessaageBox.DoModal();
					return true;
				}
			}*/
		}
		else if(bOs64bit == FALSE)
		{
			if(bIs64Setup || csOS == W98 || csOS == WME)
			{
				/*objMessaageBox.m_Text.LoadStringW(IDS_32_OPERATING_SYSTEM_MSG);
				if(bIs64Setup == TRUE)
				{
					objMessaageBox.m_Link = csDownLoadLink;
				}
				else if(csOS == W98 || csOS == WME)
				{
					objMessaageBox.m_Link = cs98DownLoadLink;
				}
				objMessaageBox.DoModal();*/
				return true;
			}
		}
		return false;
	}
	catch(...)
	{
		return true;
	}
}

/*--------------------------------------------------------------------------------------
Function       : HandlingFor64bit
In Parameters  : -
Out Parameters : BOOL
Description    : This function do handling for 64 bit
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::HandlingFor64bit()
{

	CCPUInfo objSystem;
	int iRet;
	CString csStr;
	CYesNoMsgBoxDlg objYesNoMsgBoxDlg;
	csStr.LoadStringW(IDS_UNINSTALL_MSG_EN);
	objYesNoMsgBoxDlg.m_csMessage = csStr;
	iRet = objYesNoMsgBoxDlg.DoModal();
	if(iRet == IDOK)
	{
		m_bRestartRequired = true;
		return FALSE;
	}

	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CheckHardDiskSpaceAvailable
In Parameters  : double dwDiskFreeSize, 
Out Parameters : BOOL 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::CheckHardDiskSpaceAvailable(double dwDiskFreeSize)
{
	CHardDiskManager objHardDiskManager;
	objHardDiskManager.CheckFreeSpace(CSystemInfo::m_strRoot);
	if(objHardDiskManager.GetTotalNumberOfFreeGBytes()< dwDiskFreeSize)
	{
		CString csMsg = _T("Installation requires atleast 400MB of harddisk space, which is not available. Try installing the program after you have created atleast 400MB free harddisk space.");
		CMessageBoxNormal objMessageBoxNormal;
		objMessageBoxNormal.m_csMessage = csMsg;
		objMessageBoxNormal.DoModal();
		return FALSE;
	}
	return TRUE;
}
BOOL CCommonFunctions::ProductCompatibiltiy(UINT uType, CString csDownloadUrl,  BOOL bIs64Setup, CString csProdRegKey)
{
	try
	{
		CString csProductName;
		csProductName = csProdRegKey.Mid(9);

		BOOL bRetVal = FALSE;
		CFileFind objFileFind;
		CString csPath;
		CString csSpyPath;
		CRemoveProductsDlg objRemoveProductsDlg;

		if(-1 != csProdRegKey.Find(_T("UltraAV")))
		{
			objRemoveProductsDlg.m_iProdID = PROD_ID_UAV;
			if(10 != uType)
			{
				objRemoveProductsDlg.m_bCheckSD = true;
				objRemoveProductsDlg.m_bCheckAV = true;
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in ProductCompatibiltiy"));
		return FALSE;
	}
}
/*-----------------------------------------------------------------------------
Function		: DLLFunction
In Parameters	: HWND : handle to window
: UINT :
Out Parameters	: BOOL :true if UnInstallation is successful
otherwise false.
Purpose			: 
Author			: Sandip Sanap
-----------------------------------------------------------------------------*/
BOOL CCommonFunctions::CheckDLLFunction(UINT uType, CString csDownloadUrl, BOOL bIs64Setup, CString csProdRegKey)
{
	try
	{
		if(CheckForBartPE() == FALSE)
		{
			if( CheckHardDiskSpaceAvailable(0.39) == FALSE)
			{
				return TRUE;
			}
		}
		CRegistry	objRegistry;
		CCPUInfo objSystem;
		CString csProductName;
		csProductName = csProdRegKey.Mid(9);

		BOOL bIs64 = objSystem.isOS64bit();
		if(bIs64)
		{
			objRegistry.SetWow64Key(true);
		}
		DWORD dwMajor, dwMinor = 0;
		objSystem.GetMajorAndMinorOSVersion(dwMajor, dwMinor);

		

		if(uType == 10 && objSystem.isOS64bit() && bIs64Setup)
		{
			//return HandlingFor64bit();
			m_bRestartRequired = true;
			return FALSE;
		}
		if(/*uType == 10 && */(Is64bitOS(csDownloadUrl, bIs64Setup, csProductName)))
		{
			return TRUE;
		}

		BOOL bRetVal = FALSE;
		CFileFind objFileFind;
		CString csPath;
		CString csSpyPath;
		//CRemoveProductsDlg objRemoveProductsDlg;
		

		if(uType == 10)
		{
			return CheckInstallation(csProdRegKey);
		}
		return FALSE;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in DLLFunction"));
		return FALSE;
	}
}

/*-------------------------------------------------------------------------------------
Function		: EncryptDB
In Parameters	: char
Out Parameters	: BOOL
Purpose			: This Function encrypts the Database files
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions:: EncryptFileDB(TCHAR csFileNames[200], short iHeaderSize)
{
	try
	{
		CString csFilePath;
		csFilePath = csFileNames;
		csFilePath.MakeUpper();
		CryptFile(csFilePath, iHeaderSize);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in EncryptDB"));
		return false;
	}
}

/*-----------------------------------------------------------------------------
Function		: CheckInstallation
In Parameters	: -
Out Parameters	: bool
Purpose			: To check whether product is already installed
Author		`	: Milind Shete
-----------------------------------------------------------------------------*/
bool CCommonFunctions::CheckInstallation(CString csProdReg)
{
	try
	{
		int iRet = IDOK;
		CRegistry objRegistry;
		CResourceManager objResMgr;

		CString csStr;
		DWORD dwLanguage;
		objRegistry.Get(csProdReg, _T("Language"), dwLanguage, HKEY_LOCAL_MACHINE);
		objResMgr.UpdateCurrentLanguage(dwLanguage);

		//csStr.LoadStringW(IDS_UNINSTALL_MSG_EN + dwLanguage * 1000);

		{
			/*CYesNoMsgBoxDlg objYesNoMsgBoxDlg;
			objYesNoMsgBoxDlg.m_csMessage = csStr;
			iRet = objYesNoMsgBoxDlg.DoModal();*/
		}

		//if(iRet == IDOK)
		{
			m_bRestartRequired = true;
			StopWDService();
			CheckDLLCloseFunction(NULL, MB_OK, 1, csProdReg);
			return false;
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CheckInstallation"));
		return true;
	}
}

/*--------------------------------------------------------------------------------------
Function       : RestartRequired
In Parameters  :
Out Parameters : bool
Description    : returns true if restart requires.
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CCommonFunctions::RestartRequired()
{
	return m_bRestartRequired;
}

/*--------------------------------------------------------------------------------------
Function       : RestartRequired
In Parameters  :
Out Parameters : bool
Description    : returns true if restart requires.
Author         : Swapnil Lokhande
--------------------------------------------------------------------------------------*/
int CCommonFunctions::LaunchNotificationsInUserContext(int iType, TCHAR* pszAppName, TCHAR* pszParam)
{
	CString csAppName = pszAppName; 
	CString csParam = pszParam;
	
	switch(iType)
	{
	case 1:
		{
			CExecuteProcess objProcess;
			return objProcess.StartProcessWithToken(csAppName, csParam, EXPLORE_EXE);

		}
		break;
	case 2:
		{
			CSystemInfo objSystem;
			CCPUInfo oCpuInfo;
			bool bIs64Bit = (oCpuInfo.isOS64bit()?true:false);
			CMaxCommunicator objUITOService(_NAMED_PIPE_UI_TO_SERVICE,false);
			MAX_PIPE_DATA_REG pipeData;
			//TCHAR szDesc[MAX_PATH] = {0};
			SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
			CRegistry oReg;
			if(bIs64Bit)
			{
				oReg.SetWow64Key(true);
			}
			CString csProductVer;
			/*oReg.Get(objSystem.m_csProductRegKey, _T("ProductVersionNo"), csProductVer, HKEY_LOCAL_MACHINE);
			if(csProductVer.Find(L"38") != -1)
			{
				OutputDebugString(L"406");
				pipeData.eMessageInfo = 406;
			}*/
			//else
			{
				OutputDebugString(L"LaunchAppAs_USER");
				pipeData.eMessageInfo = LaunchAppAs_USER;
			}
			OutputDebugString(L"Parameter csParam :" + csParam);
			_tcscpy_s(pipeData.strValue, MAX_PATH, csAppName);
			_tcscpy_s(pipeData.strBackup, MAX_PATH, csParam);
			objUITOService.SendData(&pipeData, sizeof(MAX_PIPE_DATA_REG));
		}
		break;
	case 3:
		{
			CEnumProcess objEnumProcess;
			objEnumProcess.IsProcessRunning(_T("AuNotifications.exe"), true, false);
		}
		break;
	case 4:
		{
			/////ExecuteApplicationAndWaitOnChilds(pszAppName, pszParam);
		}
		break;
	case 5:
		{
			CExecuteProcess objProcess;
			return objProcess.ExecuteCommandWithWait(csAppName, csParam);

		}
		break;
	}	
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: InstallService
In Parameters	: char
Out Parameters	: BOOL
Purpose			: This Function starts the remote service.
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::StopSDService(int iService, TCHAR csFileNames[MAX_PATH])
{
	BOOL bRet = TRUE;
	try
	{
		CExecuteProcess objExecute;
		CRemoteService objRemoteSrc;
		CSystemInfo objSystem;
		switch(iService)
		{
		case 6:
			{
				CString csDriverName(csFileNames);
				break;
			}
		case 8:
			{
				CRegistry objReg;
				CString csAppPath;
				objReg.Get(L"SOFTWARE\\Classes\\TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}\\1.0\\0\\win64",L"",csAppPath,HKEY_LOCAL_MACHINE);
				if (PathFileExists (csAppPath))
				{
					objExecute.ExecuteCommand( csAppPath, _T("/UnRegServer"),true);
					DeleteFile(csAppPath);
				}
				break;
			}
		case 9:
			{
				CRegistry objReg;
				if(objSystem.m_bIsOSX64)
				{
					objReg.SetWow64Key(true);
				}
				CString csAppPath;
				objReg.Get(L"SOFTWARE\\Classes\\TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}\\1.0\\0\\win32",L"",csAppPath,HKEY_LOCAL_MACHINE);
				if (PathFileExists (csAppPath))
				{
					objExecute.ExecuteCommand( csAppPath, _T("/UnRegServer"),true);
					DeleteFile(csAppPath);
				}
				break;
			}
		case 12:
			{
				bRet = objRemoteSrc.StopRemoteService(_T("SBAMSvc"), false);
				CEnumProcess objEnumProcess;
				objEnumProcess.IsProcessRunning(_T("SBAMSvc.exe"),  true, false, false);
				break;
			}			
			case 14:
				{
					CRegistry objReg;
					CString strValue(L"");
					CString csSubKey;
					csSubKey = L"SYSTEM\\CurrentControlSet\\Services\\SBFW";
					if (objReg.KeyExists(csSubKey, HKEY_LOCAL_MACHINE))
					{
						objReg.Get(csSubKey, L"ImagePath", strValue, HKEY_LOCAL_MACHINE);
						if(strValue == _T(""))
						{
							if(!objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, csSubKey))
							{
								//OutputDebugString(L"Failed to delete SBFW Trying one More Time\n");
								//RegDeleteKey (HKEY_LOCAL_MACHINE ,csSubKey);
							}
						}
					}
					break;
				}
				
		}
	}
	catch(...)
	{
		bRet = FALSE;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : AddProcessList
In Parameters  : CStringArray arrProcesses, int iExeCheck, 
Out Parameters : BOOL
Description    : this function add the processes list depends on execution type
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::AddProcessList(CStringArray & arrProcesses, int iExeCheck)
{
	arrProcesses.Add(UI_EXENAME);
	arrProcesses.Add(_T("AUFWPNP.EXE"));
	arrProcesses.Add(_T("AUUSB.EXE"));
	arrProcesses.Add(UI_TRAYNAME);
	arrProcesses.Add(_T("AUWATCHDOGSERVICE.EXE"));
	arrProcesses.Add(_T("AUSCANNER.EXE"));
	arrProcesses.Add(_T("AUSCANNER.EXE"));
	arrProcesses.Add(_T("AUSCANNER.EXE"));
	arrProcesses.Add(_T("AUSCANNER.EXE"));
	arrProcesses.Add(_T("AUSCANNER.EXE"));
	arrProcesses.Add(_T("AUACTMON.EXE"));
	arrProcesses.Add(_T("AUACTMON.EXE"));
	arrProcesses.Add(_T("AUACTMON.EXE"));
	arrProcesses.Add(_T("AUDSRV.EXE"));
	arrProcesses.Add(_T("AUUNINSTALLER.EXE"));
	arrProcesses.Add(_T("AUNOTIFICATIONS.EXE"));
	arrProcesses.Add(_T("AUSRVOPT.EXE"));
	arrProcesses.Add(_T("AUDBSERVER.EXE"));
	arrProcesses.Add(L"AuMailProxy.exe");
	arrProcesses.Add(_T("AuUnpackExe.exe"));
	
	if(iExeCheck == 1)
	{		
		arrProcesses.Add(LIVEUPDATE_EXE);
	}
	else if(iExeCheck != 2)
	{
		
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: DLLCloseFunction
In Parameters	: HWND hWnd, UINT uType, int iExeCheck
Out Parameters	: BOOL
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::CheckDLLCloseFunction(HWND hWnd, UINT uType, int iExeCheck, CString csProdName)
{
	BOOL bRet = TRUE;
	CString csProductKey;
	csProdName.MakeLower ();
	if (csProdName.Find(L"software") == -1 && !m_bRestartRequired )
	{
		CRegistry	objRegistry;
		CString csPath;
		bool bRetVal = false;
		OutputDebugString(L"Product Name " + csProdName);
		CString csType;
		csType.Format(_T("%d"), uType);
		OutputDebugString(L"Type: " + csType);
		
		if(csProdName.Find (L"ultraav")!= -1 )
		{
			csProductKey = ULTRAAV_REG_KEY;
			if(uType != 10)
			{
				/*CMessageBoxNormal objMessaageBox;
				objMessaageBox.m_csMessage = L"UltraAV is not currently installed on your System.";
				objMessaageBox.DoModal();*/
				return FALSE;	
			}
		}
	}
	
//////////////////////////////End

	CRemoteService objRemoteSrc;
	CEnumProcess objEnumProcess;
	CStringArray arrProcesses;
	CCPUInfo oCPUInfo;
	BOOL bIsx64Bit = oCPUInfo.isOS64bit();
		
	if(iExeCheck == 7)
	{
		if(objEnumProcess.IsProcessRunning(LIVEUPDATE_EXE, true, false))
		{
			OutputDebugString (_T(" AuLiveUpdate.exe Killed Successfully"));
		}
		else
		{
			OutputDebugString (_T(" Failed to Kill AuLiveUpdate.exe"));
		}
		return true;
	}
	if(iExeCheck == 2)
	{
		objEnumProcess.IsProcessRunning(UI_EXENAME, true, false);
		objEnumProcess.IsProcessRunning(UI_TRAYNAME, true, false);
		return true;
	}
	if(iExeCheck == 3)
	{
		objEnumProcess.IsProcessRunning(LIVEUPDATE_EXE, true, false);
		return true;
	}
	if(iExeCheck == 4)
	{
		objRemoteSrc.DeleteRemoteService(MAXMERGER_SVC_NAME);
		Sleep(200);
		objEnumProcess.IsProcessRunning(MAXMERGER_SVC_EXE, true, false);
		return true;
	}
	if(iExeCheck == 5)
	{
		HandlingForVirusPatch();
	}
	if(iExeCheck != 5)
	{
		if(!m_bRestartRequired || bIsx64Bit)
		{
			StopWDService();
		}
		AddProcessList(arrProcesses, iExeCheck);
		KillProcesses(arrProcesses);
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : StopWDService
In Parameters  : -
Out Parameters : void
Description    : This function stops the auwatchdogservice
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CCommonFunctions::StopWDService()
{
	CRemoteService oRemoteService;
	CEnumProcess oEnumProcess;
	
	if(IsWin10())
	{
		MAX_PIPE_DATA_REG sScanRequest = {0};
		sScanRequest.eMessageInfo = Enable_Stop_WD_PPL;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, true);
		objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		objMaxCommunicator.ReadData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		OutputDebugString(_T("StopWD Win10"));
	}
	oRemoteService.StopRemoteService(MAXWATCHDOG_SVC_NAME, false);
	
	oRemoteService.StopRemoteService(MAXMERGER_SVC_NAME, false);
	oEnumProcess.IsProcessRunning(MAXMERGER_SVC_EXE, true, false);
	oEnumProcess.IsProcessRunning(MAXWATCHDOG_SVC_EXE, true, false);
	oEnumProcess.IsProcessRunning(ACTMON_SVC_NAME, true, false);
	if(IsWin10())
	{
		SHARED_ACTMON_SWITCH_DATA ActMonSwitchDataEx = {0};
		ActMonSwitchDataEx.eProcType = Enable_Stop_WD_PPL;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_WSCREGSERVICE, true);
		objMaxCommunicator.SendData(&ActMonSwitchDataEx, sizeof(SHARED_ACTMON_SWITCH_DATA));
		objMaxCommunicator.ReadData(&ActMonSwitchDataEx, sizeof(SHARED_ACTMON_SWITCH_DATA));
		OutputDebugString(_T("StopWsc Win10"));
	}

	CleanUpService(MAXMERGER_SVC_NAME);
}

bool CCommonFunctions::UpdateFileIntegrityDB(CString csAppPath)
{
	AddLogEntry(L"In UpdateFileIntegrityDB");
	bool bRet = false;
	CString csMaxDBPath;
	
	CString csMainTempDB = csAppPath + CSystemInfo::m_strTempDBPath  + _T("\\") + SD_DB_FILE_INTEGRITY_CHECK;
	CString csClientDB = csAppPath + CSystemInfo::m_strTempLiveupdate  + _T("\\") + SD_DB_FILE_INTEGRITY_CHECK;
	CString csMainDB = csAppPath + SD_DB_FILE_INTEGRITY_CHECK;
	
	AddLogEntry(L"csMainTempDB Path : %s", csMainTempDB);
	AddLogEntry(L"csMainDB Path :%s",  csMainDB);
	AddLogEntry(L"csClientDB Path :%s", csClientDB);
	if(VerifyPatchUpdate((LPCTSTR)csClientDB,csAppPath))
	{
		CreateDirectory(csAppPath + CSystemInfo::m_strTempDBPath, NULL);
		if(CopyFile(csMainDB, csMainTempDB, false))
		{
			AddLogEntry(L"CopyFile = TRUE\n");
			CS2S objMainDB(false, true);
			CS2S objClientDB(false, true);

			if(objMainDB.Load(csMainTempDB))
			{
				AddLogEntry(L"Load DB = TRUE\n");
				LPVOID posUserName = objMainDB.GetFirst();
				while(posUserName)
				{
					LPTSTR strFileName = NULL;
					LPTSTR strDBMD5 = NULL;
					objMainDB.GetKey(posUserName, strFileName);
					objMainDB.GetData(posUserName, strDBMD5);
					CString csTemp(strFileName);
					AddLogEntry(L" Before Merging File Name : ^%s^ And MD5 : ^%s^", strFileName, strDBMD5);

					posUserName = objMainDB.GetNext(posUserName);
				}
			}

			objMainDB.RemoveAll();
			if(objMainDB.Load(csMainTempDB) && objClientDB.Load(csClientDB))
			{
				AddLogEntry(L"Load DB = TRUE\n");
				LPVOID posUserName = objClientDB.GetFirst();
				while(posUserName)
				{
					LPTSTR strFileName = NULL;
					LPTSTR strDBMD5 = NULL;
					objClientDB.GetKey(posUserName, strFileName);
					AddLogEntry(L"FileName : ^%s^\n", strFileName);
					objClientDB.GetData(posUserName, strDBMD5);
					AddLogEntry(L"DBMD5 : ^%s^\n", strDBMD5);
					AddLogEntry(L"DelItem : ^%s^\n", strFileName);
					if(objMainDB.DeleteItem(strFileName))
					{
						AddLogEntry(L"DeleteItem Success Appned for FileName : ^%s^\n", strFileName);
						objMainDB.AppendItem(strFileName, strDBMD5);
					}
					else
					{
						objMainDB.AppendItem(strFileName, strDBMD5);
						AddLogEntry(L"Delete Item Failed for FileName : ^%s^\n", strFileName);
					}
					posUserName = objClientDB.GetNext(posUserName);
				}
				AddLogEntry(L"Saving DB\n");
				objMainDB.Balance();
				objMainDB.Save(csMainTempDB);
				
				objMainDB.RemoveAll();
				if(objMainDB.Load(csMainTempDB))
				{
					AddLogEntry(L"Load DB = TRUE\n");
					LPVOID posUserName = objMainDB.GetFirst();
					while(posUserName)
					{
						LPTSTR strFileName = NULL;
						LPTSTR strDBMD5 = NULL;
						objMainDB.GetKey(posUserName, strFileName);
						objMainDB.GetData(posUserName, strDBMD5);
						CString csTemp(strFileName);
						AddLogEntry(L" After Merging File Name : ^%s^ And MD5 : ^%s^", strFileName, strDBMD5);
						if(csTemp.CompareNoCase(ACTMON_DRIVE_TITLE) == 0 ||
						   csTemp.CompareNoCase(MAXPROTECTOR_DRIVE_FILENAME) == 0	)
						{
							AddLogEntry(L"Deleting Item: ^%s^", csTemp);
							objMainDB.DeleteItem(strFileName);
						}

						posUserName = objMainDB.GetNext(posUserName);
					}
				}
				AddLogEntry(L"Saving DB\n");
				objMainDB.Balance();
				objMainDB.Save(csMainTempDB);

				if(VerifyPatchUpdate((TCHAR *)(LPCTSTR)csMainTempDB,csAppPath) && CopyFile(csMainTempDB,
					csMainDB, false))
				{
					AddLogEntry(L"Merging FIC Success");
					bRet = true;
				}
				else
				{
					AddLogEntry(L"Merging FIC Failed");
				}
			}
			else
			{
				AddLogEntry(L"LoadDB Failed Failed");
			}
		}
		else
		{
			AddLogEntry(L"Copy File Failed Failed");
		}
	}
	else
	{
		AddLogEntry(L"VerifyPatchUpdate Failed");
	}

	return bRet;
}

bool CCommonFunctions::VerifyPatchUpdate(LPCTSTR szDBPath,CString csAppPath)
{
	AddLogEntry(L"In VerifyPatchUpdate :%s ", (CString )szDBPath);
	CCommonFileIntegrityCheck objCommonFileIntegrityCheck(szDBPath);
	return objCommonFileIntegrityCheck.CheckBinaryFileMD5(csAppPath);

}

bool CCommonFunctions::CopyAndCryptFileDatabase(LPCTSTR szOrgFile, LPCTSTR szNewFile, DWORD dwMaxMemLimit, DWORD dwStartOffset)
{
	try
	{
		return CopyAndCryptFile(szOrgFile, szNewFile, dwMaxMemLimit, dwStartOffset);
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCommonFunctions::CopyAndCryptFile"));
		return false;
	}
}

bool CCommonFunctions::PauseMaxProtectorDriver(bool bDeleteService)
{
	CMaxProtectionMgr oMaxProtectionMgr;
	if(bDeleteService)
	{
		oMaxProtectionMgr.RemoveProtection();
	}
	else
	{
		oMaxProtectionMgr.PauseProtection();
	}
	return true;
}

void CCommonFunctions::PostMessageToProtection(UINT message, WPARAM wParam, LPARAM lParam)
{
	OutputDebugString(L"***** In PostMessageToProtection()!");
	CMaxCommunicator objComm(_NAMED_PIPE_TRAY_TO_ACTMON, true);

	SHARED_ACTMON_SWITCH_DATA ActMonSwitchData = {0};
	ActMonSwitchData.dwMonitorType = wParam;
	ActMonSwitchData.bStatus = lParam;
	ActMonSwitchData.bShutDownStatus = false;

	OutputDebugString(L"***** Before SendData()!");
	if(objComm.SendData(&ActMonSwitchData, sizeof(SHARED_ACTMON_SWITCH_DATA)))
	{
		OutputDebugString(L"***** Before ReadData()!");
		if(!objComm.ReadData((LPVOID)&ActMonSwitchData, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			OutputDebugString(L"***** ReadData() Failed!");
			return;
		}
	}
	OutputDebugString(L"***** After SendData()!");
}

BOOL CCommonFunctions::CheckForBartPE()
{
	HDESK       hdesk = NULL;
	HWINSTA     hwinsta = NULL;
	HWINSTA     hwinstaSave = NULL;

	// Save a handle to the caller's current window station.
	if ( (hwinstaSave = GetProcessWindowStation() ) == NULL)
	{
		return FALSE;
	}

	hwinsta = OpenWindowStation(
		_T("winsta0"),                   // the interactive window station 
		FALSE,							// handle is not inheritable
		READ_CONTROL);		// rights to read/write the DACL

	if (hwinsta == NULL) 
	{
		SetProcessWindowStation (hwinstaSave);
		return FALSE;
	}
	// To get the correct default desktop, set the caller's 
	// window station to the interactive window station.
	if (!SetProcessWindowStation( hwinsta ))
	{
		CloseWindowStation(hwinsta);
		SetProcessWindowStation (hwinstaSave);
		return FALSE;
	}
	
	// Get a handle to the interactive desktop. default winlogon
	hdesk = OpenDesktop(
		_T("winlogon"),    // the interactive window station 
		1,				// no interaction with other desktop processes
		FALSE,			// handle is not inheritable
		READ_CONTROL | DESKTOP_READOBJECTS);	// request the rights to read and write the DACL

	if (hdesk == NULL) 
	{
		CloseWindowStation( hwinsta );
		SetProcessWindowStation (hwinstaSave);
		return FALSE;
	}
	CloseDesktop(hdesk);
	CloseWindowStation( hwinsta );
	SetProcessWindowStation (hwinstaSave);
	return TRUE;
}

void CCommonFunctions::CheckAndEnableFirewallSetting()
{
	CRemoveProductsDlg objDlg;
	objDlg.ConfigureFWDuringUninstallation();

}

void CCommonFunctions::ConfigureFirewallInstallation(CString csAppPath, int iType)
{
	CMSIOperations oMSIOperations;
	OutputDebugString(L"Firewall App Path: " + csAppPath);
	CExecuteProcess oExecuteProcess;
	switch(iType)
	{
	case 1:
		{
			OutputDebugString(L"Launch: " + csAppPath + L"DriverMgr.exe INSTALL");
			oExecuteProcess.ExecuteCommandWithWait(csAppPath + L"DriverMgr.exe", L"-INSTALL");	
		}
		break;
	case 2:
		{
			OutputDebugString(L"Launch: " + csAppPath + L"DriverMgr.exe UNINSTALL");
			oExecuteProcess.ExecuteCommandWithWait(csAppPath + L"DriverMgr.exe", L"-UNINSTALL");
		}
		break;
	case 3:
		{
			OutputDebugString(L"Launch: " + csAppPath + L"DriverMgr.exe REINSTALL");
			oExecuteProcess.ExecuteCommandWithWait(csAppPath + L"DriverMgr.exe", L"-REINSTALL");
		}
		break;
	case 4:
		{
			OutputDebugString(L"Launch: " + csAppPath + L"DriverMgr.exe AFTERREINSTALL");
			oExecuteProcess.ExecuteCommandWithWait(csAppPath + L"DriverMgr.exe", L"-AFTERREINSTALL");
		}
	case 5:
		{
			oMSIOperations.InstallFirewallMSI(csAppPath);
		}
	case 6:
		{
			
			//CCPUInfo oCPUInfo;
			//BOOL bIs64bit = oCPUInfo.isOS64bit();
			//if(bIs64bit)
			//	oMSIOperations.CleanUpMSIComponents();

			oMSIOperations.ReInstallFirewallMSI(csAppPath);
			break;
		}
		break;
	}
}

void CCommonFunctions::KillProcesses(CStringArray& arrProcesses)
{
	CEnumProcess oEnumProcess;
	CString csFileName;
	for(int i = 0; i < arrProcesses.GetCount(); i++)
	{
		csFileName = arrProcesses.GetAt(i);
		csFileName.MakeLower();
		oEnumProcess.IsProcessRunning(csFileName, true, false);
	}
}

bool CCommonFunctions::ShellExecuteApp(CString csAppPath,UINT uType)
{
	bool bRet = false;
	CString csCurrentDir;
	CString csParam;
	CString csAppName;
	CString csAppFolder;
	CCPUInfo oCpuInfo;
	bool bIs64Bit = (oCpuInfo.isOS64bit()?true:false);
	switch(uType)
	{
		
	case 1:
		{
			csParam = L"/i \"" + csAppPath + L"\"" + L" /qn";
			csAppName = L"msiexec.exe";
			bRet =true;
			break;
		}
	case 2:
		{
			csCurrentDir = csAppPath;
			int iPos = csCurrentDir.ReverseFind('\\');
			csCurrentDir = csCurrentDir.Mid(0, iPos+ 1);
			csParam = L" /install /FW";
			csAppName = csAppPath.Mid(iPos + 1);
			break;
		}
	case 3:
		{
			//csParam = L"/x \"" + csAppPath + L"\"" + L" /qn";
			//csAppName = L"msiexec.exe";
			bRet =true;
			break;
		}
	case 4:
		{
			csCurrentDir = csAppPath;
			int iPos = csCurrentDir.ReverseFind('\\');
			csCurrentDir = csCurrentDir.Mid(0, iPos+ 1);
			csParam = L" /install /FW /ARVA";
			csAppName = csAppPath.Mid(iPos + 1);
			break;
		}
	case 5:
		{
			int iPos = csAppPath.ReverseFind('\\');
			csAppFolder = csAppPath.Mid(0, iPos);
			OutputDebugString(L"App Folder" + csAppFolder);
			csParam = L"/i \"" + csAppPath + L"\"" + L" REINSTALL=ALL REINSTALLMODE=vsamu /norestart /qn TARGETDIR=\"" + csAppFolder + L"\"";
			OutputDebugString(L"Parameter : " + csParam);
			csAppName = L"msiexec.exe";
			bRet =true;
			break;
		}
	}
	
	ShellExecute( NULL,  L"open",csAppName,csParam,csCurrentDir,SW_NORMAL | SW_HIDE);
		
	if (uType == 1 )
	{
		CRegistry objReg;
		HKEY hKey = NULL;
		BYTE byRegData[1] = {0x00};
		if(bIs64Bit)
		{
			objReg.CreateKey(_T("SOFTWARE\\Wow6432Node\\SBAMSvc"),hKey,HKEY_LOCAL_MACHINE);
			objReg.Set(_T("SOFTWARE\\Wow6432Node\\SBAMSvc"), _T("Product"), _T("AntiVirus"), HKEY_LOCAL_MACHINE);
		}
		else
		{
			objReg.CreateKey(_T("SOFTWARE\\SBAMSvc"),hKey,HKEY_LOCAL_MACHINE);
			objReg.Set(_T("SOFTWARE\\SBAMSvc"), _T("Product"), _T("AntiVirus"), HKEY_LOCAL_MACHINE);
		}

		if(CSystemInfo::m_bIs2kSevers || CSystemInfo::m_strOS == W2K)
		{
			objReg.Set(_T("SOFTWARE\\Microsoft\\Driver Signing"), _T("Policy"),byRegData,1,REG_BINARY,HKEY_LOCAL_MACHINE);
			objReg.Set(_T("SOFTWARE\\Microsoft\\Non-Driver Signing"), _T("Policy"),byRegData,1,REG_BINARY,HKEY_LOCAL_MACHINE);
		}
	}
	return bRet;
}

void CCommonFunctions::CleanUp(CString csFolderpath, CString csAppPath, bool bReinstall, bool bMigrate)
{
	OutputDebugString(L"In  CleanUp: ");
	CRemoteService oRemoteService;
	CRegistry  oRegistry;
	CExecuteProcess oExecuteProcess;
	CCPUInfo oCPUInfo;
	BOOL bIs64bit = FALSE;
	bIs64bit = oCPUInfo.isOS64bit();
	if(bIs64bit)
	{
		oRegistry.SetWow64Key(true);
	}

	oRemoteService.DeleteRemoteService(_T("SDManager"));
	
	
}

void CCommonFunctions::ExecuteApplicationAndWaitOnChilds(char * pszAppName, char * pszParam)
{
	HANDLE hJob = 0;
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};
	JOBOBJECT_BASIC_ACCOUNTING_INFORMATION stJobObjInfo = {0};
	char szFullCmdLine[MAX_PATH] = {0};

	hJob = CreateJobObject(0, 0);
	if(NULL == hJob)
	{
		OutputDebugStringA("`````````````````````````CJO() failed");
		return;
	}

	if(pszAppName && pszParam)
	{
		OutputDebugStringA("`````````````````````````both available");
		sprintf_s(szFullCmdLine, sizeof(szFullCmdLine), "\"%s\" %s", pszAppName, pszParam);
	}
	else if(pszAppName)
	{
		OutputDebugStringA("`````````````````````````only appname no args");
		sprintf_s(szFullCmdLine, sizeof(szFullCmdLine), "\"%s\"", pszAppName);
	}
	else
	{
		OutputDebugStringA("`````````````````````````neither app nor args found");
		CloseHandle(hJob);
		return;
	}

	si.cb = sizeof(si);
	if(!CreateProcessA(NULL, szFullCmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
		OutputDebugStringA("`````````````````````````CPA() failed");
		CloseHandle(hJob);
        return;
    }

	if(AssignProcessToJobObject(hJob, pi.hProcess))
	{
		OutputDebugStringA("`````````````````````````APTJO() success");
		ResumeThread(pi.hThread);
		while(QueryInformationJobObject(hJob, JobObjectBasicAccountingInformation, &stJobObjInfo, sizeof(stJobObjInfo), 0))
		{
			if(0 == stJobObjInfo.ActiveProcesses)
			{
				OutputDebugStringA("`````````````````````````no active processes");
				break;
			}

			Sleep(1000 * 5);
		}
	}
	else
	{
		OutputDebugStringA("`````````````````````````APTJO() failed, waiting for max 30min");
		ResumeThread(pi.hThread);
		WaitForSingleObject(pi.hProcess, 1000 * 60 * 30);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(hJob);
	OutputDebugStringA("`````````````````````````Leaving function");
	return;
}

void CCommonFunctions::UnregisterComponents(CString csFilePath)
{
	LPDLLREGISTER lpDllRegisterServer = NULL;
	HMODULE hModule =  NULL;

	hModule = LoadLibrary(csFilePath);
	if(!hModule)
	{
		AddLogEntry(L"###### Failed to load %s", csFilePath);
		return;
	}
	lpDllRegisterServer = (LPDLLREGISTER)GetProcAddress(hModule, "DllUnregisterServer");
	if(lpDllRegisterServer != NULL)
	{
		lpDllRegisterServer();
	}
	FreeLibrary(hModule);
	hModule =  NULL;
}

void CCommonFunctions::HandlingForVirusPatch()
{
	CStringArray arrProcesses;
	CRemoteService oRemoteService;
//	CRegistry oReg;
	DWORD dwVer = 0;
	CCPUInfo objSystem;
	/*if(TRUE == objSystem.isOS64bit())
	{
		oReg.SetWow64Key(true);
	}
	oReg.Get(CSystemInfo::m_csProductRegKey, _T("Win10"), dwVer, HKEY_LOCAL_MACHINE);*/
	if(IsWin10())
	{
		MAX_PIPE_DATA_REG sScanRequest = {0};
		sScanRequest.eMessageInfo = Enable_Stop_WD_PPL;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, true);
		objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		objMaxCommunicator.ReadData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		OutputDebugString(_T("StopWD Win10"));
	}
	oRemoteService.StopRemoteService(MAXWATCHDOG_SVC_NAME, false);
	
	Sleep(15000);
	AddProcessList(arrProcesses, 5);
	KillProcesses(arrProcesses);
}

BOOL CCommonFunctions::CheckForDBVersion(CString csNewVer)
{
	
	
	return TRUE;
}

BOOL CCommonFunctions::ParseInfo(CString csSetupFilePath)
{
	OutputDebugString(L"In ParseSetupInfo");
	OutputDebugString(csSetupFilePath);

	BOOL bRet = FALSE;
	HANDLE hFileHandle = CreateFile(csSetupFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hFileHandle)
	{
		return bRet;
	}

	const int BUFF_SIZE = 0x200;
	BYTE byBuff[BUFF_SIZE] = {0};	
	DWORD dwBytesRead = 0;
	
	::SetFilePointer(hFileHandle, GetFileSize(hFileHandle, NULL) - BUFF_SIZE, 0, FILE_BEGIN);
	if(!ReadFile(hFileHandle, byBuff, BUFF_SIZE, &dwBytesRead, NULL))
	{
		return bRet;
	}
	if(dwBytesRead == 0)
	{
		return bRet;
	}

	const BYTE START_TAG[] = {0x21, 0x53, 0x23};
	const BYTE END_TAG[] = {0x21, 0x45, 0x23};
	bool bFoundStartTag = false;
	DWORD dwValNameLen = 0, dwValDataLen = 0;
	BYTE byTemp[MAX_PATH] = {0};
	TCHAR szValName[MAX_PATH] = {0}, szValData[MAX_PATH] = {0}; 
	
	CRegistry objReg;
	CCPUInfo objSystem;
	if(TRUE == objSystem.isOS64bit())
	{
		objReg.SetWow64Key(true);
	}
	CString csServerVer;
	HKEY hKey = NULL;
	CString csKeyName = L"";
	return bRet;
	csKeyName += TRACKER_KEY;
	objReg.CreateKey(csKeyName, hKey, HKEY_LOCAL_MACHINE);	
	OutputDebugString(csKeyName);
			
	for(DWORD dwOffset = 0; dwOffset < BUFF_SIZE; dwOffset++)
	{
		if(!bFoundStartTag && memcmp(&byBuff[dwOffset], START_TAG, sizeof(START_TAG)) != 0)
		{
			continue;
		}
		if(!bFoundStartTag)
		{
			bFoundStartTag = true;
			dwOffset += sizeof(START_TAG) + 1;
		}
		if(memcmp(&byBuff[dwOffset], END_TAG, sizeof(END_TAG)) == 0)
		{
			bRet = TRUE;
			break;
		}

		dwValNameLen = 0;
		while(byBuff[dwOffset + dwValNameLen] != '=')
		{
			dwValNameLen++;
		}
		memcpy(byTemp, &byBuff[dwOffset], dwValNameLen);
		byTemp[dwValNameLen]= '\0';
		_stprintf_s(szValName, MAX_PATH, L"%S", byTemp);

		dwValDataLen = 0;
		while(byBuff[dwOffset + dwValNameLen + dwValDataLen + 1] != 0x0A)
		{
			dwValDataLen++;
		}
		memcpy(byTemp, &byBuff[dwOffset + dwValNameLen + 1], dwValDataLen);
		byTemp[dwValDataLen]= '\0';
		_stprintf_s(szValData, MAX_PATH, L"%S", byTemp);
		
		if(_memicmp(szValName, L"DLY", 3) == 0)
		{
			int iVal = _tstoi(szValData);
			objReg.Set(csKeyName, TRACKER_DELAY_START, iVal, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"BI", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_QUERY, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"UL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_UNISTALL_URL, szValData, HKEY_LOCAL_MACHINE);
		}		
		else if(_memicmp(szValName, L"SL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_SUPPORT_URL, szValData, HKEY_LOCAL_MACHINE);
		}		
		else if(_memicmp(szValName, L"PL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_HOMEPAGE_URL, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"WL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_WELCOME_PAGE, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"GL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_BUYNOW_URL, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"FL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_SETUP_NAME, szValData, HKEY_LOCAL_MACHINE);
		}	
		
		OutputDebugString(szValName);
		OutputDebugString(szValData);
		dwOffset += dwValNameLen + dwValDataLen + 1;
	}

	time_t tim = time(NULL);
	objReg.Set(csKeyName, TRACKER_INSTALL_DATE, tim, HKEY_LOCAL_MACHINE);

	GUID guid;
	CoCreateGuid(&guid); 
	
	const CComBSTR guidBstr(guid);  // Converts from binary GUID to BSTR
	CString guidStr(guidBstr); // Converts from BSTR to appropriate string, ANSI
		
	guidStr.Remove('{');
	guidStr.Remove('}');
	objReg.Set(csKeyName, TRACKER_MACHINE_GUID, guidStr, HKEY_LOCAL_MACHINE);
	
	CString csBuyNowLink = _T("");
	objReg.Get(csKeyName, TRACKER_BUYNOW_URL, csBuyNowLink, HKEY_LOCAL_MACHINE);
	csBuyNowLink.Replace(_T("%GID%"), guidStr);
	objReg.Set(csKeyName, TRACKER_BUYNOW_URL, csBuyNowLink, HKEY_LOCAL_MACHINE);
	
	GetOSVersion(szValData);
	objReg.Set(csKeyName, TRACKER_OS, szValData, HKEY_LOCAL_MACHINE);

	CString csTemp;
	DWORD dwBuffLen = MAX_PATH;
	TCHAR szCurrentUser[MAX_PATH] = {0};
	GetUserName(szCurrentUser, &dwBuffLen);
	objReg.Set(csKeyName, TRACKER_USER, szCurrentUser, HKEY_LOCAL_MACHINE);
	//csTemp.Format(L"##### Logged In User: %s\n", szCurrentUser);
	//OutputDebugString(csTemp);

	return bRet;
}

void CCommonFunctions::GetOSVersion(LPTSTR szOSVer)
{
	SYSTEM_INFO si;
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	BOOL bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi);

	_tcscpy_s(szOSVer, MAX_PATH, UNTRACTED);

	if(bOsVersionInfoEx == NULL ) 
	{
		return;
	}

	// Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.	
	typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
	PGNSI pGNSI = (PGNSI) GetProcAddress(
		GetModuleHandle(TEXT("kernel32.dll")), 
		"GetNativeSystemInfo");
	if(NULL != pGNSI)
		pGNSI(&si);
	else GetSystemInfo(&si);	

	if ( VER_PLATFORM_WIN32_NT == osvi.dwPlatformId && 
		osvi.dwMajorVersion > 4 )
	{
		if ( osvi.dwMajorVersion == 6  && osvi.wProductType == VER_NT_WORKSTATION )
		{
			if( osvi.dwMinorVersion == 0 )
			{
				if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN_VISTA_64BIT);
				}
				else 
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN_VISTA_32BIT);
				}
			}				
			if ( osvi.dwMinorVersion == 1 )
			{				
				if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN7_64BIT);
				}
				else
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN7_32BIT);
				}
			}
			if(osvi.dwMinorVersion == 2 )
			{
				if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN8_64BIT);
				}
				else
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN8_32BIT);
				}
			}
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION &&
				si.wProcessorArchitecture== PROCESSOR_ARCHITECTURE_AMD64)
			{
				_tcscpy_s(szOSVer, MAX_PATH, WINXP_64BIT);
			}			
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
		{
			_tcscpy_s(szOSVer, MAX_PATH, WINXP_32BIT);
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
		{
			_tcscpy_s(szOSVer, MAX_PATH, WIN_2000);
		}		
	}
	return; 
}

BOOL CCommonFunctions::EnableAutoScnAndSchedular()
{
	CSystemInfo oSystemInfo;
	CRegistry oRegistry;
	oRegistry.SetWow64Key(oSystemInfo.m_bIsOSX64);

	if(oRegistry.ValueExists(oSystemInfo.m_csProductRegKey, _T("LU_Last"), HKEY_LOCAL_MACHINE) == false)
	{
		ULONG64 ulCurTime;
		_time64((__time64_t*)&ulCurTime);
		oRegistry.Set(oSystemInfo.m_csProductRegKey, _T("LU_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY,  HKEY_LOCAL_MACHINE);
	}

	CString csTemp = _T("");
	oRegistry.Get(oSystemInfo.m_csProductRegKey, _T("APPDATA"), csTemp, HKEY_LOCAL_MACHINE);
	if(csTemp.GetLength() == 0)
	{
		WCHAR szBuff[1024] = {0};
		SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, szBuff);
		if(szBuff[0])
		{
			OutputDebugString(_T("*** Setting APPDATA"));
			OutputDebugString(szBuff);
			oRegistry.Set(oSystemInfo.m_csProductRegKey, _T("APPDATA"), szBuff, HKEY_LOCAL_MACHINE);
		}
	}
	else
	{
		CString csTemp2 = _T("");
		oRegistry.Get(oSystemInfo.m_csProductRegKey, _T("APPDATA_LOCAL"), csTemp2, HKEY_LOCAL_MACHINE);
		if(csTemp2.IsEmpty())
		{
			int iPos = 0;
			int iLen = 0;
			iPos = csTemp.ReverseFind(_T('\\'));
			iLen = csTemp.GetLength();
			CString csLastPath = csTemp.Mid(iPos, (iLen - iPos));
			CString csFolder = csTemp.Mid(0, iLen - (iLen - iPos));
			OutputDebugString(_T("*** Setting APPDATA_LOCAL 1"));
			OutputDebugString(_T("Last Path = ") + csLastPath);
			OutputDebugString(_T("Folder = ") + csFolder);
			if(csLastPath.Find(_T("Roaming")) != -1)
			{
				//Windows Vista onwards
				csFolder += _T("\\Local");
			}
			else
			{
				//Windows XP
				csFolder += _T("\\Local Settings\\Application Data");			
			}
			oRegistry.Set(oSystemInfo.m_csProductRegKey, _T("APPDATA_LOCAL"), csFolder, HKEY_LOCAL_MACHINE);
		}
	}
	
	csTemp = _T("");
	oRegistry.Get(oSystemInfo.m_csProductRegKey, _T("APPDATA_LOCAL"), csTemp, HKEY_LOCAL_MACHINE);
	if(csTemp.IsEmpty())
	{
		WCHAR szBuff[1024] = {0};
		SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, szBuff);
		if(szBuff[0])
		{
			OutputDebugString(_T("*** Setting APPDATA_LOCAL 2"));
			OutputDebugString(szBuff);
			oRegistry.Set(oSystemInfo.m_csProductRegKey, _T("APPDATA_LOCAL"), szBuff, HKEY_LOCAL_MACHINE);
		}
	}

	DWORD dwValue = 0;
	oRegistry.Get(oSystemInfo.m_csProductRegKey, QUARANTINECNT, dwValue, HKEY_LOCAL_MACHINE);
		
	if(!dwValue)
	{
		//User is Registered
		OutputDebugString(_T("####  Removing Schedular and Autoscan"));
		dwValue = 0;
		if(oRegistry.Set(oSystemInfo.m_csProductRegKey, AUAUTOSCAN, dwValue, HKEY_LOCAL_MACHINE))
			OutputDebugString(_T("####  AutoScan Flag set to 0"));

		CString csTime = _T(""), csScheduleDrives = _T("");
		oRegistry.Get(oSystemInfo.m_csSchedulerRegKey, _T("Time"), csTime, HKEY_LOCAL_MACHINE);
		oRegistry.Get(oSystemInfo.m_csSchedulerRegKey, _T("ScheduleDrives"), csScheduleDrives, HKEY_LOCAL_MACHINE);

		//We had set this to 11:00 AM
		if(csTime.CompareNoCase(_T("11:00")) == 0)
		{
			//We had set this as Blank
			if(csScheduleDrives.IsEmpty())
			{
				if(oRegistry.DeleteKey(oSystemInfo.m_csProductRegKey, _T("SCHEDULE_INFO"), HKEY_LOCAL_MACHINE))
				{
					OutputDebugString(_T("####  SCHEDULE_INFO key deleted successfully!"));
					return TRUE;
				}
			}
		}
	}	

	return FALSE;
}

BOOL CCommonFunctions::PauseForDataBasePatch()
{
	OutputDebugString(_T("****** Before StopWDService"));
	StopWDService();
	OutputDebugString(_T("****** After StopWDService"));

	OutputDebugString(_T("****** Before Killing AuDBServer.exe"));

	CStringArray csArrProc;
	csArrProc.Add(_T("AuDBServer.exe"));
	KillProcesses(csArrProc);
	OutputDebugString(_T("****** After Killing AuDBServer.exe"));

	return true;

}

BOOL CCommonFunctions::CheckForDataBaseVersion(CString csNewVer)
{
	OutputDebugString(L"In CheckForDataBaseVersion");
	CRegistry objReg;
	BOOL bRet = FALSE;
	CString csOldVer;
	
	CRegistry oReg;
	CString csRegKey = _T("");
	if(oReg.KeyExists(ULTRAAV_REG_KEY, HKEY_LOCAL_MACHINE))
		csRegKey = ULTRAAV_REG_KEY;
	
	if(csRegKey.IsEmpty())
		OutputDebugString(L"csRegKey is EMPTY!");
	else
		OutputDebugString(csRegKey);

	objReg.Get(csRegKey, _T("DatabaseVersionNo"), csOldVer, HKEY_LOCAL_MACHINE);
	long lNewVersionNo = 0, lOldServerVersion = 0 ;
	csNewVer.Replace(L".",L"");
	csOldVer.Replace(L".",L"");
	lNewVersionNo = _ttol(csNewVer);
	lOldServerVersion = _ttol(csOldVer);
	
	CString csTemp;
	csTemp.Format(L"New Version : %d, Old Version : %d",lNewVersionNo,lOldServerVersion);
	OutputDebugString(csTemp);
	if(lNewVersionNo == lOldServerVersion)
	{
		OutputDebugString(L"Returning = False");
		bRet = FALSE;
	}
	else if (lNewVersionNo > lOldServerVersion)
 	{
		OutputDebugString(L"Returning > TRUE");
		bRet = TRUE;		
	}
	
	return bRet;
}

BOOL CCommonFunctions::CheckForValidProductToProceed()
{
	return FALSE;
}
void CCommonFunctions::RemoveServiceKeys(LPCTSTR szName)
{
	CRegistry m_objReg;
	CCPUInfo obj;
	if(obj.isOS64bit())
	{
		m_objReg.SetWow64Key(true);
	}
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Services\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Enum\\Root\\LEGACY_")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Enum\\Root\\LEGACY_")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Enum\\Root\\LEGACY_")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Enum\\Root\\LEGACY_")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Enum\\Root\\LEGACY_")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Enum\\Root\\LEGACY_")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Enum\\Root\\LEGACY_")) + szName);

	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Network\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Network\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Network\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Network\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Network\\")) + szName);
	m_objReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Network\\")) + szName);
}
BOOL CCommonFunctions::CheckCleanLocalDB()
{
	BOOL bRet = FALSE;
	CCPUInfo objCpuInfo;
	CString csAppDataPath = objCpuInfo.GetAllUserAppDataPath();
	CStringArray csArrAppData;
	csArrAppData.Add(csAppDataPath+ CSystemInfo::m_csAppPathProdName);
	CString csTempPath;
	BOOL bMoreFiles = FALSE;
	for(int i=0; i < csArrAppData.GetCount(); i++)
	{
		CFileFind objFinder;
		csTempPath = csArrAppData.ElementAt(i) + _T("\\*");
		bMoreFiles = objFinder.FindFile(csTempPath);
		while(bMoreFiles)
		{
			bMoreFiles = objFinder.FindNextFile();
			if(objFinder.IsDirectory() || objFinder.IsDots())
			{
				continue;
			}
			else
			{
				CString csFilePath = objFinder.GetFilePath();
				CString csExt = csFilePath.Right(4);
				if(csExt.CompareNoCase(_T(".txt")) == 0)
				{
					DeleteFile(csFilePath);
				}
			}
		}
		objFinder.Close();

	}
	return bRet;
}

/*-----------------------------------------------------------------------------
Function		: Is64bitOSEx
In Parameters	:
Out Parameters	:
Purpose			: To check whether operating system is 64 bit and do the operations accordingly
Author		`	: Milind Shete
-----------------------------------------------------------------------------*/
bool CCommonFunctions::Is64bitOSEx(CString csDownLoadLink,  BOOL bIs64Setup, CString csProductName,BOOL bShowMsgBox)
{
	try
	{
		CCPUInfo objSystem;
		CString csOS = objSystem.GetOSVerTag();
		/*CMessageBox objMessaageBox;
		objMessaageBox.m_Title = csProductName;*/
		BOOL bOs64bit = objSystem.isOS64bit();
		if(bOs64bit == TRUE)
		{
			if(bIs64Setup == false)
			{	
				/*objMessaageBox.m_Text.LoadStringW(IDS_OS_COMPAT_MSG);
				objMessaageBox.m_Link = csDownLoadLink;
				if(bShowMsgBox != false)
					objMessaageBox.DoModal();*/
				return true;
			}
			else
			{
			}
		}
		else if(bOs64bit == FALSE)
		{
			if(bIs64Setup || csOS == W98 || csOS == WME)
			{
				/*objMessaageBox.m_Text.LoadStringW(IDS_32_OPERATING_SYSTEM_MSG);
				if(bIs64Setup == TRUE)
				{
					objMessaageBox.m_Link = csDownLoadLink;
				}
				if(bShowMsgBox != false)
					objMessaageBox.DoModal();*/
				return true;
			}
		}
		return false;
	}
	catch(...)
	{
		return true;
	}
}

/*-------------------------------------------------------------------------------------
Function		: NetFilterFirewall
Out Parameters	: BOOL
Purpose			: To check Netfilter is present and is it XP system.
Author			: Ravi.
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::NetFilterFirewall(CString csAppPath)
{
	CMSIOperations oMSIOperations;
	oMSIOperations.UninstallFirewallSetup(csAppPath);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: WinDefendSrvStop
Out Parameters	: BOOL
Purpose			: To disable WindDefender.
Author			: Ravi.
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::WinDefendSrvStop(int iOldVer, int iDefendServ)
{
	DWORD dwStartType = 0;
	/*CRegistry objReg;
	CRemoteService objRemoteSrc;

	if(iOldVer == 1)
	{
		DWORD dwValMps = 0;
		DWORD dwValDefend = 0;
		objReg.Get(_T("SYSTEM\\CurrentControlSet\\Services\\MpsSvc"), _T("Start"), dwValMps, HKEY_LOCAL_MACHINE);
		
		if(dwValMps == 4)
		{
			objReg.Set(_T("SYSTEM\\CurrentControlSet\\Services\\MpsSvc"), _T("Start"), 2, HKEY_LOCAL_MACHINE);
			ChangeServiceStartType(L"MpsSvc", NULL, 2);
			Sleep(10);
			objRemoteSrc.StopRemoteService(L"MpsSvc", false);
		}
	}
	
	objReg.Set(_T("SYSTEM\\CurrentControlSet\\Services\\WinDefend"), _T("Start"), 3, HKEY_LOCAL_MACHINE);
	ChangeServiceStartType(L"WinDefend", NULL, 3);
	Sleep(10);
	objRemoteSrc.StopRemoteService(L"WinDefend", false);*/



	return FALSE;
}
bool CCommonFunctions::ChangeServiceStartType(LPCTSTR sDriverName, LPCTSTR sDriverPath, DWORD dwStartType)
{
	bool bRetVal = false;
	BOOL bRet = FALSE;

	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return bRetVal;
	}
	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService =::OpenService(hSCM, sDriverName, SERVICE_ALL_ACCESS);
	bRet = ::ChangeServiceConfig(hService,16, dwStartType, SERVICE_ERROR_NORMAL,sDriverPath, NULL, NULL, NULL, NULL, NULL, NULL);
	if(!bRet)
	{
		CString csTemp;
		csTemp.Format(L"ChangeServiceConfig Falied with Errpr Code :%d", GetLastError());
		OutputDebugString(csTemp);
	}
	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);
	return bRetVal;
}
BOOL CCommonFunctions::WinELamDriver()
{
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.InstallElamDriver();
	return TRUE;
}
bool CCommonFunctions::IsWin10()
{
	CRegistry objReg;
	CCPUInfo objSystem;
	if(TRUE == objSystem.isOS64bit())
	{
		objReg.SetWow64Key(true);
	}
	CString csRegKey = L"";
	if(objReg.KeyExists(ULTRAAV_REG_KEY,HKEY_LOCAL_MACHINE) == true)
	{
		csRegKey = ULTRAAV_REG_KEY;
	}
	DWORD dwVer=0;
	objReg.Get(csRegKey, _T("Win10"), dwVer, HKEY_LOCAL_MACHINE);
	if(dwVer == 1)
	{
		return true;
	}
	return false;
}

bool CCommonFunctions::CreateRansomBackupFolderEx()
{
	CSystemInfo objSystem;
	CCPUInfo oCpuInfo;
	bool bIs64Bit = (oCpuInfo.isOS64bit() ? true : false);

	CRegistry oReg;
	if (bIs64Bit)
	{
		oReg.SetWow64Key(true);
	}

	//ChangePermission(L"SOFTWARE\\UltraAV", HKEY_LOCAL_MACHINE);
	CString csAppPath;
	CString csCurrentMDB;
	oReg.Get(L"SOFTWARE\\UltraAV", _T("AppFolder"), csAppPath, HKEY_LOCAL_MACHINE);
	WCHAR csWinDir[MAX_PATH] = _T("");
	UINT uRetVal = 0;
	TCHAR	szDriveStrings[MAX_PATH] = { 0x00 };
	DWORD	dwBuffLen = MAX_PATH;
	TCHAR* pDummy = NULL;
	GetLogicalDriveStrings(dwBuffLen, szDriveStrings);
	pDummy = szDriveStrings;
	int iCount = 0;
	DWORD dwData = 0;
	TCHAR	szDrive[0x10] = { 0x00 };
	CDirectoryManager objDirectoryMgr;
	while (pDummy)
	{
		_stprintf_s(szDrive, 0x10, L"%s", pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}
		DWORD dwDriveType = GetDriveType(szDrive);
		if (GetDriveType(szDrive) == DRIVE_FIXED)
		{
			CString csFolder;
			csFolder.Format(_T("%s!-"), szDrive);
			CreateDirectory(csFolder, NULL);
			SetFileAttributes(csFolder, FILE_ATTRIBUTE_HIDDEN);
			objDirectoryMgr.MaxCopyDirectory(csFolder, csAppPath, true, true);

			csFolder.Format(_T("%s~!-"), szDrive);
			CreateDirectory(csFolder, NULL);
			SetFileAttributes(csFolder, FILE_ATTRIBUTE_HIDDEN);
			objDirectoryMgr.MaxCopyDirectory(csFolder, csAppPath, true, true);

			CString		csScapeGoatFile;
			csScapeGoatFile.Format(L"%s\\Data18.doc", csAppPath);
			csFolder.Format(_T("%s!-SCPGT01.DOC"), szDrive);
			CopyFile(csScapeGoatFile, csFolder, false);
			SetFileAttributes(csFolder, FILE_ATTRIBUTE_HIDDEN);

			csScapeGoatFile.Format(L"%s\\Data21.xlsx", csAppPath);
			csFolder.Format(_T("%s!-SCPGT02.XLSX"), szDrive);
			CopyFile(csScapeGoatFile, csFolder, false);
			SetFileAttributes(csFolder, FILE_ATTRIBUTE_HIDDEN);

			csScapeGoatFile.Format(L"%s\\Data26.jpeg", csAppPath);
			csFolder.Format(_T("%s!-SCPGT03.JPEG"), szDrive);
			CopyFile(csScapeGoatFile, csFolder, false);
			SetFileAttributes(csFolder, FILE_ATTRIBUTE_HIDDEN);

			csScapeGoatFile.Format(L"%s\\Data28.pdf", csAppPath);
			csFolder.Format(_T("%s!-SCPGT04.PDF"), szDrive);
			CopyFile(csScapeGoatFile, csFolder, false);
			SetFileAttributes(csFolder, FILE_ATTRIBUTE_HIDDEN);
		}

		iCount++;
		pDummy += (_tcslen(szDriveStrings) + 0x01);
	}
	return true;
}

bool CCommonFunctions::CreateRansomBackupFolder(CString csAppPath)
{

	WCHAR csWinDir[MAX_PATH] = _T("");
	UINT uRetVal = 0;
	TCHAR	szDriveStrings[MAX_PATH] = {0x00};
	DWORD	dwBuffLen = MAX_PATH;
	TCHAR	*pDummy = NULL;
	GetLogicalDriveStrings(dwBuffLen,szDriveStrings);
	pDummy = szDriveStrings;
	int iCount= 0;
	DWORD dwData = 0;
	TCHAR	szDrive[0x10] = {0x00};
	CDirectoryManager objDirectoryMgr;
	while(pDummy)
	{
		_stprintf_s(szDrive,0x10,L"%s",pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}
		DWORD dwDriveType = GetDriveType(szDrive);
		if(GetDriveType(szDrive) == DRIVE_FIXED)
		{
			CString csFolder;
			csFolder.Format(_T("%s!-"),szDrive);
			CreateDirectory(csFolder, NULL);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);
			objDirectoryMgr.MaxCopyDirectory(csFolder,csAppPath,true,true);

			csFolder.Format(_T("%s~!-"),szDrive);
			CreateDirectory(csFolder, NULL);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);
			objDirectoryMgr.MaxCopyDirectory(csFolder,csAppPath,true,true);

			CString		csScapeGoatFile;
			csScapeGoatFile.Format(L"%s\\Data18.doc",csAppPath);
			csFolder.Format(_T("%s!-SCPGT01.DOC"),szDrive);
			CopyFile(csScapeGoatFile,csFolder,false);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);

			csScapeGoatFile.Format(L"%s\\Data21.xlsx",csAppPath);
			csFolder.Format(_T("%s!-SCPGT02.XLSX"),szDrive);
			CopyFile(csScapeGoatFile,csFolder,false);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);

			csScapeGoatFile.Format(L"%s\\Data26.jpeg",csAppPath);
			csFolder.Format(_T("%s!-SCPGT03.JPEG"),szDrive);
			CopyFile(csScapeGoatFile,csFolder,false);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);

			csScapeGoatFile.Format(L"%s\\Data28.pdf",csAppPath);
			csFolder.Format(_T("%s!-SCPGT04.PDF"),szDrive);
			CopyFile(csScapeGoatFile,csFolder,false);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);
		}
		
		iCount++;
		pDummy+=(_tcslen(szDriveStrings) + 0x01);
	}
	return true;
}


bool CCommonFunctions::CleanUpService(LPCTSTR szName)
{
	CRemoteService objRemoteSrc; 
	CRegistry oReg;
	objRemoteSrc.DeleteRemoteService(szName);

	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Services\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Enum\\Root\\LEGACY_")) + szName);

	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Network\\")) + szName);
	return true;
}
bool CCommonFunctions::SetIniRegistries()
{
	//AfxMessageBox(L"Inside SetIniRegistries()");
	CSystemInfo objSystem;
	CCPUInfo oCpuInfo;
	bool bIs64Bit = (oCpuInfo.isOS64bit() ? true : false);

	CRegistry oReg;
	if (bIs64Bit)
	{
		oReg.SetWow64Key(true);
	}

	//RegistryGrantAll();
	//ChangePermission(L"SOFTWARE\\UltraAV", HKEY_LOCAL_MACHINE);
	CString csIniPath;
	CString csCurrentMDB;
	oReg.Get(L"SOFTWARE\\UltraAV", _T("AppFolder"), csIniPath, HKEY_LOCAL_MACHINE);
	CString csIniFullPath = csIniPath + L"ver.txt";
	TCHAR szData[MAX_PATH] = { 0 };
	GetPrivateProfileString(L"Version", L"ProductVersionNo", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("ProductVersionNo"), szData, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(L"Version", L"DatabaseVersionNo", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("DatabaseVersionNo"), szData, HKEY_LOCAL_MACHINE);
	csCurrentMDB = csIniPath + L"Data\\" + CString(szData) + L"\\";
	oReg.Set(L"SOFTWARE\\UltraAV", _T("CurrentMDB"), csCurrentMDB, HKEY_LOCAL_MACHINE);

	GetPrivateProfileString(L"Version", L"VirusVersionNo", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("VirusVersionNo"), szData, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(L"Version", L"FirstPriorityVersionNo", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("FirstPriorityVersionNo"), szData, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(L"Version", L"UpdateVersion", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("UpdateVersion"), szData, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(L"Version", L"DatabaseMiniVersionNo", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("DatabaseMiniVersionNo"), szData, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(L"Version", L"MLearnVersion", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("MLearnVersion"), szData, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(L"Version", L"YrScanVersion", _T(""), szData, MAX_PATH, csIniFullPath);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("YrScanVersion"), szData, HKEY_LOCAL_MACHINE);


	COleDateTime objOleDateTime;
	objOleDateTime = objOleDateTime.GetCurrentTime();
	CString csDate;
	CString csLiveUpdateDate;
	CCPUInfo objCPUInfo;
	csLiveUpdateDate.Format(L"%d-%s-%d", objOleDateTime.GetDay(), objCPUInfo.GetMonthName(objOleDateTime.GetMonth()),
		objOleDateTime.GetYear());
	csDate.Format(_T("%d/%d/%d"), objOleDateTime.GetMonth(), objOleDateTime.GetDay(), objOleDateTime.GetYear());

	oReg.Set(L"SOFTWARE\\UltraAV", _T("InstallationDate"), csDate, HKEY_LOCAL_MACHINE);
	oReg.Set(L"SOFTWARE\\UltraAV", _T("AutoScanTime"), csDate, HKEY_LOCAL_MACHINE);

	CString csInstalledDrive = csCurrentMDB.GetAt(0);
	csInstalledDrive = csInstalledDrive + L":,";
	oReg.Set(L"SOFTWARE\\UltraAV", _T("SelectedDrive"), csInstalledDrive, HKEY_LOCAL_MACHINE);


	
	
	oReg.Set(CSystemInfo::m_csProductRegKey, L"LastLiveUpdate", csLiveUpdateDate, HKEY_LOCAL_MACHINE);

	DeleteFile(csIniFullPath);

	DWORD dwMajorVersion = 0x00;
	oReg.Get(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentMajorVersionNumber", dwMajorVersion, HKEY_LOCAL_MACHINE);
	if (dwMajorVersion >= 10)
	{
		oReg.Set(L"SOFTWARE\\UltraAV", _T("Win10"), 1, HKEY_LOCAL_MACHINE);
	}
	return true;
}

void CCommonFunctions::EnableProtectection()
{
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXAVSETUP);
}
 
void CCommonFunctions::LaunchUltraAV()
{
	CSystemInfo objSystem;
	CCPUInfo oCpuInfo;
	bool bIs64Bit = (oCpuInfo.isOS64bit() ? true : false);

	CRegistry oReg;
	if (bIs64Bit)
	{
		oReg.SetWow64Key(true);
	} 
	CString csAppPath; 
	
	oReg.Get(L"SOFTWARE\\UltraAV", _T("AppFolder"), csAppPath, HKEY_LOCAL_MACHINE);

	CString csSerOptPath = csAppPath + L"AuSrvOpt.exe";
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	CreateProcess(csSerOptPath, L"-NOUI",
		0, 0, 0, 0, 0, 0, &si, &pi);
	WaitForSingleObject(pi.hProcess, INFINITE);
	Sleep(2000); 
	DllRegisterComponentsEx(csAppPath);
	ShellExecute(0, _T("open"), csAppPath + UI_EXENAME, L"", 0, SW_SHOW);
}

void CCommonFunctions::DllRegisterComponentsEx(CString cszDllPath)
{
	/*
	CString csDLLPath = L"\"" + cszDllPath + L"RegShellExt.bat\"";
	ShellExecute(NULL, L"open", csDLLPath, L"", L"", NULL);
	*/
	CString csAppPath = L"\"" + cszDllPath;

	TCHAR szShellExtBat[1024] = { 0x00 };
	TCHAR szAMSIBat[1024] = { 0x00 };
	TCHAR szTempPath[1024] = { 0x00 };
	GetTempPath(MAX_PATH, szTempPath);

	if (_tcslen(szTempPath) > 0x00)
	{
		_stprintf(szShellExtBat, L"%s\\RegShellExt.bat", szTempPath);
		_stprintf(szAMSIBat, L"%s\\RegAMSI.bat", szTempPath);
	}

	TCHAR szAdminText[1024] = { 0x00 };
	TCHAR szAuShellExtDLL[1024] = { 0x00 };
	TCHAR szAuAMSIDLL[1024] = { 0x00 };
	_stprintf(szAuShellExtDLL, L"\nRegsvr32 /s %sAuShellExt.dll\"", csAppPath);
	_stprintf(szAuAMSIDLL, L"\nRegsvr32 /s %sAMSI\\AuAMSIProvider.dll\"", csAppPath);
	_stprintf(szAdminText, L">NUL 2>&1 REG.exe query \"HKU\\S-1-5-19\" || ( \n ECHO SET UAC = CreateObject^(\"Shell.Application\"^) > \"%%TEMP%%\\Getadmin.vbs\" \n ECHO UAC.ShellExecute \"%%~f0\", \"%%1\", \"\", \"runas\", 1 >> \"%%TEMP%%\\Getadmin.vbs\" \n \"%%TEMP%%\\Getadmin.vbs\" \n DEL /f /q \"%%TEMP%%\\Getadmin.vbs\" 2>NUL \n Exit /b \n )");
	
	FILE* pOutFile = NULL;
	if (!pOutFile)
	{
		pOutFile = _wfsopen(szShellExtBat, _T("w"), 0x40);
	}
	if (pOutFile != NULL)
	{
		fputws((LPCTSTR)szAdminText, pOutFile);
		fputws((LPCTSTR)szAuShellExtDLL, pOutFile);
	}
	fflush(pOutFile);

	FILE* pOutFileAMSI = NULL;
	if (!pOutFileAMSI)
	{
		pOutFileAMSI = _wfsopen(szAMSIBat, _T("w"), 0x40);
	}
	if (pOutFileAMSI != NULL)
	{
		fputws((LPCTSTR)szAdminText, pOutFileAMSI);
		fputws((LPCTSTR)szAuAMSIDLL, pOutFileAMSI);
	}
	fflush(pOutFileAMSI);

	
	if (pOutFile)
		fclose(pOutFile);
	pOutFile = NULL;

	if (pOutFileAMSI)
		fclose(pOutFileAMSI);
	pOutFileAMSI = NULL;
	Sleep(1000);
	
	ShellExecute(NULL, L"open", szShellExtBat, L"", L"", NULL);
	Sleep(1000);
	ShellExecute(NULL, L"open", szAMSIBat, L"", L"", NULL);
	Sleep(1000);

	DeleteFile(szShellExtBat);
	DeleteFile(szAMSIBat);
}


bool CCommonFunctions::RegistryGrantAll()
{
	bool bResult = false;
	HKEY hKey;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\UltraAV", &hKey) == ERROR_SUCCESS)
	{
		PSECURITY_DESCRIPTOR sd = nullptr;

		const TCHAR* szSD =
			TEXT("D:")                  // Discretionary ACL
			TEXT("(D;OICI;KA;;;BG)")    // Deny access to built-in guests
			TEXT("(D;OICI;KA;;;AN)")    // Deny access to anonymous logon
			TEXT("(A;OICI;KRKW;;;AU)")  // Allow KEY_READ and KEY_WRITE to authenticated users ("AU")
			TEXT("(A;OICI;KA;;;BA)");   // Allow KEY_ALL_ACCESS to administrators ("BA" = Built-in Administrators)

		if (ConvertStringSecurityDescriptorToSecurityDescriptor((LPCTSTR)szSD, SDDL_REVISION_1, &sd, 0))
		{
			auto result = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, sd);
			if (ERROR_SUCCESS == result)
				bResult = true;
			else
				SetLastError(result);

			// Free the memory allocated for the SECURITY_DESCRIPTOR.
			LocalFree(sd);
		}
	}

	

	return bResult;
}

void CCommonFunctions::StartInstallation()
{
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RegisterProcessSetup(MAX_PROC_MAXAVSETUP);
}

void CCommonFunctions::EndInstallation()
{
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RegisterProcessSetupOFF(MAX_PROC_MAXAVSETUP);
}