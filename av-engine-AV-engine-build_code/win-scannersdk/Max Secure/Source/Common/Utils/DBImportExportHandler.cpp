#include "StdAfx.h"
#include "DBImportExportHandler.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include "CPUInfo.h"
#include "DirectoryManager.h"
#include "MaxCommunicator.h"
#include "MaxProtectionMgr.h"
#include "MaxPipes.h"
#include "USBManager.h"
#include "MaxDSrvWrapper.h"
#include "EnumProcess.h"
#include "ExecuteProcess.h"

bool m_bWin7orBelow;
CDBImportExportHandler::CDBImportExportHandler(void)
:m_objUserSettingsDB(false), m_objUserSettingsFirewallDB(false), m_objUserSettingsUSBDB(false), m_objUserSettingsPassDB(false)
{
	m_objUserSettingsDB.RemoveAll();
	m_objUserSettingsFirewallDB.RemoveAll();
	m_objUserSettingsUSBDB.RemoveAll();
	m_objUserSettingsPassDB.RemoveAll();

	m_csAppPath = CSystemInfo::m_strAppPath;;
	CCPUInfo	objCPUInfo;
	m_csDBsPath = objCPUInfo.GetAllUserAppDataPath();
	CString csParent = CSystemInfo::m_csFolderInAppPathParent;
	CString csPath = L"";
	csPath.Format(_T("%s\\%s\\BackupData"), m_csDBsPath, csParent);
	m_csDBsPath= csPath;
	CDirectoryManager m_oDirectoryManager;
	m_oDirectoryManager.MaxCreateDirectory(m_csDBsPath);
	m_csDBsPath+=_T("\\");
	m_bWin7orBelow = false;
	DWORD dwMajorVer = 0;
	DWORD dwMinorVer = 0;
	objCPUInfo.GetMajorAndMinorOSVersion(dwMajorVer,dwMinorVer);
	if(dwMajorVer < 6 || (dwMajorVer == 6 && dwMinorVer < 2))
	{
		m_bWin7orBelow = false;
	}
}

CDBImportExportHandler::~CDBImportExportHandler(void)
{
	m_objUserSettingsDB.RemoveAll();
	m_objUserSettingsFirewallDB.RemoveAll();
	m_objUserSettingsUSBDB.RemoveAll();
	m_objUserSettingsPassDB.RemoveAll();
	
}

void CDBImportExportHandler::SetValues(bool bCustomSettings, bool bScanByName, bool bUsbManager, bool bFirewall, bool bAppWhiteList)
{
	m_bCustomSettings	= bCustomSettings;
	m_bScanByName		= bScanByName;
	m_bUsbManager		= bUsbManager;
	m_bFirewall			= bFirewall;	
	m_bAppWhiteList		= bAppWhiteList;
}

void CDBImportExportHandler::ImportSettings()
{
	m_objUserSettingsDB.RemoveAll();
	m_objUserSettingsFirewallDB.RemoveAll();
	m_objUserSettingsUSBDB.RemoveAll();
	m_objUserSettingsPassDB.RemoveAll();
	CRegistry objReg;
	DWORD dwSettingVal = 0;
	int iCount = 0;
	CString csRegKey =FW_DRIVER_PATH;

	//
	// PasswordDB
	CString csUserPassDBPath = m_csDBsPath + USERSETTINGS_PASSWORDIMEX_DB;
	if (m_objUserSettingsPassDB.Load(csUserPassDBPath) == true)
	{
		LPVOID lpVoid = m_objUserSettingsPassDB.GetFirst();
		while(lpVoid)
		{
			CString csKey, csData;
			LPTSTR strKey = NULL;
			LPTSTR strData = NULL;
			dwSettingVal = 0;
			m_objUserSettingsPassDB.GetKey(lpVoid, strKey);
			m_objUserSettingsPassDB.GetData(lpVoid, strData);
			csKey = strKey; //GetSpyName(ulSpyName);
			dwSettingVal = _ttoi(strData);
			objReg.Set(CSystemInfo::m_csProductRegKey, csKey, dwSettingVal, HKEY_LOCAL_MACHINE);
			lpVoid = m_objUserSettingsPassDB.GetNext(lpVoid);
			iCount++;
		}		
	}
	///////////////////////
	
	dwSettingVal = 0;
	CString csUserDBPath = m_csDBsPath + USERSETTINGS_IMEX_DB;
	m_bSysFileProtection = false;
	if(m_bCustomSettings)
	{
		if (m_objUserSettingsDB.Load(csUserDBPath) == true)
		{
			LPVOID lpVoid = m_objUserSettingsDB.GetFirst();
			while(lpVoid)
			{
				CString csKey, csData;
				LPTSTR strKey = NULL;
				LPTSTR strData = NULL;
				dwSettingVal = 0;
				m_objUserSettingsDB.GetKey(lpVoid, strKey);
				m_objUserSettingsDB.GetData(lpVoid, strData);
				csKey = strKey; 
				dwSettingVal = _ttoi(strData);

				if(csKey.Find(_T("ProtectSystemRegistry")) != -1)
				{
					m_bSysFileProtection = dwSettingVal;
					SystemFileProtection();
				}
				else if(csKey.Find(_T("ShowKillPopup")) != -1)
				{
					objReg.Set(CSystemInfo::m_csActMonRegKey, _T("ShowKillPopup"), dwSettingVal, HKEY_LOCAL_MACHINE);
				}
				else if(csKey.Find(_T("GamingMode")) != -1)
				{
					GamingModeSetting(dwSettingVal);
				}
				else if(csKey.Find(_T("EnableCopyPaste")) != -1)
				{
					EnableCopyPasteSetting(dwSettingVal);
				}
				else if(csKey.Find(_T("EnableReplicating")) != -1)
				{
					EnableReplicatingSetting(dwSettingVal);
				}		//else if(csKey.Find(_T("AutoScan")) != -1){SendSockProductSettingsMsg(dwSettingVal);}
				else
				{
					if(csKey.Find(_T("ShowGadget")) != -1)
					{
						if(dwSettingVal == 1)
						{
							CString csGadgetPath;
							objReg.Get(CSystemInfo::m_csProductRegKey, _T("AppFolder"), csGadgetPath, HKEY_LOCAL_MACHINE);
							csGadgetPath += _T("Gadget.exe");
							objReg.Set(RUN_KEY_PATH, SHOW_GADGET_KEY, _T("\"") + csGadgetPath + _T("\""), HKEY_LOCAL_MACHINE);
						}
						else
						{
							objReg.DeleteValue(RUN_KEY_PATH, SHOW_GADGET_KEY, HKEY_LOCAL_MACHINE);
						}
					}

					objReg.Set(CSystemInfo::m_csProductRegKey, csKey, dwSettingVal, HKEY_LOCAL_MACHINE);
				}
				lpVoid = m_objUserSettingsDB.GetNext(lpVoid);
				iCount++;
			}		
		}
	}
	//Usb Manager
	if(m_bUsbManager)
	{
		CString csUserUSBDBPath = m_csDBsPath + USERSETTINGS_USB_IMEX_DB;
		m_bWriteButton = m_bExecuteButton = m_bReadButton = m_bBlockAutorun = m_bTotalBlock = false;
		if (m_objUserSettingsUSBDB.Load(csUserUSBDBPath) == true)
		{
			LPVOID lpVoid = m_objUserSettingsUSBDB.GetFirst();
			while(lpVoid)
			{
				CString csKey, csData;
				LPTSTR strKey = NULL;
				LPTSTR strData = NULL;
				dwSettingVal = 0;
				m_objUserSettingsUSBDB.GetKey(lpVoid, strKey);
				m_objUserSettingsUSBDB.GetData(lpVoid, strData);
				csKey = strKey; 
				dwSettingVal = _ttoi(strData);
				//,USBScan,USBScanMode,Protect
				if(csKey.Find(_T("USBScan")) != -1)
				{
					objReg.Set(CSystemInfo::m_csProductRegKey, csKey, dwSettingVal, HKEY_LOCAL_MACHINE);
				}
				else if(csKey.Find(_T("USBScanMode")) != -1)
				{
					objReg.Set(CSystemInfo::m_csProductRegKey, csKey, dwSettingVal, HKEY_LOCAL_MACHINE);
				}
				else if(csKey.Find(_T("Protect")) != -1)
				{
					objReg.Set(CSystemInfo::m_csProductRegKey, csKey, dwSettingVal, HKEY_LOCAL_MACHINE);
				}
				else if(csKey.Find(_T("USB_READ")) != -1)
				{
					m_bReadButton = dwSettingVal;
				}
				else if(csKey.Find(_T("USB_WRITE")) != -1)
				{
					m_bWriteButton = dwSettingVal;
				}
				else if(csKey.Find(_T("USB_EXECUTE")) != -1)
				{
					m_bExecuteButton = dwSettingVal;
				}
				else if(csKey.Find(_T("USB_ACTIVITY")) != -1)
				{
					m_bActivityLogButton = dwSettingVal;
				}
				else if(csKey.Find(_T("USB_TOTAL")) != -1)
				{
					if(dwSettingVal == 4)
					{
						m_bTotalBlock = true;
					}
					else
					{
						m_bTotalBlock = false;
					}

				}
				else if(csKey.Find(_T("USB_AUTORUN")) != -1)
				{
					m_bBlockAutorun = dwSettingVal;
				}
				lpVoid = m_objUserSettingsUSBDB.GetNext(lpVoid);
				iCount++;
			}		
		}
		USBManagerSettings();
	}
	///USB Manager
	
	//Firewall
	if(m_bFirewall && objReg.KeyExists(FIREWALL_REG_KEY, HKEY_LOCAL_MACHINE) && objReg.KeyExists(csRegKey, HKEY_LOCAL_MACHINE))
	{
		//SendMessageToTray(WM_USER_ID_FW_PNP_STOP, NULL, NULL);
		objReg.AllowAccessToEveryone(HKEY_LOCAL_MACHINE, FW_DRIVER_PATH);
		CString csUserDBPath = m_csDBsPath + USERSETTINGS_FIREWALL_IMEX_DB;
		if (m_objUserSettingsFirewallDB.Load(csUserDBPath) == true)
		{
			LPVOID lpVoid = m_objUserSettingsFirewallDB.GetFirst();
			while(lpVoid)
			{
				CString csKey, csData;
				LPTSTR strKey = NULL;
				LPTSTR strData = NULL;
				dwSettingVal = 0;
				m_objUserSettingsFirewallDB.GetKey(lpVoid, strKey);
				m_objUserSettingsFirewallDB.GetData(lpVoid, strData);
				csKey = strKey; //GetSpyName(ulSpyName);
				dwSettingVal = _ttoi(strData);
				objReg.Set(csRegKey, csKey, dwSettingVal, HKEY_LOCAL_MACHINE);
				lpVoid = m_objUserSettingsFirewallDB.GetNext(lpVoid);
				iCount++;
			}		
		}
	}

	ImportDB();
	if(m_bFirewall && objReg.KeyExists(FIREWALL_REG_KEY, HKEY_LOCAL_MACHINE) && objReg.KeyExists(csRegKey, HKEY_LOCAL_MACHINE)){
		SendMessageToTray(WM_USER_ID_FW_MON_RESTART, NULL, NULL);
	}
		
}
void CDBImportExportHandler::ExportSettings()
{
	//CDirectoryManager m_oDirectoryManager;
	//m_oDirectoryManager.MaxDeleteDirectoryContents(m_csDBsPath,true);
	
	m_objUserSettingsDB.RemoveAll();
	m_objUserSettingsFirewallDB.RemoveAll();
	m_objUserSettingsUSBDB.RemoveAll();
	m_objUserSettingsPassDB.RemoveAll();
	//CString m_csUserFirewallSettings=_T("StopPNP,NFStatus,BSBlockStatus,APStatus,FireWallEnable,AntiPStatus,AntiBStatus,EmailEnable,EnableNetworkBlock");
	CString m_csUserFirewallSettings=_T("FireWallEnable,EmailEnable");
	CString m_csUserCustomSettings=_T("CleanTemp,CleanTempIE,ShowTipsAtStartup,SplashScreen,AutoLiveupdate,AutoLiveupdateOff,PlaySound,AutomationLab,ShowGadget");
	CString m_csUserAdvanceSettings=_T("KeyLoggerScan,AutoScan,RootkitQuarantine,RootkitQuarantineAlway,ThreatCommunity,ScanQuarantine,SkipCompressedFiles,CleanBrowsers");

	DWORD dwSettingVal = 0;
	CRegistry objReg;
	CString csToken;
	int iPos = 0;
	CString csSettingVal;

	// PasswordDB
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_USB, dwSettingVal, HKEY_LOCAL_MACHINE);
	csSettingVal.Format(_T("%d"),dwSettingVal);
	m_objUserSettingsPassDB.AppendItem(PASSWORD_USB,csSettingVal);

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_WHITELIST, dwSettingVal, HKEY_LOCAL_MACHINE);
	csSettingVal.Format(_T("%d"),dwSettingVal);
	m_objUserSettingsPassDB.AppendItem(PASSWORD_WHITELIST,csSettingVal);

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_PARENTAL, dwSettingVal, HKEY_LOCAL_MACHINE);
	csSettingVal.Format(_T("%d"),dwSettingVal);
	m_objUserSettingsPassDB.AppendItem(PASSWORD_PARENTAL,csSettingVal);
	
	CString csUserPassDBPath = m_csDBsPath + USERSETTINGS_PASSWORDIMEX_DB;
	DeleteFile(csUserPassDBPath);
	if(m_objUserSettingsPassDB.GetFirst())
	{
		m_objUserSettingsPassDB.Balance();
		m_objUserSettingsPassDB.Save(csUserPassDBPath);
	}
	///////////////////////
	
	// Firewall Setting
	CString csReturn;
	CString csRegKey =FW_DRIVER_PATH;
	if(m_bFirewall && objReg.KeyExists(FIREWALL_REG_KEY, HKEY_LOCAL_MACHINE) && objReg.KeyExists(csRegKey, HKEY_LOCAL_MACHINE))
	{
		CString csUserFirewallDBPath = m_csDBsPath + USERSETTINGS_FIREWALL_IMEX_DB;
		csToken = m_csUserFirewallSettings.Tokenize(_T(","),iPos);
		csToken.Trim();
		while(csToken.GetLength() != 0)
		{
			dwSettingVal = 0;
			CRegistry objReg;
			objReg.Get(csRegKey, csToken, dwSettingVal, HKEY_LOCAL_MACHINE);
			csSettingVal.Format(_T("%d"),dwSettingVal);
			m_objUserSettingsFirewallDB.AppendItem(csToken,csSettingVal);
			csToken = m_csUserFirewallSettings.Tokenize(L",", iPos);
			csToken.Trim();
		}
		DeleteFile(csUserFirewallDBPath);
		if(m_objUserSettingsFirewallDB.GetFirst())
		{
			m_objUserSettingsFirewallDB.Balance();
			m_objUserSettingsFirewallDB.Save(csUserFirewallDBPath);
		}
	}

	if(m_bCustomSettings)
	{
		CString csUserDBPath = m_csDBsPath + USERSETTINGS_IMEX_DB;
		// Firewall Setting
		iPos = 0;
		csToken = m_csUserCustomSettings.Tokenize(_T(","),iPos);
		csToken.Trim();
		while(csToken.GetLength() != 0)
		{
			dwSettingVal = 0;
			objReg.Get(CSystemInfo::m_csProductRegKey, csToken, dwSettingVal, HKEY_LOCAL_MACHINE);
			csSettingVal.Format(_T("%d"),dwSettingVal);
			m_objUserSettingsDB.AppendItem(csToken,csSettingVal);
			csToken = m_csUserCustomSettings.Tokenize(L",", iPos);
			csToken.Trim();
		}

		dwSettingVal = 0;
		objReg.Get(CSystemInfo::m_csActMonRegKey, _T("ShowKillPopup"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsDB.AppendItem(_T("ShowKillPopup"),csSettingVal);

		dwSettingVal = 0;
		objReg.Get(CSystemInfo::m_csActMonRegKey, _T("GamingMode"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsDB.AppendItem(_T("GamingMode"),csSettingVal);

		dwSettingVal = 0;
		objReg.Get(ACTMON_SERVICE_PATH, _T("EnableCopyPaste"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsDB.AppendItem(_T("EnableCopyPaste"),csSettingVal);

		dwSettingVal = 0;
		objReg.Get(ACTMON_SERVICE_PATH, _T("EnableReplicating"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsDB.AppendItem(_T("EnableReplicating"),csSettingVal);

		iPos = 0;
		csToken = m_csUserAdvanceSettings.Tokenize(_T(","),iPos);
		csToken.Trim();
		while(csToken.GetLength() != 0)
		{
			dwSettingVal = 0;
			CRegistry objReg;
			objReg.Get(CSystemInfo::m_csProductRegKey, csToken, dwSettingVal, HKEY_LOCAL_MACHINE);
			csSettingVal.Format(_T("%d"),dwSettingVal);
			m_objUserSettingsDB.AppendItem(csToken,csSettingVal);
			csToken = m_csUserAdvanceSettings.Tokenize(L",", iPos);
			csToken.Trim();
		}
		dwSettingVal = 0;
		CMaxProtectionMgr objProtMgr;
		objProtMgr.GetProtectSysRegKeyStatus(dwSettingVal);	
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsDB.AppendItem(_T("ProtectSystemRegistry"),csSettingVal);

		DeleteFile(csUserDBPath);
		if(m_objUserSettingsDB.GetFirst())
		{
			m_objUserSettingsDB.Balance();
			m_objUserSettingsDB.Save(csUserDBPath);
		}
	}

	/////USBManager
	if(m_bUsbManager)
	{
		dwSettingVal = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBScan"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USBScan"),csSettingVal);

		dwSettingVal = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBScanMode"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USBScanMode"),csSettingVal);

		dwSettingVal = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("Protect"), dwSettingVal, HKEY_LOCAL_MACHINE);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("Protect"),csSettingVal);

		dwSettingVal=0;
		if(ReadUsbRegistrySettings(0) == 1)
		{
			dwSettingVal = 1;
		}
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USB_READ"),csSettingVal);
		dwSettingVal=0;
		if(ReadUsbRegistrySettings(1) == 1)
		{
			dwSettingVal = 1;
		}
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USB_WRITE"),csSettingVal);
		dwSettingVal=0;
		if(ReadUsbRegistrySettings(2) == 1)
		{
			dwSettingVal = 1;
		}
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USB_EXECUTE"),csSettingVal);

		dwSettingVal=0;
		if(ReadUsbRegistrySettings(3) == 1)
		{
			dwSettingVal = 1;
		}
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USB_ACTIVITY"),csSettingVal);


		DWORD dw = 3;
		objReg.Get(L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR",L"Start",dw,HKEY_LOCAL_MACHINE);	
		if(dw==4)
		{
			dwSettingVal = 4;
			csSettingVal.Format(_T("%d"),dwSettingVal);
			m_objUserSettingsUSBDB.AppendItem(_T("USB_TOTAL"),csSettingVal);
		}
		else
		{
			dwSettingVal = 3;
			csSettingVal.Format(_T("%d"),dwSettingVal);
			m_objUserSettingsUSBDB.AppendItem(_T("USB_TOTAL"),csSettingVal);
		}

		dwSettingVal = 0;
		CMaxProtectionMgr oMaxProtectionMgr;
		oMaxProtectionMgr.GetBlockAutoRunStatus(dwSettingVal);
		csSettingVal.Format(_T("%d"),dwSettingVal);
		m_objUserSettingsUSBDB.AppendItem(_T("USB_AUTORUN"),csSettingVal);

		/////
		CString csUserUSBDBPath = m_csDBsPath + USERSETTINGS_USB_IMEX_DB;
		DeleteFile(csUserUSBDBPath);
		if(m_objUserSettingsUSBDB.GetFirst())
		{
			m_objUserSettingsUSBDB.Balance();
			m_objUserSettingsUSBDB.Save(csUserUSBDBPath);
		}
	}

	ExportDB();
}
void CDBImportExportHandler::ExportDB()
{
	CopyFile(m_csAppPath+ FWDATA_USERPASSDB, m_csDBsPath + FWDATA_USERPASSDB, FALSE);
	CopyFile(m_csAppPath+ _T("ManageUserHint.DB"), m_csDBsPath + _T("ManageUserHint.DB"), FALSE);
	if(m_bScanByName)
	{
		CopyFile(m_csAppPath+ _T("Setting\\InstantScan.ini"), m_csDBsPath + _T("InstantScan.ini"), FALSE);
	}
	
	if(m_bAppWhiteList)
	{
		CopyFile(m_csAppPath+ _T("Tools\\WhiteListMgr.DB"), m_csDBsPath + _T("WhiteListMgr.DB"), FALSE);
		CopyFile(m_csAppPath+ _T("Tools\\AppBlockListMgr.DB"), m_csDBsPath + _T("AppBlockListMgr.DB"), FALSE);
	}
	CopyFile(m_csAppPath+ _T("Tools\\AppExtListMgr.DB"), m_csDBsPath + _T("AppExtListMgr.DB"), FALSE);
	// Firewall
	if(m_bFirewall)
	{
		//CopyFile(m_csAppPath+ _T("ManageUser.DB"), m_csDBsPath + _T("ManageUser.DB"), FALSE);
		CDirectoryManager m_oDirectoryManager;
		CString csFolderPath = m_csDBsPath+ _T("FWData");
		m_oDirectoryManager.MaxCreateDirectory(csFolderPath);
		csFolderPath = m_csDBsPath+ FWPNPDATA_FOLDER;
		m_oDirectoryManager.MaxCreateDirectory(csFolderPath);

		CopyFile(m_csAppPath+ _T("Setting\\AntiSpamSetting.ini"), m_csDBsPath + _T("AntiSpamSetting.ini"), FALSE);

		csFolderPath=m_csAppPath+ _T("FWData\\*.*");
		CString csFilePath, csFileName;
		CFileFind findfile;
		csFileName = _T("");
		BOOL bCheck = findfile.FindFile(csFolderPath);
		while(bCheck)
		{
			//To Find Next File In Same Directory
			bCheck = findfile.FindNextFile();
			if(findfile.IsDots())
			{
				continue;
			}
			if(findfile.IsDirectory())
			{
				continue;
			}
			csFilePath = findfile.GetFilePath();
			csFileName = findfile.GetFileName();
			if(csFileName.Find(_T(".DB")) != -1)
			{
				CopyFile(csFilePath, m_csDBsPath + _T("FWData\\")+ csFileName, FALSE);
			}
		}
		findfile.Close();

		csFolderPath=m_csAppPath+ FWPNPDATA_FOLDER+_T("\\*.*");
		csFileName = _T("");
		bCheck = findfile.FindFile(csFolderPath);
		while(bCheck)
		{
			//To Find Next File In Same Directory
			bCheck = findfile.FindNextFile();
			if(findfile.IsDots())
			{
				continue;
			}
			if(findfile.IsDirectory())
			{
				continue;
			}
			csFilePath = findfile.GetFilePath();
			csFileName = findfile.GetFileName();
			if(csFileName.Find(_T(".DB")) != -1)
			{
				CopyFile(csFilePath, m_csDBsPath + FWPNPDATA_FOLDER+ _T("\\")+ csFileName, FALSE);
			}
		}
		findfile.Close();
	}

	
	
}
void CDBImportExportHandler::ImportDB()
{
	CopyFile(m_csDBsPath+ FWDATA_USERPASSDB, m_csAppPath + FWDATA_USERPASSDB, FALSE);
	CopyFile(m_csDBsPath+ _T("ManageUserHint.DB"), m_csAppPath + _T("ManageUserHint.DB"), FALSE);
	if(m_bScanByName)
	{
		CopyFile(m_csDBsPath + _T("InstantScan.ini"), m_csAppPath + _T("Setting\\InstantScan.ini"), FALSE);
	}
	
	if(m_bAppWhiteList)
	{
		CopyFile(m_csDBsPath+ _T("WhiteListMgr.DB"), m_csAppPath + _T("Tools\\WhiteListMgr.DB"), FALSE);
		CopyFile(m_csDBsPath+ _T("AppBlockListMgr.DB"), m_csAppPath + _T("Tools\\AppBlockListMgr.DB"), FALSE);
	}
	CopyFile(m_csDBsPath+ _T("AppExtListMgr.DB"), m_csAppPath + _T("Tools\\AppExtListMgr.DB"), FALSE);
	
	// Firewall
	if(m_bFirewall)
	{
		//CopyFile(m_csDBsPath+ _T("ManageUser.DB"), m_csAppPath + _T("ManageUser.DB"), FALSE);		
		CopyFile(m_csDBsPath+ _T("AntiSpamSetting.ini"), m_csAppPath + _T("Setting\\AntiSpamSetting.ini"), FALSE);
		CString csFolderPath=m_csDBsPath+ _T("FWData\\*.*");
		CString csFilePath, csFileName;
		CFileFind findfile;
		csFileName = _T("");
		BOOL bCheck = findfile.FindFile(csFolderPath);
		while(bCheck)
		{
			//To Find Next File In Same Directory
			bCheck = findfile.FindNextFile();
			if(findfile.IsDots())
			{
				continue;
			}
			if(findfile.IsDirectory())
			{
				continue;
			}
			csFilePath = findfile.GetFilePath();
			csFileName = findfile.GetFileName();
			if(csFileName.Find(_T(".DB")) != -1)
			{
				CopyFile(csFilePath, m_csAppPath + _T("FWData\\")+ csFileName, FALSE);
			}
		}
		findfile.Close();

		csFolderPath=m_csDBsPath+ FWPNPDATA_FOLDER+ _T("\\*.*");
		csFileName = _T("");
		bCheck = findfile.FindFile(csFolderPath);
		while(bCheck)
		{
			//To Find Next File In Same Directory
			bCheck = findfile.FindNextFile();
			if(findfile.IsDots())
			{
				continue;
			}
			if(findfile.IsDirectory())
			{
				continue;
			}
			csFilePath = findfile.GetFilePath();
			csFileName = findfile.GetFileName();
			if(csFileName.Find(_T(".DB")) != -1)
			{
				CopyFile(csFilePath, m_csAppPath + FWPNPDATA_FOLDER+ _T("\\")+ csFileName, FALSE);
			}
		}
		findfile.Close();
	}
}
void CDBImportExportHandler::SendMessageToTray(UINT uMessage, WPARAM wParam, LPARAM lParam)
{	
	HWND hWnd=::FindWindowEx(NULL, NULL, _T("#32770"), AUACTIVEPROTECTION);
	if(hWnd)
	{
		SendMessageTimeout(hWnd, uMessage, wParam, lParam, SMTO_ABORTIFHUNG, TIMEOUT, NULL);
	}
}

int CDBImportExportHandler::ReadUsbRegistrySettings(ULONG ulTypeOfKey)
{	
	HKEY hKey;
	DWORD dw = 0;
	DWORD data;
	DWORD iValue = 0, dwLen = 0;
	DWORD dwType = REG_DWORD;
	int returnVal = 0;
	DWORD lResult;	

	if(::RegOpenKeyEx(HKEY_LOCAL_MACHINE, ACTMON_REG_KEY,0,KEY_READ,&hKey) == ERROR_SUCCESS)
	{
		CString str;

		if(ulTypeOfKey == 0)
		{
			lResult = RegQueryValueEx(hKey,L"USB-READ",NULL,&dwType,(LPBYTE)&data,&dw);
			
			if(::RegQueryValueEx(hKey,L"USB-READ",NULL,&dwType,(LPBYTE)&data,&dw) == ERROR_SUCCESS)
			{			
				returnVal = (int) data;
			}
			else
			{
				returnVal = 0;
			}
		}

		if(ulTypeOfKey == 1)
		{
			lResult = RegQueryValueEx(hKey,L"USB-WRITE",NULL,&dwType,(LPBYTE)&data,&dw);
			
			if(::RegQueryValueEx(hKey,L"USB-WRITE",NULL,&dwType,(LPBYTE)&data,&dw) == ERROR_SUCCESS)
			{
				returnVal = (int) data;
			}
			else
			{
				returnVal = 0;
			}
		}

		if(ulTypeOfKey == 2)
		{
			lResult = RegQueryValueEx(hKey,L"USB-EXECUTE",NULL,&dwType,(LPBYTE)&data,&dw);
						
			if(::RegQueryValueEx(hKey,L"USB-EXECUTE",NULL,&dwType,(LPBYTE)&data,&dw) == ERROR_SUCCESS)
			{
				returnVal = (int) data;
			}
			else
			{
				returnVal = 0;
			}
		}

		if(ulTypeOfKey == 3)
		{
			lResult = RegQueryValueEx(hKey,L"USB-ACTIVITY",NULL,&dwType,(LPBYTE)&data,&dw);
						
			if(::RegQueryValueEx(hKey,L"USB-ACTIVITY",NULL,&dwType,(LPBYTE)&data,&dw) == ERROR_SUCCESS)
			{
				returnVal = (int) data;
			}
			else
			{
				returnVal = 0;
			}
		}

		::RegCloseKey(hKey);
	}
	

	return returnVal;
}
void CDBImportExportHandler::WriteUsbRegistrySettings(int iType, ULONG ulUsbSettings)
{

	MAX_PIPE_DATA_REG sMaxPipeDataReg = {0};
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);

	memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
	
	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
	sMaxPipeDataReg.ulSpyNameID = ulUsbSettings;
	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), ACTMON_REG_KEY;
	
	{
		if(iType == 0)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-READ");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}

		if(iType == 1)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-WRITE");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}

		if(iType == 2)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-EXECUTE");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}

		if(iType == 3)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-ACTIVITY");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}
	}
}
void CDBImportExportHandler::WriteUSBSettings()
{
	ULONG ulData = 0;
	if(m_bWriteButton == true)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_WRITE_BLOCK,ulData);
		WriteUsbRegistrySettings(1,1);
	}
	else
	{
		SendDataToDriver(IOCTL_USB_WRITE_BLOCK,ulData);
		WriteUsbRegistrySettings(1,0);
	}	

	Sleep(100);
	
	ulData = 0;
	if(m_bExecuteButton == true)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_EXECUTE_BLOCK,ulData);
		WriteUsbRegistrySettings(2,1);
	}
	else
	{
		SendDataToDriver(IOCTL_USB_EXECUTE_BLOCK,ulData);
		WriteUsbRegistrySettings(2,0);
	}

	Sleep(100);
	
	ulData = 0;
	if(m_bReadButton == true)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_READ_BLOCK,ulData);
		WriteUsbRegistrySettings(0,1);
		
	}
	else
	{
		SendDataToDriver(IOCTL_USB_READ_BLOCK,ulData);
		WriteUsbRegistrySettings(0,0);
	}

	Sleep(100);
	
	ulData = 0;
	if(m_bActivityLogButton == true)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_ACTIVITY_LOG,ulData);
		WriteUsbRegistrySettings(3,1);
		
	}
	else
	{
		SendDataToDriver(IOCTL_USB_ACTIVITY_LOG,ulData);
		WriteUsbRegistrySettings(3,0);
	}

	Sleep(100);
}
void CDBImportExportHandler::USBManagerSettings()
{
	WriteUSBSettings();
	CRegistry objReg;
	DWORD dw =0;
	
	MAX_PIPE_DATA_REG sMaxPipeDataReg = {0};
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);

	DWORD dwr = 1;
	DWORD dwAutoCheck = (m_bBlockAutorun == true ? 1 : 0) ;

	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;

	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), MAX_PROTECTOR_REG_KEY);
	
	_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), _T("BlockAutorun"));
	sMaxPipeDataReg.ulSpyNameID = dwAutoCheck;
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
	objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

	dw = 3;
	if(m_bTotalBlock== true)
	{		
		dw=4;
	}
	memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR");
	_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"Start");
	sMaxPipeDataReg.ulSpyNameID = dw;
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
	objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
}
void CDBImportExportHandler::SendDataToDriver(ULONG ulIoCode,ULONG data)
{
	DWORD dwReturn;
	HANDLE hFile = CreateFile(ACTMON_DRIVE_SYMBOLIC, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if(hFile != INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("ACTMON drv handle created\n");
		DeviceIoControl(hFile, ulIoCode, &data, sizeof(ULONG) , &data, sizeof(ULONG), &dwReturn, NULL);
		CloseHandle(hFile);
	}
}
void CDBImportExportHandler::SystemFileProtection()
{
	try
	{
		MAX_PIPE_DATA_REG sMaxPipeDataReg = {0};
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
		sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
		_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), MAX_PROTECTOR_REG_KEY);
		
		_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), _T("ProtectSystemRegistry"));
		if(m_bSysFileProtection == true)
		{		
			sMaxPipeDataReg.ulSpyNameID = 1;
			}
		else
		{		
			sMaxPipeDataReg.ulSpyNameID = 0;
			}
		sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
		objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
	}
	catch(...)
	{
		AddLogEntry(L"Exception in CDBImportExportHandler::SystemFileProtection");
	}
}
bool CDBImportExportHandler::SetGamingMode(bool bStatus)
{
	CMaxDSrvWrapper objMaxDSrvWrapper;
	bool bRetVal = objMaxDSrvWrapper.SetGamingMode(bStatus);

	MAX_PIPE_DATA_REG oPipeData = {0};
	oPipeData.eMessageInfo = GamingMode;
	oPipeData.ulSpyNameID = (ULONG)bStatus;
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG));

	return bRetVal;
}
void CDBImportExportHandler::GamingModeSetting(DWORD dwSettingVal)
{
	CRegistry objReg;
	if(dwSettingVal == 1)
	{
		if(SetGamingMode(true))
		{
			objReg.Set(CSystemInfo::m_csActMonRegKey, GAMINGMODE_KEY, 1, HKEY_LOCAL_MACHINE);
		}
		
	}
	else
	{
		if(SetGamingMode(false))
		{
			objReg.Set(CSystemInfo::m_csActMonRegKey, GAMINGMODE_KEY, 0, HKEY_LOCAL_MACHINE);
		}
	}
}
void CDBImportExportHandler::EnableCopyPasteSetting(DWORD dwSettingVal)
{
	MAX_PIPE_DATA_REG oPipeData = {0};
	oPipeData.eMessageInfo = SetCopyPasteSetting;
	oPipeData.ulSpyNameID = 1;
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	oPipeData.ulSpyNameID = dwSettingVal;
	
	if(!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
	{
		AddLogEntry(_T("### SendData Failed In CDBImportExportHandler::EnableCopyPasteSetting"));
	}
}
void CDBImportExportHandler::EnableReplicatingSetting(DWORD dwSettingVal)
{
	try
	{
		MAX_PIPE_DATA_REG oPipeData = {0};
		oPipeData.eMessageInfo = Enable_Replication;
		oPipeData.ulSpyNameID = 1;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		oPipeData.ulSpyNameID = dwSettingVal;
		
		if(!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
		{
			AddLogEntry(_T("### SendData Failed In CDBImportExportHandler::EnableReplicatingSetting"));
		}
	}
	catch(...)
	{
		AddLogEntry(L"Exception in CDBImportExportHandler::EnableReplicatingSetting");
	}
}
//void CDBImportExportHandler::CheckRunNativeScanner(bool bSettingVal)
//{
//	CRegistry objReg;
//	CString csValue[2] = {_T("autocheck autochk *"), MAXNATIVESCANNER_EXE};
//
//	CStringArray csAValue;	
//	csAValue.Add(csValue[0]);
//
//	CStringArray csACheckValue;
//	objReg.Get(BOOT_EXECUTE_REG_KEY, _T("BootExecute"), csACheckValue, HKEY_LOCAL_MACHINE);
//
//	bool bFound = false;
//	for(int iCount = 0; iCount < csACheckValue.GetCount(); iCount++)
//	{		
//		if(csACheckValue[iCount].Trim() == CString(MAXNATIVESCANNER_EXE))
//		{
//			bFound = true;
//		}
//	}
//	if(bSettingVal == bFound)
//	{
//		return;
//	}
//	MAX_PIPE_DATA_REG oPipeData = {0};
//	oPipeData.eMessageInfo = SetNativeScanSetting;
//	oPipeData.ulSpyNameID = 1;
//	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
//	
//	if(bFound && !bSettingVal)
//	{
//		oPipeData.ulSpyNameID = 1;
//	}
//	else
//	{
//		oPipeData.ulSpyNameID = 0;
//	}
//	
//	if(!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
//	{
//		AddLogEntry(_T("### SendData Failed In CAdvancedSetting::OnBnClickedCheckRunNativeScanner"));
//	}
//}

//void CDBImportExportHandler::SendSockProductSettingsMsg(bool bStatus)
//{
//	CRegistry		objReg;
//	bool			bRet = false;
//	DWORD			dwVal = 0;
//	if(bStatus)
//	{
//		dwVal = 1;
//		bRet  = objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScan"), dwVal, HKEY_LOCAL_MACHINE);
//		CString csAPPPath, csAutoScanPath;
//		objReg.Get(CSystemInfo::m_csProductRegKey, _T("AppPath"), csAPPPath, HKEY_LOCAL_MACHINE);
//		csAutoScanPath+= csAPPPath;
//		CString csEntry;
//		csEntry = _T("HK_LM[Run]^AUAutoScan^") + csAutoScanPath + _T(" -AUTOSCAN");
//		MAX_PIPE_DATA sMaxPipeData = {0};
//		sMaxPipeData.eMessageInfo = ENUM_OA_INSERTSTARTUP;
//		sMaxPipeData.ulSpyNameID = 0;
//		_tcscpy_s(sMaxPipeData.strValue, csEntry);
//		//theApp.SendOptionsData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
//	}
//	else
//	{
//		dwVal = 0;
//		bRet  = objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScan"), dwVal, HKEY_LOCAL_MACHINE);
//		CString csEntry = _T("HK_LM[Run]AUAutoScan");
//		MAX_PIPE_DATA sMaxPipeData = {0};
//		sMaxPipeData.eMessageInfo = ENUM_OA_DELSTARTUP;
//		sMaxPipeData.ulSpyNameID = 0;
//		_tcscpy_s(sMaxPipeData.strValue, csEntry);
//		theApp.SendOptionsData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
//	}
//}

void CDBImportExportHandler::DefaultSettings()
{

	DWORD dwSettingVal = 0;
	DWORD dw=0;
	CString csProductRegKey = CSystemInfo::m_csProductRegKey;
	CString csActMonRegKey  = CSystemInfo::m_csActMonRegKey;
	CRegistry objReg;
	/////Custom Settings
	objReg.Set(csActMonRegKey, _T("ShowKillPopup"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("CleanTemp"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("CleanTempIE"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("ShowTipsAtStartup"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("SplashScreen"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("AutoLiveupdate"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("AutoLiveupdateOff"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("PlaySound"), 1, HKEY_LOCAL_MACHINE);

	objReg.Get(csProductRegKey, _T("ShowGadget"), dw, HKEY_LOCAL_MACHINE);
	if(dw == 0)
	{
		ShowGadget(dw);
	}
	DWORD dwProcessMonitor = 0;
	objReg.Get(csProductRegKey, _T("AutomationLab"), dw, HKEY_LOCAL_MACHINE);
	if(dw == 1)
	{
		dwProcessMonitor = 1;
		objReg.Set(csProductRegKey, _T("AutomationLab"), 0, HKEY_LOCAL_MACHINE);
	}
	

	/////Advance Settings
	objReg.Set(csProductRegKey, _T("KeyLoggerScan"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("CleanBrowsers"), 1, HKEY_LOCAL_MACHINE);
	objReg.Get(csProductRegKey, _T("AutoScan"), dw, HKEY_LOCAL_MACHINE);
	if(dw == 1)
	{
		objReg.Set(csProductRegKey, _T("AutoScan"), 0, HKEY_LOCAL_MACHINE);
	//	SendSockProductSettingsMsg(0);
	}

	objReg.Set(csProductRegKey, _T("RootkitQuarantine"), 0, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("RootkitQuarantineAlway"), 1, HKEY_LOCAL_MACHINE);
	objReg.Get(csProductRegKey, _T("SkipCompressedFiles"), dw, HKEY_LOCAL_MACHINE);
	if(dw == 0)
	{
		dwProcessMonitor = 1;
		objReg.Set(csProductRegKey, _T("SkipCompressedFiles"), 1, HKEY_LOCAL_MACHINE);
	}
	objReg.Set(csProductRegKey, _T("ThreatCommunity"), dwSettingVal, HKEY_LOCAL_MACHINE);

	objReg.Get(csProductRegKey, _T("ScanQuarantine"), dw, HKEY_LOCAL_MACHINE);
	if(dw == 0)
	{
		dwProcessMonitor = 1;
		objReg.Set(csProductRegKey, _T("ScanQuarantine"), 1, HKEY_LOCAL_MACHINE);
	}
	if(dwProcessMonitor == 1)
	{
		SetProcessMonitor();
	}
	if(SetGamingMode(false))
	{
		objReg.Set(CSystemInfo::m_csActMonRegKey, GAMINGMODE_KEY, 0, HKEY_LOCAL_MACHINE);
	}
	m_bSysFileProtection = true;
	SystemFileProtection();
	EnableCopyPasteSetting(0);
	EnableReplicatingSetting(0);

	////USB Manager
	m_bWriteButton = m_bExecuteButton = m_bReadButton = m_bBlockAutorun = m_bTotalBlock = false;
	objReg.Set(csProductRegKey, _T("USBScan"), 1, HKEY_LOCAL_MACHINE);
	objReg.Set(csProductRegKey, _T("USBScanMode"), 1, HKEY_LOCAL_MACHINE);
	m_bReadButton = false;
	m_bWriteButton = false;
	m_bExecuteButton = false;
	m_bActivityLogButton = false;
	m_bTotalBlock = false;
	m_bBlockAutorun = true;
	USBManagerSettings();

}

//void CDBImportExportHandler::SendSockProductSettingsMsg(DWORD dw)
//{
//	CRegistry objReg;
//	DWORD dwVal = 0;
//	if(dw == 1)
//	{
//		dwVal = 1;
//		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScan"), dwVal, HKEY_LOCAL_MACHINE);
//		CString csAPPPath, csAutoScanPath;
//		objReg.Get(CSystemInfo::m_csProductRegKey, _T("AppPath"), csAPPPath, HKEY_LOCAL_MACHINE);
//		csAutoScanPath+= csAPPPath;
//		CString csEntry;
//		csEntry = _T("HK_LM[Run]^AUAutoScan^") + csAutoScanPath + _T(" -AUTOSCAN");
//		MAX_PIPE_DATA sMaxPipeData = {0};
//		sMaxPipeData.eMessageInfo = ENUM_OA_INSERTSTARTUP;
//		sMaxPipeData.ulSpyNameID = 0;
//		_tcscpy_s(sMaxPipeData.strValue, csEntry);
//		//theApp.SendOptionsData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
//	}
//	else
//	{
//		dwVal = 0;
//		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScan"), dwVal, HKEY_LOCAL_MACHINE);
//		CString csEntry = _T("HK_LM[Run]AUAutoScan");
//		MAX_PIPE_DATA sMaxPipeData = {0};
//		sMaxPipeData.eMessageInfo = ENUM_OA_DELSTARTUP;
//		sMaxPipeData.ulSpyNameID = 0;
//		_tcscpy_s(sMaxPipeData.strValue, csEntry);
//		theApp.SendOptionsData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
//	}
//	
//}

void CDBImportExportHandler::SetProcessMonitor()
{
	CRegistry objReg;
	DWORD dw = 0;
	
	objReg.Get(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dw, HKEY_LOCAL_MACHINE);
	if(dw)
	{
		PostMessageToProtection(SETPROCESS, OFF);

		for(int i = 0; i < 400; i++)
		{
			//DoEvents();
			Sleep(5);
		}

		PostMessageToProtection(SETPROCESS, ON);
	}

}
void CDBImportExportHandler::ShowGadget(DWORD dw)
{
	CRegistry objReg;
	
	CString csGadgetPath;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AppFolder"), csGadgetPath, HKEY_LOCAL_MACHINE);
	csGadgetPath += _T("Gadget.exe");

	if(dw==1)
	{
		objReg.DeleteValue(RUN_KEY_PATH, SHOW_GADGET_KEY, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, SHOW_GADGET_KEY, 0, HKEY_LOCAL_MACHINE);
		CEnumProcess oProcessMgr;
		oProcessMgr.IsProcessRunning(csGadgetPath, true, true);
	}
	else
	{
		objReg.Set(RUN_KEY_PATH, SHOW_GADGET_KEY, _T("\"") + csGadgetPath + _T("\""), HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, SHOW_GADGET_KEY, 1, HKEY_LOCAL_MACHINE);
		CExecuteProcess oExecutor;
		oExecutor.ExecuteProcess(csGadgetPath, NULL, false, 0);
	}
}

void CDBImportExportHandler::DoEvents()
{
	/*MSG oMsg = {0};

	while(::PeekMessage(&oMsg, m_hWnd, 0, 0, PM_NOREMOVE))
	{
		if(::GetMessage(&oMsg, m_hWnd, 0, 0))
		{
			TranslateMessage(&oMsg);
			DispatchMessage(&oMsg);
		}
		else
		{
			break;
		}
	}*/
}
bool CDBImportExportHandler::PostMessageToProtection(WPARAM wParam, LPARAM lParam)
{
	bool bResult = false;
	bool bStatus = false;
	if(lParam == 1)
	{
		bStatus = true;
	}
	CMaxCommunicator objComm(_NAMED_PIPE_TRAY_TO_ACTMON);

	//writing the data to shared szBuffer.
	SHARED_ACTMON_SWITCH_DATA ActMonSwitchData = {0};
	int nType = (int)wParam;
	ActMonSwitchData.dwMonitorType = nType;
	ActMonSwitchData.bStatus = bStatus;
	ActMonSwitchData.bShutDownStatus = 0;
	if(objComm.SendData(&ActMonSwitchData, sizeof(SHARED_ACTMON_SWITCH_DATA)))
	{
		//m_ProgAutoClean.StepIt();
		if(!objComm.ReadData((LPVOID)&ActMonSwitchData, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			return false;
		}
		//wait broken so read the result.
		/*for(int i = 0; i < 7; i++)
		{
			m_ProgAutoClean.StepIt();
			Sleep(100);
		}*/
		bResult = ActMonSwitchData.bStatus;
	}
	return bResult;
}