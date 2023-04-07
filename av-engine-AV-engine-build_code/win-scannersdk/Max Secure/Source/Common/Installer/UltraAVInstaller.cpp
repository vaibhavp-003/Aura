#include "pch.h"
#include "AuUninstall.h"
#include "UltraAVInstaller.h"
#include "MaxProtectionMgr.h"
#include "ValueTypeConst.h"

#include "MaxCommunicator.h"
#include "MaxPipes.h"


CUltraAVInstaller::CUltraAVInstaller(void)
{
	Init();
}

CUltraAVInstaller::~CUltraAVInstaller(void)
{
		
}

void CUltraAVInstaller::Init()
{
	//Initailize all Vairables
	HRESULT iResult = 0;
	TCHAR szProgPath[MAX_PATH] = {0};
	CString csTemp;
	
	wmemset(m_szAppPath, 0, MAX_PATH);
	wmemset(m_szSystemPath, 0, MAX_PATH);

	m_szProductName = _T("UltraAV");
	m_szRegistryKey = ULTRAAV_REG_KEY;
	m_szFolderInAppPath = _T("\\Aura\\UltraAV\\");

	m_oReg.Get(m_szRegistryKey, _T("AppFolder"), csTemp, HKEY_LOCAL_MACHINE);
	if(L"" == csTemp)
	{
		if(SUCCEEDED(SHGetFolderPath(0, CSIDL_PROGRAM_FILES , NULL, 0, szProgPath)))
		{
			_tcscat_s(szProgPath, _countof(szProgPath), _T("\\UltraAV"));
		}		
		if(szProgPath[0])
		{
			_tcscpy_s(m_szAppPath, MAX_PATH, szProgPath);
		}
	}
	else
	{
		_tcscpy_s(m_szAppPath, _countof(m_szAppPath), csTemp);
	}

	memset(szProgPath, 0, sizeof(szProgPath));
	GetSystemDirectory(szProgPath, _countof(szProgPath));
	if(szProgPath[0])
	{
		_tcscpy_s(m_szSystemPath, _countof(m_szSystemPath), szProgPath);
	}

		//make firewall installed folder path
	memset(szProgPath, 0, sizeof(szProgPath));
	iResult = SHGetFolderPath(0, CSIDL_PROGRAM_FILES, 0 ,SHGFP_TYPE_CURRENT, szProgPath);
	if((S_OK == iResult) && (0 != szProgPath[0]))
	{
		_tcscat_s(szProgPath, _countof(szProgPath), _T("\\AuFirewall"));
		_tcscpy_s(m_szFirewallPath, _countof(m_szFirewallPath), szProgPath);
	}
}

void CUltraAVInstaller::UninstalltionStart()
{ 
	int iRet = 0;
	CStringArray csarrProcess;
	AddProcessesInArray(csarrProcess);

	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_REMOVING_PROTECTION").GetBuffer());
	theApp.ShowStatus(1, 10);

	AddLogEntry(L"Removing Protection :");
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RemoveProtection();

	CleanUpService(MAXPROTECTOR_DRIVE_TITLE);
	CleanUpService(ELAM_DRIVE_TITLE);
	
	AddLogEntry(L"Removing Services...");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_REMOVING_SERVICES").GetBuffer());
	theApp.ShowStatus(2, 20);

	MAX_PIPE_DATA_REG sMaxPipeDataReg = { 0 };
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR");
	_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"Start");
	sMaxPipeDataReg.ulSpyNameID = 3;
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
	objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

	DWORD dwVer = 0;
	CRegistry oReg;
	oReg.Get(m_szRegistryKey, _T("Win10"), dwVer, HKEY_LOCAL_MACHINE);
	if(dwVer == 1)
	{	

		CMaxCommunicator objComm1(_NAMED_PIPE_UI_TO_WSCREGSERVICE, true);
		//writing the data to shared buffer.
		SHARED_ACTMON_SWITCH_DATA ActMonSwitchDataEx = { 0 };
		ActMonSwitchDataEx.eProcType = EnableDisablePlugin;
		ActMonSwitchDataEx.dwMonitorType = 0;
		ActMonSwitchDataEx.bStatus = 1;
		ActMonSwitchDataEx.bShutDownStatus = 0;
		OutputDebugString(L"Send mrg to Wws");
		objComm1.SendData(&ActMonSwitchDataEx, sizeof(SHARED_ACTMON_SWITCH_DATA));

		MAX_PIPE_DATA_REG sScanRequest = {0};
		sScanRequest.eMessageInfo = UnRegister_WD_PPL;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, true);
		objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		objMaxCommunicator.ReadData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));

		MAX_PIPE_DATA_REG sScanRequestStop = { 0 };
		sScanRequestStop.eMessageInfo = Enable_Stop_WD_PPL;
		//CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, true);
		objMaxCommunicator.SendData(&sScanRequestStop, sizeof(MAX_PIPE_DATA_REG));
		objMaxCommunicator.ReadData(&sScanRequestStop, sizeof(MAX_PIPE_DATA_REG));

		OutputDebugString(_T("StopWD Done"));
	}
	CString csEarlyLaunch=L"";
	if(oReg.Get(_T("SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch"), _T("BackupPath"), csEarlyLaunch, HKEY_LOCAL_MACHINE))
	{
		csEarlyLaunch = csEarlyLaunch +_T("\\")+ ELAM_DRIVE_FILENAME;
		DeleteFile(csEarlyLaunch);
	}
	
	CleanUpService(MAXWATCHDOG_SVC_NAME);

	AddLogEntry(L"Removing drivers...");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_KILL_PROCESS").GetBuffer());
	theApp.ShowStatus(3, 30);

	CleanUpService(ACTMON_DRIVE_TITLE);
	CleanUpService(MAXMGR_DRIVE_TITLE);
	
	
	AddLogEntry(L"Killing Process...");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_KILL_PROCESS").GetBuffer());
	theApp.ShowStatus(4, 40);

	KillProcesses(csarrProcess);
	
	AddLogEntry(L"Unregistering COM Components...");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_UNREGISTER_COMPONENTS").GetBuffer());
	theApp.ShowStatus(5, 50);

	DllUnRegisterComponents(m_szAppPath);

	AddLogEntry(L"Removing Registry Keys...");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_REMOVE_REGISTRY_KEYS").GetBuffer());
	theApp.ShowStatus(6, 60);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\PLA\\UltraAV"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(VALTYPE_UNINSTALL_KEY) + _T("\\UltraAV"));

	/*Removing WPD Device Blocking Registry*/
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices");

#ifdef WIN64
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Wow6432Node\\UltraAV"));
#endif
	
	AddLogEntry(L"Uninstall Partial");
}

void CUltraAVInstaller::AddProcessesInArray(CStringArray &arrProcesses)
{
	arrProcesses.Add(UI_EXENAME);
	arrProcesses.Add(MAXWATCHDOG_SVC_EXE);
	arrProcesses.Add(MAX_SCANNER);
	arrProcesses.Add(ACT_MON_TRAY_EXE);
	arrProcesses.Add(LIVEUPDATE_EXE);
	arrProcesses.Add(ACTMON_SVC_NAME);
	arrProcesses.Add(MAXMERGER_SVC_EXE);
	arrProcesses.Add(_T("AuDBServer.exe"));
	arrProcesses.Add(_T("AuUSB.EXE"));
	arrProcesses.Add(_T("AuMAILPROXY.EXE"));
	arrProcesses.Add(_T("AuFWPnP.exe"));
	arrProcesses.Add(_T("AuUnpackExe.exe"));
}
void CUltraAVInstaller::StartCleanUp()
{
	AddLogEntry(L"Deleting Shortcut Files..");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_DELETE_SHORTCUT").GetBuffer());
	theApp.ShowStatus(7, 70);

	CleanUpShortCut(m_szProductName, m_szRegistryKey);
	CleanUpStartMenu(m_szProductName);
	
	if (PathFileExists(m_szSystemPath + (CString)L"\\drivers\\" + MAXPROTECTOR_DRIVE_FILENAME))
	{
		DeleteFile(m_szSystemPath + (CString)L"\\drivers\\" + MAXPROTECTOR_DRIVE_FILENAME);
	}
	if (PathFileExists(m_szSystemPath + (CString)L"\\drivers\\" + ACTMON_DRIVE_FILENAME))
	{
		DeleteFile(m_szSystemPath + (CString)L"\\drivers\\" + ACTMON_DRIVE_FILENAME);
	}
	if (PathFileExists(m_szSystemPath + (CString)L"\\drivers\\" + MAXMGR_DRIVE_FILENAME))
	{
		DeleteFile(m_szSystemPath + (CString)L"\\drivers\\" + MAXMGR_DRIVE_FILENAME);
	}
	if (PathFileExists(m_szSystemPath + (CString)L"\\drivers\\_" + FW_DRIVER_SYS))
	{
		DeleteFile(m_szSystemPath + (CString)L"\\drivers\\_" + FW_DRIVER_SYS);
	}
	if (PathFileExists(m_szSystemPath + (CString)L"\\drivers\\_" + MAXPROTECTOR_DRIVE_FILENAME))
	{
		DeleteFile(m_szSystemPath + (CString)L"\\drivers\\_" + MAXPROTECTOR_DRIVE_FILENAME);
	}
	if (PathFileExists(m_szSystemPath + (CString)L"\\drivers\\" + ELAM_DRIVE_FILENAME))
	{
		DeleteFile(m_szSystemPath + (CString)L"\\drivers\\" + ELAM_DRIVE_FILENAME);
	}


	AddLogEntry(L"Deleting Files & Folders..");
	//theApp.SendMessageToUI(WM_USER_MESSAGES, WM_SETTEXT, (LPARAM)theApp.m_pResMgr->GetString(L"IDS_DELETE_FILES").GetBuffer());
	theApp.ShowStatus(8, 80);

	CleanUpProdRegKey(m_szProductName, m_szRegistryKey);

	CleanUpPFFolder(m_szProductName, m_szAppPath, NULL, true, true);
	CompleteUninst(m_szProductName, m_szFolderInAppPath);
	theApp.ShowStatus(9, 90);
	CreateRansomBackupFolder();

	CleanUpPFFolder(m_szProductName, m_szFirewallPath, NULL, true, true);
	DeleteFilesFolders(m_szAppPath, m_szProductName);
	theApp.ShowStatus(10, 100);
	AddLogEntry(L"Uninstall Done Successfully");
}