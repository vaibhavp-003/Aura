#include "pch.h"
#include "USBManager.h"
#include "SDSystemInfo.h"
#include "MaxProtectionMgr.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "USBDbOperations.h"

CUSBManager::CUSBManager()
{
	/*
	m_bScanDevice = false;
	m_bAutoScanUsb = false;
	m_bManualScan = false;

	m_bReadButton = false;
	m_bWriteButton = false;
	m_bExecuteButton = false;
	m_bUSBLogButton = false;
	m_bUSBWhitelist = false;
	*/
}

CUSBManager::~CUSBManager()
{

}

void CUSBManager::GetInitialStatus()
{
	/*DWORD dw = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBScan"), dw, HKEY_LOCAL_MACHINE);
	if (dw == 1)
	{
		m_bScanDevice = true;
		dw = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBScanMode"), dw, HKEY_LOCAL_MACHINE);
		if (dw == 1)
		{
			m_bAutoScanUsb = true;
			m_bManualScan = false;
		}
		else
		{
			m_bAutoScanUsb = false;
			m_bManualScan = true;
		}
	}
	else
	{
		m_bScanDevice = false;
		m_bAutoScanUsb = true;
		m_bManualScan = false;
	}*/
}

void CUSBManager::WriteUsbRegistrySettings(int iType, ULONG ulUsbSettings)
{

	MAX_PIPE_DATA_REG sMaxPipeDataReg = { 0 };
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);

	memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;

	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
	sMaxPipeDataReg.ulSpyNameID = ulUsbSettings;
	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), ACTMON_REG_KEY);

	{
		if (iType == 0)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-READ");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}

		if (iType == 1)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-WRITE");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}

		if (iType == 2)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-EXECUTE");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}

		if (iType == 3)
		{
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"USB-ACTIVITY");
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}
	}
}
void CUSBManager::SendDataToDriver(ULONG ulIoCode, ULONG data)
{
	DWORD dwReturn;
	HANDLE hFile = CreateFile(ACTMON_DRIVE_SYMBOLIC, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("ACTMON drv handle created\n");
		DeviceIoControl(hFile, ulIoCode, &data, sizeof(ULONG), &data, sizeof(ULONG), &dwReturn, NULL);
		CloseHandle(hFile);
	}
}

void CUSBManager::WriteUSBSettings(USBSetting* pUSBSetting)
{
	ULONG ulData = 0;
	if (pUSBSetting->iWriteBlock == 1)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_WRITE_BLOCK, ulData);
		WriteUsbRegistrySettings(1, 1);
	}
	else
	{
		SendDataToDriver(IOCTL_USB_WRITE_BLOCK, ulData);
		WriteUsbRegistrySettings(1, 0);
	}

	Sleep(100);

	ulData = 0;
	if (pUSBSetting->iExecuteBlock == 1)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_EXECUTE_BLOCK, ulData);
		WriteUsbRegistrySettings(2, 1);
	}
	else
	{
		SendDataToDriver(IOCTL_USB_EXECUTE_BLOCK, ulData);
		WriteUsbRegistrySettings(2, 0);
	}

	Sleep(100);

	ulData = 0;
	if (pUSBSetting->iReadBlock == 1)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_READ_BLOCK, ulData);
		WriteUsbRegistrySettings(0, 1);

	}
	else
	{
		SendDataToDriver(IOCTL_USB_READ_BLOCK, ulData);
		WriteUsbRegistrySettings(0, 0);
	}

	Sleep(100);

	ulData = 0;
	if (pUSBSetting->iActivityLog == 1)
	{
		ulData = 1;
		SendDataToDriver(IOCTL_USB_ACTIVITY_LOG, ulData);
		WriteUsbRegistrySettings(3, 1);

	}
	else
	{
		SendDataToDriver(IOCTL_USB_ACTIVITY_LOG, ulData);
		WriteUsbRegistrySettings(3, 0);
	}

	Sleep(100);
}

void CUSBManager::SetUSBSettings(USBSetting* pUSBSetting)
{ 
	DWORD dw = 0;
	WriteUSBSettings(pUSBSetting);

	if (pUSBSetting->iScanRemovable == 1)
	{
		dw = 1;
	}
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("USBScan"), dw, HKEY_LOCAL_MACHINE);

	if (pUSBSetting->iAutoManualScan == 1)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("USBScanMode"), 1, HKEY_LOCAL_MACHINE);
	}
	else
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("USBScanMode"), 0, HKEY_LOCAL_MACHINE);
	}

	if (pUSBSetting->iUSBWhiteList == 1)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("USBWhiteList"), 1, HKEY_LOCAL_MACHINE);
	}
	else
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("USBWhiteList"), 0, HKEY_LOCAL_MACHINE);
	}

	if (pUSBSetting->iDontAskPassword == 1)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AskUSBPassword"), 1, HKEY_LOCAL_MACHINE);
	}
	else
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AskUSBPassword"), 0, HKEY_LOCAL_MACHINE);
	}
	if (pUSBSetting->iBlockPhoneDevices == 1)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("BlockWPDDevice"), 1, HKEY_LOCAL_MACHINE);
	}
	else
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("BlockWPDDevice"), 0, HKEY_LOCAL_MACHINE);
	}


	MAX_PIPE_DATA_REG sMaxPipeDataReg = { 0 };
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);

	DWORD dwr = 1;
	DWORD dwAutoCheck = pUSBSetting->iAutoRunINFBlock;

	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), MAX_PROTECTOR_REG_KEY);
	
	_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), _T("BlockAutorun"));
	sMaxPipeDataReg.ulSpyNameID = dwAutoCheck;
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
	objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

	dw = 3;
	if (pUSBSetting->iTotalBlock == 1)
	{
		dw = 4;
	}
	memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
	sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
	sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
	_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR");
	_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"Start");
	sMaxPipeDataReg.ulSpyNameID = dw;
	sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
	objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

	if (pUSBSetting->iAskPhoneRestart == 1)
	{

		memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
		sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
		sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
		_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{6AC27878-A6FA-4155-BA85-F98F491D4F33}");
		_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"Deny_Read");
		if (pUSBSetting->iBlockPhoneDevices == 1)
		{
			sMaxPipeDataReg.ulSpyNameID = 1;
		}
		else
		{
			sMaxPipeDataReg.ulSpyNameID = 0;
		}
		sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
		objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

		memset(&sMaxPipeDataReg, 0, sizeof(sMaxPipeDataReg));
		sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
		sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
		_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}");
		_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), L"Deny_Read");
		if (pUSBSetting->iBlockPhoneDevices == 1)
		{
			sMaxPipeDataReg.ulSpyNameID = 1;
		}
		else
		{
			sMaxPipeDataReg.ulSpyNameID = 0;
		}
		sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
		objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

		/*
		CYesNoMsgBoxDlg objMessageBox;
		//CYesNoMsgBox objMessageBox;
		objMessageBox.m_csMessage = theApp.m_pResMgr->GetString(L"IDS_REBOOT_MSG_WPD");
		if (objMessageBox.DoModal() == IDOK)
		{
			CEnumProcess objEnumProcess;
			objEnumProcess.RebootSystem(0);
		}
		*/
	}

}
void CUSBManager::GetUSBSettings(USBSetting* pUSBSetting)
{
	DWORD dw = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBScan"), dw, HKEY_LOCAL_MACHINE);
	if (dw == 1)
	{
		m_bScanDevice = true;
		pUSBSetting->iScanRemovable = 1;
		//USBSettings[USBSetting::ScanRemovable] = 1; //Checked Removable Scan
		dw = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBScanMode"), dw, HKEY_LOCAL_MACHINE);
		if (dw == 1)
		{
			pUSBSetting->iAutoManualScan = 1;
			//USBSettings[USBSetting::AutoManual] = 1; //Radio Button Auto
			m_bAutoScanUsb = true;
			m_bManualScan = false;
		}
		else
		{
			pUSBSetting->iAutoManualScan = 0;
			//USBSettings[USBSetting::AutoManual] = 0; //Radio Button Manual
			m_bAutoScanUsb = false;
			m_bManualScan = true;
		}
	}
	else
	{
		pUSBSetting->iScanRemovable = 0;
		pUSBSetting->iAutoManualScan = 1;
		//USBSettings[USBSetting::ScanRemovable] = 0; //UnChecked Removable Scan
		//USBSettings[USBSetting::AutoManual] = 1; // //Radio Button Auto
		m_bScanDevice = false;
		m_bAutoScanUsb = true;
		m_bManualScan = false;
	}

	dw = 0;

	if (ReadUsbRegistrySettings(0) == 1)
	{
		pUSBSetting->iReadBlock = 1;
		//USBSettings[USBSetting::ReadBlock] = 1;
		m_bReadButton = true;

	}
	else
	{
		pUSBSetting->iReadBlock = 0;
		//USBSettings[USBSetting::ReadBlock] = 0;
		m_bReadButton = false;
	}

	Sleep(100);

	if (ReadUsbRegistrySettings(1) == 1)
	{
		pUSBSetting->iWriteBlock = 1;
		//USBSettings[USBSetting::WriteBlock] = 1;
		m_bWriteButton = true;
	}
	else
	{
		pUSBSetting->iWriteBlock= 0;
		//USBSettings[USBSetting::WriteBlock] = 0;
		m_bWriteButton = false;
	}

	Sleep(100);

	if (ReadUsbRegistrySettings(2) == 1)
	{
		pUSBSetting->iExecuteBlock = 1;
		//USBSettings[USBSetting::ExecuteBlock] = 1;
		m_bExecuteButton = true;
	}
	else
	{
		pUSBSetting->iExecuteBlock = 0;
		//USBSettings[USBSetting::ExecuteBlock] = 0;
		m_bExecuteButton = false;
	}

	Sleep(100);

	if (ReadUsbRegistrySettings(3) == 1)
	{
		pUSBSetting->iActivityLog = 1;
		//USBSettings[USBSetting::ActivityLog] = 1;
		m_bUSBLogButton = true;
	}
	else
	{
		pUSBSetting->iActivityLog = 0;
		//USBSettings[USBSetting::ActivityLog] = 0;
		m_bUSBLogButton = false;
	}

	DWORD dwUSBWhitelist = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("USBWhiteList"), dwUSBWhitelist, HKEY_LOCAL_MACHINE);//checkbox setting for USB whitelist
	if (dwUSBWhitelist == 1)
	{
		pUSBSetting->iUSBWhiteList = 1;
		//USBSettings[USBSetting::USBWhiteList] = 1;
		m_bUSBWhitelist = true;
	}
	else
	{
		pUSBSetting->iUSBWhiteList = 0;
		//USBSettings[USBSetting::USBWhiteList] = 0;
		m_bUSBWhitelist = false;
	}

	m_bAskForRestart = false;

	DWORD dwUSBPWD = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("BlockWPDDevice"), dwUSBPWD, HKEY_LOCAL_MACHINE);//checkbox setting for Block WPD Device
	if (dwUSBPWD == 1)
	{
		pUSBSetting->iBlockPhoneDevices = 1;
		//USBSettings[USBSetting::BlockPhoneDevices] = 1;
		m_bBlockPhones = true;
	}
	else
	{
		pUSBSetting->iBlockPhoneDevices = 0;
		//USBSettings[USBSetting::BlockPhoneDevices] = 0;
		m_bBlockPhones = false;
	}

	dwUSBPWD = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AskUSBPassword"), dwUSBPWD, HKEY_LOCAL_MACHINE);//checkbox setting for USB whitelist
	if (dwUSBPWD == 1)
	{
		pUSBSetting->iDontAskPassword = 1;
		//USBSettings[USBSetting::DontAskPassword] = 1;
		m_bUSBPWD = true;
	}
	else
	{
		pUSBSetting->iDontAskPassword = 0;
		//USBSettings[USBSetting::DontAskPassword] = 0;
		m_bUSBPWD = false;
	}

	dw = 3;
	objReg.Get(L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR", L"Start", dw, HKEY_LOCAL_MACHINE);
	if (dw == 4)
	{
		pUSBSetting->iTotalBlock = 1;
		//USBSettings[USBSetting::TotalBlock] = 1;
		m_bTotalBlock = true;
	}
	else
	{
		pUSBSetting->iTotalBlock = 0;
		//USBSettings[USBSetting::TotalBlock] = 0;
		m_bTotalBlock = false;
	}

	dw = 0;
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.GetBlockAutoRunStatus(dw);
	if (dw == 1)
	{
		pUSBSetting->iAutoRunINFBlock = 1;
		//USBSettings[USBSetting::AutoRunINFBlock] = 1;
		m_bBlockAutorun = true;
	}
	else
	{
		pUSBSetting->iAutoRunINFBlock = 0;
		//USBSettings[USBSetting::AutoRunINFBlock] = 0;
		m_bBlockAutorun = false;
	}
	
}

int CUSBManager::ReadUsbRegistrySettings(ULONG ulTypeOfKey)
{

	HKEY hKey;
	DWORD dw = 0;
	DWORD data;
	DWORD iValue = 0, dwLen = 0;
	DWORD dwType = REG_DWORD;
	int returnVal = 0;
	DWORD lResult;


	if (::RegOpenKeyEx(HKEY_LOCAL_MACHINE, ACTMON_REG_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		CString str;

		if (ulTypeOfKey == 0)
		{
			lResult = RegQueryValueEx(hKey, L"USB-READ", NULL, &dwType, (LPBYTE)&data, &dw);

			if (::RegQueryValueEx(hKey, L"USB-READ", NULL, &dwType, (LPBYTE)&data, &dw) == ERROR_SUCCESS)
			{
				returnVal = (int)data;
			}
			else
			{
				returnVal = 0;
			}
		}

		if (ulTypeOfKey == 1)
		{
			lResult = RegQueryValueEx(hKey, L"USB-WRITE", NULL, &dwType, (LPBYTE)&data, &dw);

			if (::RegQueryValueEx(hKey, L"USB-WRITE", NULL, &dwType, (LPBYTE)&data, &dw) == ERROR_SUCCESS)
			{
				returnVal = (int)data;
			}
			else
			{
				returnVal = 0;
			}
		}

		if (ulTypeOfKey == 2)
		{
			lResult = RegQueryValueEx(hKey, L"USB-EXECUTE", NULL, &dwType, (LPBYTE)&data, &dw);

			if (::RegQueryValueEx(hKey, L"USB-EXECUTE", NULL, &dwType, (LPBYTE)&data, &dw) == ERROR_SUCCESS)
			{
				returnVal = (int)data;
			}
			else
			{
				returnVal = 0;
			}
		}
		if (ulTypeOfKey == 3)
		{
			lResult = RegQueryValueEx(hKey, L"USB-ACTIVITY", NULL, &dwType, (LPBYTE)&data, &dw);

			if (::RegQueryValueEx(hKey, L"USB-ACTIVITY", NULL, &dwType, (LPBYTE)&data, &dw) == ERROR_SUCCESS)
			{
				returnVal = (int)data;
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

int CUSBManager::LoadUSBListCnt()
{
	int iUCnt = 0;
	CProductInfo objProductInfo;
	CString csAppPath = objProductInfo.GetInstallPath();
	CString csWhiteUSBDB = csAppPath + L"WhiteUSB.db";
	CS2S objS2S(false);
	objS2S.Load(csWhiteUSBDB);
	iUCnt = objS2S.GetCount();
	return iUCnt;
}


void CUSBManager::LoadUSBList(AttachedUSB* pAttachedUSB, int iAttachedUSBCnt)
{
	CProductInfo objProductInfo;
	CString csAppPath = objProductInfo.GetInstallPath();
	CString csWhiteUSBDB = csAppPath + L"WhiteUSB.db";
	CS2S objS2S(false);
	objS2S.Load(csWhiteUSBDB);

	int iCount = 0;
	LPVOID lpUSBSerial = objS2S.GetFirst();
	while (lpUSBSerial)
	{
		TCHAR* szUSBSerial = NULL;
		TCHAR* szUSBName = NULL;
		objS2S.GetKey(lpUSBSerial, szUSBSerial);
		objS2S.GetData(lpUSBSerial, szUSBName);
		//pAttachedUSB[iCount].szUSBDrive
		
		//int index = m_lstUSBList.InsertItem(iCount, szUSBName);
		//m_lstUSBList.SetItemText(iCount, 1, szUSBSerial);
		wcscpy_s(pAttachedUSB[iCount].szUSBDrive, szUSBName);
		wcscpy_s(pAttachedUSB[iCount].szUSBSerialNumber, szUSBSerial);
		iCount++;
		lpUSBSerial = objS2S.GetNext(lpUSBSerial);
	}
}

void CUSBManager::DeleteUSBList(AttachedUSB* pAttachedUSB, int iAttachedUSBCnt)
{
	CUSBDbOperations objUSBDbOperations;
	objUSBDbOperations.LoadDB();
	int icount = iAttachedUSBCnt;
	BOOL bchkState = FALSE;
	DWORD dwData = 0;

	for (int nItem = 0; nItem < icount; nItem++)
	{
		CString csSerialNumber = pAttachedUSB[nItem].szUSBSerialNumber;
		objUSBDbOperations.DeleteSerialNo(csSerialNumber);
		nItem++;
	}
	objUSBDbOperations.SaveDB();
}

bool CUSBManager::ViewUSBActivityLog()
{
	CString	csAppPath = CSystemInfo::m_strAppPath + _T("Log\\USBActivityLog.txt");
	SetLastError(0);
	if (_waccess(csAppPath, 0) == 0)
	{
		ShellExecute(NULL, _T("Open"), csAppPath, NULL, NULL, SW_NORMAL);
		return true;
	}
	return false;
}