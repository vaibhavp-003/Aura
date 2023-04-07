#include "pch.h"
#include "CustomSettings.h"
#include "BKComDll.h"

/*-------------------------------------------------------------------------------------
Function		: CCustomSettings
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CCustomSettings
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
CCustomSettings::CCustomSettings()
{

}

/*-------------------------------------------------------------------------------------
Function		: CCustomSettings
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CCustomSettings
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
CCustomSettings::~CCustomSettings()
{

}
/*-------------------------------------------------------------------------------------
Function		: GetCustomSetting
In Parameters	: Length of Custom Settings , Array Of custom Settings
Out Parameters	: void
Purpose			: Destructor for class CCustomSettings
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
void CCustomSettings::GetCustomSetting(int CustomSettingLength, int* CustomSetting)
{
	CRegistry		objReg;
	CString			csAPPPath;
	DWORD			dwSettingVal = 0;

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csActMonRegKey, _T("ShowKillPopup"), dwSettingVal, HKEY_LOCAL_MACHINE);
	CustomSetting[ShowActMonNotification] = dwSettingVal;

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("CleanTemp"), dwSettingVal, HKEY_LOCAL_MACHINE);
	CustomSetting[CleanTempRecycleFiles] = dwSettingVal;

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("CleanTempIE"), dwSettingVal, HKEY_LOCAL_MACHINE);
	CustomSetting[CleanTempInternetFiles] = dwSettingVal;

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoLiveupdate"), dwSettingVal, HKEY_LOCAL_MACHINE);
	CustomSetting[AutoLiveUpdate] = dwSettingVal;

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoLiveupdateOff"), dwSettingVal, HKEY_LOCAL_MACHINE);
	CustomSetting[LiveUpdateReminder] = dwSettingVal;

	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutomationLab"), dwSettingVal, HKEY_LOCAL_MACHINE);
	CustomSetting[DontQuarantineBackup] = dwSettingVal;
}

/*-------------------------------------------------------------------------------------
Function		: SetCustomSetting
In Parameters	: Setting Enum , Setting Status
Out Parameters	: void
Purpose			: Destructor for class CCustomSettings
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
void CCustomSettings::SetCustomSetting(int iSetting, int iValue)
{

	CRegistry objReg;

	if (iSetting == ShowActMonNotification)
	{
		objReg.Set(CSystemInfo::m_csActMonRegKey, _T("ShowKillPopup"), iValue, HKEY_LOCAL_MACHINE);
	}

	if (iSetting == CleanTempRecycleFiles)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("CleanTemp"), iValue, HKEY_LOCAL_MACHINE);
	}


	if (iSetting == CleanTempInternetFiles)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("CleanTempIE"), iValue, HKEY_LOCAL_MACHINE);
	}

	if (iSetting == AutoLiveUpdate)
	{
		if (iValue == 1)
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoLiveupdate"), iValue, HKEY_LOCAL_MACHINE);
		}
		else
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoLiveupdate"), iValue, HKEY_LOCAL_MACHINE);
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsUpdating"), iValue, HKEY_LOCAL_MACHINE);
		}
	}

	if (iSetting == LiveUpdateReminder)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoLiveupdateOff"), iValue, HKEY_LOCAL_MACHINE);
	}

	if (iSetting == DontQuarantineBackup)
	{
		DWORD dw = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutomationLab"), iValue, HKEY_LOCAL_MACHINE);

		dw = 0;
		objReg.Get(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dw, HKEY_LOCAL_MACHINE);
		if (dw)
		{
			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, OFF);

			for (int i = 0; i < 400; i++)
			{
				Sleep(5);
			}

			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, ON);
		}
	}

}