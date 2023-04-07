#include "pch.h"
#include "AdvanceSettings.h".
#include "Registry.h"
#include "SDSystemInfo.h"
#include "MaxProtectionMgr.h"
#include "BKComDll.h"
#include "MaxDSrvWrapper.h"

/*-------------------------------------------------------------------------------------
Function		: GetAdvanceSettingsData
In Parameters	: int iAdvanceSettingLength, int* ptrAdvanceSetting
Out Parameters	: -
Description		: Get Advance Setting from Registry
--------------------------------------------------------------------------------------*/
void CAdvanceSettings::GetAdvanceSettingsData(int iAdvanceSettingLength, int* ptrAdvanceSetting)
{
	CRegistry		objReg;
	CString			csAPPPath;
	DWORD			dwSettingVal = 0;

	//Scan windows startup
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoScan"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[WindowStartScan] = dwSettingVal;

	//Skip compress
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("SkipCompressedFiles"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[SkipCompressFile] = dwSettingVal;

	//Protect System Registry
	dwSettingVal = 0;
	CMaxProtectionMgr objProtMgr;
	objProtMgr.GetProtectSysRegKeyStatus(dwSettingVal);
	ptrAdvanceSetting[ProtectSysRegistry] = dwSettingVal; 

	//Enable on copy protection
	dwSettingVal = 0;
	objReg.Get(ACTMON_SERVICE_PATH, L"EnableCopyPaste", dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[CopyProtection] = dwSettingVal;

	//Block Replicating pattern
	dwSettingVal = 0;
	objReg.Get(ACTMON_SERVICE_PATH, L"EnableReplicating", dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[BlockReplicatingPattern] = dwSettingVal;


	////Auto Quarantine
	//If unregister or subscription expired set the value to 0 and disable the checkbox
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[AutoQuarantine] = dwSettingVal;

	////Clean Browser
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("CleanBrowsers"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[CleanBroswer] = dwSettingVal;

	////Heuristic Scan ML
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("MacLearning"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[HeuristicScanML] = dwSettingVal;

	////Cookies Scan
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("CookiesScan"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[CookiesScan] = dwSettingVal;

	//Gaming Mode
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csActMonRegKey, _T("GamingMode"), dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[EnableGamingMode] = dwSettingVal;

	//Active Protection
	dwSettingVal = 0;
	objReg.Get(CSystemInfo::m_csActMonRegKey, PROCESS_KEY, dwSettingVal, HKEY_LOCAL_MACHINE);
	ptrAdvanceSetting[ActiveMonitor] = dwSettingVal;

}
void CAdvanceSettings::SetAdvanceSettingsData(int iSetOption, int iSetVal)
{
	CRegistry objReg;

	if (iSetOption == WindowStartScan)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScan"), iSetVal, HKEY_LOCAL_MACHINE);
	}

	if (iSetOption == SkipCompressFile)
	{
		DWORD dwVal = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("SkipCompressedFiles"), iSetVal, HKEY_LOCAL_MACHINE);

		dwVal = 0;
		objReg.Get(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dwVal, HKEY_LOCAL_MACHINE);
		if (dwVal)
		{
			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, OFF);

			for (int i = 0; i < 400; i++)
			{
				Sleep(5);
			}

			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, ON);
		}
	}
	
	//PostMessageToProtection
	if (iSetOption == ProtectSysRegistry)
	{
		try
		{
			MAX_PIPE_DATA_REG sMaxPipeDataReg = { 0 };
			CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
			sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
			sMaxPipeDataReg.Type_Of_Data = REG_DWORD;
			_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), MAX_PROTECTOR_REG_KEY);
			
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), _T("ProtectSystemRegistry"));
			sMaxPipeDataReg.ulSpyNameID = iSetVal;
			sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}
		catch (...)
		{
			AddLogEntry(L"Exception in CPipeCom::PostMessageToService");
		}
	}

	//PostMessageToProtection
	if (iSetOption == CopyProtection)
	{
		
		MAX_PIPE_DATA_REG oPipeData = { 0 };
		oPipeData.eMessageInfo = SetCopyPasteSetting;
		oPipeData.ulSpyNameID = 1;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		oPipeData.ulSpyNameID = iSetVal;
		if (!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
		{
			AddLogEntry(_T("### SendData Failed In CPipeCom::PostMessageToService"));
		}
		
	}

	//PostMessageToProtection
	if (iSetOption == BlockReplicatingPattern)
	{
		MAX_PIPE_DATA_REG oPipeData = { 0 };
		oPipeData.eMessageInfo = Enable_Replication;
		oPipeData.ulSpyNameID = 1;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		oPipeData.ulSpyNameID = iSetVal;
		if (!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
		{
			AddLogEntry(_T("### SendData Failed In CPipeCom::PostMessageToService"));
		}
	}

	//PostMessageToProtection
	if (iSetOption == AutoQuarantine)
	{
		DWORD dwVal = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), iSetVal, HKEY_LOCAL_MACHINE);
		dwVal = 0;
		objReg.Get(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dwVal, HKEY_LOCAL_MACHINE);
		if (dwVal)
		{
			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, OFF);

			for (int i = 0; i < 400; i++)
			{
				Sleep(5);
			}

			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, ON);
		}
	}
	 
	if (iSetOption == CleanBroswer)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("CleanBrowsers"), iSetVal, HKEY_LOCAL_MACHINE);
	}

	if (iSetOption == HeuristicScanML)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("MacLearning"), iSetVal, HKEY_LOCAL_MACHINE);
	}

	if (iSetOption == CookiesScan)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("CookiesScan"), iSetVal, HKEY_LOCAL_MACHINE);
	}

	if (iSetOption == EnableGamingMode)
	{
		if (iSetVal == 0)
		{
			SetGamingMode(false);
		}
		else
		{
			SetGamingMode(true);
		}
		objReg.Set(CSystemInfo::m_csActMonRegKey, GAMINGMODE_KEY, iSetVal, HKEY_LOCAL_MACHINE);
	}
	
	if (iSetOption == ActiveMonitor)
	{
		if (iSetVal == 0)
		{
			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, OFF);
			theApp.m_objPipeCom.PostMessageToWSCSrv(SETPROCESS, OFF);
			objReg.Set(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", iSetVal, HKEY_LOCAL_MACHINE);
		}
		else
		{
			theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, ON);
			theApp.m_objPipeCom.PostMessageToWSCSrv(SETPROCESS, ON);
			objReg.Set(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", iSetVal, HKEY_LOCAL_MACHINE);
		}
		
	}
	
}


bool CAdvanceSettings::SetGamingMode(bool bStatus)
{
	CMaxDSrvWrapper objMaxDSrvWrapper; 
	bool bRetVal = objMaxDSrvWrapper.SetGamingMode(bStatus);

	MAX_PIPE_DATA_REG oPipeData = { 0 };
	oPipeData.eMessageInfo = GamingMode;
	oPipeData.ulSpyNameID = (ULONG)bStatus;
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG));

	return bRetVal;
}