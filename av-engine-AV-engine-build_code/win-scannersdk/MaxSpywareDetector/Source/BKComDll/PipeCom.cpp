#include "pch.h"
#include "BKComDll.h"
#include "PipeCom.h"




CMaxCommunicatorServer m_objMaxComServDB(_NAMED_PIPE_SCANNER_TO_UI, CPipeCom::OnDataReceivedCallBack, sizeof(MAX_PIPE_DATA_REG));
int m_iCounter = 0;
UINT LaunchUIComServ(LPVOID lpVoid)
{
	OutputDebugString(_T("LaunchUIComServ"));
	m_objMaxComServDB.Run();
	return 0;
}
bool CPipeCom::CreateComServer(CString csPipeName)
{
	return true;
}
bool CPipeCom::CreateUIComServer()
{
	/*MAX_PIPE_DATA_REG sMaxPipeDataReg = {0};
	MAX_PIPE_DATA sMaxPipeData = { 0 };
	int iSize = sizeof(sMaxPipeDataReg);
	iSize = sizeof(sMaxPipeData);*/
	AfxBeginThread(LaunchUIComServ, this);
	
	return true;
}
bool CPipeCom::CreateComClient(CString csPipeName, LPVOID lpParam, bool bWait)
{
	CMaxCommunicator objCom(csPipeName);

	LPMAX_PIPE_DATA_REG sMaxPipeData = (MAX_PIPE_DATA_REG*)lpParam;
	if (objCom.SendData(sMaxPipeData, sizeof(MAX_PIPE_DATA_REG)))
	{
		if(bWait)
		{
			objCom.ReadData((LPVOID)sMaxPipeData, sizeof(MAX_PIPE_DATA_REG));
		}
	}
	return true;
}
void CPipeCom::OnDataReceivedCallBack(LPVOID lpMaxParam)
{
	OutputDebugString(_T("OnDataReceivedCallBack"));
	TCHAR szResponse[MAX_PATH] = { 0x00 };
	LPMAX_PIPE_DATA_REG sMaxPipeData = (MAX_PIPE_DATA_REG*)lpMaxParam;
	
	if (!sMaxPipeData)
	{
		return;
	}

	if (sMaxPipeData->eMessageInfo == Process)
	{
		_stprintf_s(szResponse, L"Com Srv %s", sMaxPipeData->strBackup);
		//OutputDebugString(_T("Recieve data"));
		//OutputDebugString(szResponse);
		UScanStatusData objData = {0};
		objData.iMessageId = 1;
		objData.dwFilesCount = m_iCounter;
		objData.dwThreatCount = m_iCounter/10;
		
		if (m_iCounter >= 10000)
		{
			objData.iPercentage = 99;
		}
		else 
		{
			objData.iPercentage = (m_iCounter * 100) / 10000;
		}
		_stprintf_s(szResponse, _T("%d: %s"), objData.iPercentage, sMaxPipeData->strBackup);
		OutputDebugString(szResponse);
		if (m_iCounter >= 10 && objData.iPercentage== 0)
		{
			objData.iPercentage = 1;
		}
		_stprintf_s(objData.szData, _T("%s%d"), sMaxPipeData->strBackup, m_iCounter);
		//objData.szData.Format(_T("%s"), sMaxPipeData->strBackup);
		if(theApp.m_pSendMsgUltraUI != NULL)
		{
			theApp.m_pSendMsgUltraUI(objData);
		}		
		m_iCounter++;
		return;
	}
	else if(sMaxPipeData->eMessageInfo == SendGuid)
	{
		theApp.m_csScannerID = sMaxPipeData->strValue;
		return;
	}
	m_objMaxComServDB.SendResponse(sMaxPipeData);
}
bool CPipeCom::PostMessageToProtection(WPARAM wParam, LPARAM lParam)
{
	bool bResult = false;
	bool bStatus = false;
	if (lParam == 1)
	{
		bStatus = true;
	}
	CMaxCommunicator objComm(_NAMED_PIPE_TRAY_TO_ACTMON);

	//writing the data to shared szBuffer.
	SHARED_ACTMON_SWITCH_DATA ActMonSwitchData = { 0 };
	int nType = (int)wParam;
	ActMonSwitchData.dwMonitorType = nType;
	ActMonSwitchData.bStatus = bStatus;
	ActMonSwitchData.bShutDownStatus = 0;
	if (objComm.SendData(&ActMonSwitchData, sizeof(SHARED_ACTMON_SWITCH_DATA)))
	{
		if (!objComm.ReadData((LPVOID)&ActMonSwitchData, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			return false;
		}
		bResult = ActMonSwitchData.bStatus;
	}
	return bResult;
}
bool CPipeCom::PostMessageToService(int iType, int iStatus)
{
	bool bResult = true;
	if (iType == CopyProtection)
	{
		MAX_PIPE_DATA_REG oPipeData = { 0 };
		oPipeData.eMessageInfo = SetCopyPasteSetting;
		oPipeData.ulSpyNameID = 1;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		oPipeData.ulSpyNameID = iStatus;
		if (!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
		{
			AddLogEntry(_T("### SendData Failed In CPipeCom::PostMessageToService"));
			bResult = false;
		}
	}	
	else if (iType == BlockReplicatingPattern)
	{
		MAX_PIPE_DATA_REG oPipeData = { 0 };
		oPipeData.eMessageInfo = Enable_Replication;
		oPipeData.ulSpyNameID = 1;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		oPipeData.ulSpyNameID = iStatus;
		if (!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
		{
			AddLogEntry(_T("### SendData Failed In CPipeCom::PostMessageToService"));
			bResult = false;
		}
	}
	/*else if(iType == GameMode)
	{
		MAX_PIPE_DATA_REG oPipeData = { 0 };
		oPipeData.eMessageInfo = GamingMode;
		oPipeData.ulSpyNameID = (ULONG)iStatus;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		if (!objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG)))
		{
			AddLogEntry(_T("### SendData Failed In CPipeCom::PostMessageToService"));
			bResult = false;
		}
	}*/
	else if (iType == ProtectSysRegistry)
	{
		try
		{
			MAX_PIPE_DATA_REG sMaxPipeDataReg = { 0 };
			CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
			sMaxPipeDataReg.eMessageInfo = Set_RegistrySetting;
			sMaxPipeDataReg.Type_Of_Data = REG_DWORD;

			_tcscpy_s(sMaxPipeDataReg.strKey, _countof(sMaxPipeDataReg.strKey), MAX_PROTECTOR_REG_KEY);
			
			_tcscpy_s(sMaxPipeDataReg.strValue, _countof(sMaxPipeDataReg.strValue), _T("ProtectSystemRegistry"));
			sMaxPipeDataReg.ulSpyNameID = iStatus;
			sMaxPipeDataReg.Hive_Type = HKEY_LOCAL_MACHINE;
			objMaxCommunicator.SendData(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		}
		catch (...)
		{
			AddLogEntry(L"Exception in CPipeCom::PostMessageToService");
		}
	}
	return bResult;
}


bool CPipeCom::PostMessageToWSCSrv(WPARAM wParam, LPARAM lParam)
{
	int nType = (int)wParam;
	bool bStatus = false;
	if (lParam == 1)
	{
		bStatus = true;
	}
	CMaxCommunicator objComm1(_NAMED_PIPE_UI_TO_WSCREGSERVICE, true);

	//writing the data to shared buffer.
	SHARED_ACTMON_SWITCH_DATA ActMonSwitchDataEx = { 0 };
	ActMonSwitchDataEx.dwMonitorType = nType;
	ActMonSwitchDataEx.bStatus = bStatus;
	ActMonSwitchDataEx.bShutDownStatus = 0;
	objComm1.SendData(&ActMonSwitchDataEx, sizeof(SHARED_ACTMON_SWITCH_DATA));
	return true;

}