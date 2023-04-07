#include "pch.h"
#include "MaxMergerWrapper.h"

CMaxMergerWrapper::CMaxMergerWrapper(void):m_pMaxProductMerger(NULL)
{
}

CMaxMergerWrapper::~CMaxMergerWrapper(void)
{
}

void CMaxMergerWrapper::ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	if(lpDispatchMessage->eDispatch_Type == eLoadMerger)
	{
		
		// creating this object here so that all static members are initialized!
		while(true)
		{
			CSystemInfo oSysInfo;
			if(oSysInfo.m_strAppPath.Trim().GetLength() == 0)
			{
				AddLogEntry(L"AppPath is not initialized!");
				Sleep(60000);
			}
			else
			{
				AddLogEntry(L"Application Installed Path: %s", oSysInfo.m_strAppPath, 0, true, LOG_DEBUG);
				break;
			}
		}

		if(!m_pMaxProductMerger)
		{
			m_pMaxProductMerger = new CMaxProductMerger();
			m_pMaxProductMerger->StartMonitoringThread();
		}
	}
	else if(lpDispatchMessage->eDispatch_Type == eUnLoadMerger)
	{
		if(m_pMaxProductMerger)
		{
			m_pMaxProductMerger->StopMonitoringThread();
			delete m_pMaxProductMerger;
			m_pMaxProductMerger = NULL;
		}
	}
}