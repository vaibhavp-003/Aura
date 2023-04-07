#include "pch.h"
#include "MaxIEOptimizer.h"


CMaxIEOptimizer::CMaxIEOptimizer(void)
{
	m_hIEOptimizeDll = ::LoadLibrary(_T("OptimizerDll.dll"));	
}

CMaxIEOptimizer::~CMaxIEOptimizer(void)
{
}

bool CMaxIEOptimizer::IEOptimize(LPIO_MAX_PIPE_DATA lpIOMaxPipeData)
{
	try
	{
	
		if(!m_hIEOptimizeDll)
		{
			return (false);
		}

		m_fnSetAllProperties = (SETALLPROPERTIES)GetProcAddress(m_hIEOptimizeDll, "SetAllProperties");
		m_fnClearIndexDatFile = (CLEARINDEXDAT)GetProcAddress(m_hIEOptimizeDll, "ClearIndexDatFile");

		if( (m_fnSetAllProperties == NULL) || (m_fnClearIndexDatFile == NULL) )
		{
			return (false);
		}

		if ( !m_fnSetAllProperties(lpIOMaxPipeData->sIOScanOptions.TCPWindowSize, lpIOMaxPipeData->sIOScanOptions.DefaultTTL,
								   lpIOMaxPipeData->sIOScanOptions.BlackHoleDetect,lpIOMaxPipeData->sIOScanOptions.SackOpts,
								   lpIOMaxPipeData->sIOScanOptions.MaxDupAcks, lpIOMaxPipeData->sIOScanOptions.HttpPatch,
								   lpIOMaxPipeData->sIOScanOptions.DNSErrorCaching, lpIOMaxPipeData->sIOScanOptions.HostResolution,
								   lpIOMaxPipeData->sIOScanOptions.MTUSize, TRUE))
		{
			return (false);
		}

		if( !m_fnClearIndexDatFile())
		{
			return (false);
		}

		return (true);
	}
	catch(...)
	{
		AddLogEntry(L"Exception caught in CMaxIEOptimizer::IEOptimize fuction");
	}
	return (false);
}


bool CMaxIEOptimizer::IERollBack(LPIO_MAX_PIPE_DATA lpIOMaxPipeData)
{
	try
	{
		if(!m_hIEOptimizeDll)
		{
			return (false);
		}

		m_fnSetAllProperties = (SETALLPROPERTIES)GetProcAddress(m_hIEOptimizeDll, "SetAllProperties");

		if( (m_fnSetAllProperties == NULL) )
		{
			return (false);
		}
		
		if ( !m_fnSetAllProperties(lpIOMaxPipeData->sIOScanOptions.TCPWindowSize, lpIOMaxPipeData->sIOScanOptions.DefaultTTL,
								   lpIOMaxPipeData->sIOScanOptions.BlackHoleDetect,lpIOMaxPipeData->sIOScanOptions.SackOpts,
								   lpIOMaxPipeData->sIOScanOptions.MaxDupAcks, lpIOMaxPipeData->sIOScanOptions.HttpPatch,
								   lpIOMaxPipeData->sIOScanOptions.DNSErrorCaching, lpIOMaxPipeData->sIOScanOptions.HostResolution,
								   lpIOMaxPipeData->sIOScanOptions.MTUSize, FALSE))
		{
			return (false);
		}

		return (true);
	}
	catch(...)
	{
		AddLogEntry(L"Exception caught in CMaxIEOptimizer::IERollBack fuction");
	}
	return (false);
}

void CMaxIEOptimizer::ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	try
	{
		if(!m_hIEOptimizeDll)
		{
			return;
		}
		SetSendMessage(lpDispatchMessage->pSendVoidMessageToUI);

		LPIO_MAX_PIPE_DATA pIOMaxPipeData	= (LPIO_MAX_PIPE_DATA)lpVoid;
		if(pIOMaxPipeData->eMessageInfo == IO_StartOpimize)
		{
			pIOMaxPipeData->bReturn = IEOptimize( pIOMaxPipeData );

			pIOMaxPipeData->eMessageInfo = IO_Finish_Optimize;
			m_pSendVoidMessageToUI(pIOMaxPipeData, sizeof(IO_MAX_PIPE_DATA));
		}
		else if(pIOMaxPipeData->eMessageInfo == IO_StartRollBack)
		{	
			pIOMaxPipeData->bReturn = IERollBack( pIOMaxPipeData );
			pIOMaxPipeData->eMessageInfo = IO_Finish_Rollback;
			m_pSendVoidMessageToUI(pIOMaxPipeData, sizeof(IO_MAX_PIPE_DATA));
		}
	}
	catch(...)
	{
		AddLogEntry(L"Exception caught in CMaxIEOptimizer::ProcessMessage fuction");
	}
}
