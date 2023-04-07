
// MaxUnpackExe.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "MaxCommunicatorServer.h"

// CMaxUnpackExeApp:
// See MaxUnpackExe.cpp for the implementation of this class
//
typedef int (*LPFNUnpackFile)(LPCTSTR szFileToUnPack, LPTSTR szUnpackFilePath);

class CMaxUnpackExeApp : public CWinAppEx
{
public:
	CMaxUnpackExeApp();

// Overrides
	public:
	virtual BOOL InitInstance();

	CMaxCommunicatorServer m_objMaxCommunicatorServer;
	HANDLE	m_hAppStopEvent;
	bool	SingleInstance();
	HMODULE			m_hUnpacker32;
	LPFNUnpackFile	m_lpfnUnpackFileNew32;
	BOOL			m_bIsUIProduct;
	DWORD			m_dwWaitRetryCnt;
	TCHAR			m_szUpakLibPath[MAX_PATH] = { 0x00 };

	static HANDLE	m_hUnpckSignal;

	static void OnDataReceivedCallBack(LPVOID sMaxPipeData);

	int	UnpackFile(LPCTSTR pszInFile,LPTSTR pszOutFile);
	int LoadUpackLib();
	int UnLoadUpackLib();
// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CMaxUnpackExeApp theApp;