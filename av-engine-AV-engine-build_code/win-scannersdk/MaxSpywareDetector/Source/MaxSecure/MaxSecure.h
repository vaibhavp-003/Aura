// MaxSecure.h : main header file for the AuSecure DLL
#pragma once
#include "MaxConstant.h"
#include "MaxSecureScanner.h"
#include "MaxIEOptimizer.h"
#include "RegistryCleaner.h"
#include "MaxFileShredder.h"

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
// CMaxSecureApp
// See MaxSecure.cpp for the implementation of this class
//

class CMaxSecureApp : public CWinApp
{
public:
	CMaxSecureApp();
	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);
	void ProcessCmdLog(LPVOID lpVoid);
	CRegistryCleaner* GetRegistryCleaner();

private:
	CMaxSecureScanner	m_oMaxSecureScanner;
	CMaxIEOptimizer		m_oMaxIEOptimizer;
	CRegistryCleaner	m_oRegistryCleaner;
	CMaxFileShredder	m_oFileShredder;
// Overrides
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	virtual int ExitInstance();
};
