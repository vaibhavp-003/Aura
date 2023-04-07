// SpecialSpyHandler.h : main header file for the SpecialSpyHandler DLL
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CSpecialSpyHandlerApp
// See SpecialSpyHandler.cpp for the implementation of this class
//

class CSpecialSpyHandlerApp : public CWinApp
{
	CSplSpyWrapper * m_pSplSpyWrapper;

public:
	CSpecialSpyHandlerApp();
	~CSpecialSpyHandlerApp();

	void StartSpecialSpywareScan(SENDMESSAGETOUI lpSndMessage, const bool bFullScan, const bool bUSBScan, const CString& csDrives);
	void StopSplScan();
	void RemoveSpecialSpyware();
	bool IsRestartNeeded();
	bool ScanUSB(const CString& csCmdLineArg, SENDMESSAGETOUI lpSndMessage);
// Overrides
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	virtual int ExitInstance();
};
