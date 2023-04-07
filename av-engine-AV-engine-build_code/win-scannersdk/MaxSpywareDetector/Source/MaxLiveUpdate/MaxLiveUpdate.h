// MaxLiveUpdate.h : main header file for the AuLiveUpdate DLL
//
#pragma once
#include "MaxConstant.h"
#include "MaxMergerWrapper.h"
#include "MaxLiveUpdateWrapper.h"

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
// CMaxLiveUpdateApp
// See MaxLiveUpdate.cpp for the implementation of this class
//

class CMaxLiveUpdateApp : public CWinApp
{
public:
	CMaxLiveUpdateApp();
	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);

private:
	CMaxMergerWrapper		m_oMaxMergerWrapper;
	CMaxLiveUpdateWrapper	m_oMaxLiveUpdateWrapper;

// Overrides
public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	DECLARE_MESSAGE_MAP()
};
