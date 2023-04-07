#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif
#include "resource.h"		// main symbols

class CSrvOptApp : public CWinApp
{
public:
	CSrvOptApp();
	virtual BOOL InitInstance();
	bool IsAnotherInstancePresent();

	DECLARE_MESSAGE_MAP()
	virtual int ExitInstance();
};

extern CSrvOptApp theApp;