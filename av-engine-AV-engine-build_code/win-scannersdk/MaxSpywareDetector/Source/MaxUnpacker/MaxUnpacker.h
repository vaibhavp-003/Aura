// MaxUnpacker.h : main header file for the MaxUnpacker DLL
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

// CMaxUnpackerApp
// See MaxUnpacker.cpp for the implementation of this class
//

class CMaxUnpackerApp : public CWinApp
{
public:
	CMaxUnpackerApp();

// Overrides
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
