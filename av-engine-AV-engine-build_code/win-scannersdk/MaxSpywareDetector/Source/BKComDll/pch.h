// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"

#endif //PCH_H

//#include "MaxConstant.h"
/*
#include "Constants.h"

//DWORD LoadLoggingLevel();

void AddLogEntry(const TCHAR* sFormatString, const TCHAR* sEntry1 = 0, const TCHAR* sEntry2 = 0, bool isDateTime = true, int iLogLevel = 0);
*/

#pragma once


#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers
#endif

//// Modify the following defines if you have to target a platform prior to the ones specified below.
//// Refer to MSDN for the latest info on corresponding values for different platforms.
//#ifndef WINVER				// Allow use of features specific to Windows 95 and Windows NT 4 or later.
//#define WINVER 0x0400		// Change this to the appropriate value to target Windows 98 and Windows 2000 or later.
//#endif
//
//#ifndef _WIN32_WINNT		// Allow use of features specific to Windows NT 4 or later.
//#define _WIN32_WINNT 0x0400		// Change this to the appropriate value to target Windows 98 and Windows 2000 or later.
//#endif						
//
//#ifndef _WIN32_WINDOWS		// Allow use of features specific to Windows 98 or later.
//#define _WIN32_WINDOWS 0x0410 // Change this to the appropriate value to target Windows Me or later.
//#endif
//
//#ifndef _WIN32_IE			// Allow use of features specific to IE 4.0 or later.
//#define _WIN32_IE 0x0400	// Change this to the appropriate value to target IE 5.0 or later.
//#endif



#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0501		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifndef _WIN32_WINDOWS		// Allow use of features specific to Windows 98 or later.
#define _WIN32_WINDOWS 0x0410 // Change this to the appropriate value to target Windows Me or later.
#endif

#ifndef _WIN32_IE			// Allow use of features specific to IE 6.0 or later.
#define _WIN32_IE 0x0600	// Change this to the appropriate value to target other versions of IE.
#endif


#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// some CString constructors will be explicit

// turns off MFC's hiding of some common and often safely ignored warning messages
#define _AFX_ALL_WARNINGS
#include "MaxWarnings.h"
#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxdisp.h>        // MFC Automation classes

#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT
#include <afxdlgs.h>

#define WM_SHOWMESSAGE (WM_USER + 100)
#include <afxconv.h>
#include <afxtempl.h>
#include <atlbase.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <winuser.h>
#include <wininet.h>
#include <afxinet.h>
#include <afxdhtml.h>        // HTML Dialogs



//#include "SDSAConstants.h"
#include "ProductInfo.h"
//#include "Map.h"
//#include "resource.h"
#include "sysinfoapi.h"

#include "SDConstants.h"
#include "SDSAConstants.h"

#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
DWORD LoadLoggingLevel();
void AddLogEntry(const TCHAR* sFormatString, const TCHAR* sEntry1 = 0, const TCHAR* sEntry2 = 0, bool isDateTime = true, int iLogLevel = 0);
