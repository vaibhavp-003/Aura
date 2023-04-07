// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#include "Constants.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
//#include <windows.h>
#include "afxwin.h"


#include <afxext.h>         // MFC extensions
#include <afxdisp.h>        // MFC Automation classes

#include <afxtempl.h>
#include <afxsock.h>		// MFC socket extensions
#include <shlobj.h>
//#include <shfolder.h>
#include <afx.h>
#include <Afxtempl.h>

#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT
#include "SDSAConstants.h"
#include "ProductInfo.h"
#include "MaxConstant.h"
#include "MaxConstantSDK.h"
//#include "SDKSettings.h"
#include <atlbase.h>
#include <atlstr.h>


#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

//#include "MaxRes.h"
DWORD LoadLoggingLevel();
#ifndef SDENTERPRISECLIENT
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true, int iLogLevel = 0);
#endif //SDENTERPRISECLIENT


// TODO: reference additional headers your program requires here
