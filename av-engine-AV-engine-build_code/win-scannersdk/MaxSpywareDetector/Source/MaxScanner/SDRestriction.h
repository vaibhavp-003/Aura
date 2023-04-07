/*======================================================================================
   FILE				: Activex.h
   ABSTRACT			: This class will be used To Get the List of 
					  ActiveX,Block and unblock the activex
   DOCUMENTS		: OptionDll Design.doc
   AUTHOR			: Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 06-Feb-2006
   NOTES			: 
   VERSION HISTORY	: 
					Version : 09-08-07
					Resource : Dipali
					Description : Added unicode and 64 support
======================================================================================*/
#pragma once
#include "Registry.h"
#include "ExecuteProcess.h"

const TCHAR DISABLE_TASKMGR[]		= _T("DisableTaskMgr");
const TCHAR DISABLE_REGISTRY[]		= _T("DisableRegistryTools");
const TCHAR DISABLE_CMD[]			= _T("DisableCMD");
const TCHAR DISABLE_PROPERTY[]		= _T("NoDispCPL");
const TCHAR DISABLE_PASSWORD[]		= _T("DisableChangePassword");
const TCHAR DISABLE_SEARCH[]		= _T("NoFind");
const TCHAR DISABLE_LOCK_COMPUTER[]	= _T("DisableLockWorkstation");
const TCHAR DISABLE_TASKBAR_CLICK[]	= _T("NoTrayContextMenu");
const TCHAR DISABLE_SHUTDOWN[]		= _T("NoClose");
const TCHAR DISABLE_RUN[]			= _T("NoRun");
const TCHAR DISABLE_CONTROL_PANEL[]	= _T("NoControlPanel");

const DWORD DISABLE		=	1;
const DWORD ENABLE		=   0;

class CSDRestriction
{
public:
	CSDRestriction();
	virtual ~CSDRestriction();
	
	bool GetAllOptionsProperty(LPBYTE byCurSettings, SIZE_T nCurSettings);
	bool SetAllOptionsProperty(LPBYTE byCurSettings, SIZE_T nCurSettings);

private:
	CString m_csCurUserSID;
	CRegistry m_objReg;
	CExecuteProcess m_objExecProc;

	bool SetDefaultData(HKEY hHive, CString csKey, CString csValue, DWORD dwData, bool bCreate = false);
	bool SetDefaultData(HKEY hHive, CString csKey, CString csValue, CString csData, bool bCreate = false);
	bool SetAssoc(CString csExtension);
	void SetOpt(CStringArray &csArrayUserSID, LPCTSTR lpszSubKey, LPCTSTR lpszValue, DWORD dwData);
	bool GetOpt(CString csKey, CString csValue);
};
