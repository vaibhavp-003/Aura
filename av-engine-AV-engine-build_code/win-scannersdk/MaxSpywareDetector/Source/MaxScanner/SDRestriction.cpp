/*======================================================================================
   FILE				: Activex.Cpp
   ABSTRACT			: This class will be used To Get the List of 
					  ActiveX,Block and unblock the activex
   DOCUMENTS		: OptionDll Design.doc
   AUTHOR			: Tejas Kurhade
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 31-May-2010
======================================================================================*/

#include "pch.h"
#include "SDRestriction.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CString g_csSftCls = _T("Software\\Classes\\");

/*-------------------------------------------------------------------------------------
	Function		: CSDRestriction
	In Parameters	: -
	Out Parameters	: -
	Purpose			: constructor 
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
CSDRestriction::CSDRestriction()
{
	m_csCurUserSID = BLANKSTRING;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CSDRestriction
	In Parameters	: -
	Out Parameters	: -
	Purpose			: constructor 
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
CSDRestriction::~CSDRestriction()
{
}

/*-------------------------------------------------------------------------------------
	Function		: SetDefaultData
	In Parameters	: HKEY hHive, CString csKey, CString csValue, DWORD dwData, bool bCreate = false
	Out Parameters	: bool
	Purpose			: set DWORD default data if not present
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
bool CSDRestriction::SetDefaultData(HKEY hHive, CString csKey, CString csValue, DWORD dwData, bool bCreate)
{
	DWORD dwCurData = 0;

	if(!m_objReg.KeyExists(csKey, hHive) && !bCreate)
	{
		return true;
	}

	m_objReg.Get(csKey, csValue, dwCurData, hHive);
	if(dwCurData == dwData)
	{
		return true;
	}

	return m_objReg.Set(csKey, csValue, dwData, hHive);
}

/*-------------------------------------------------------------------------------------
	Function		: SetDefaultData
	In Parameters	: HKEY hHive, CString csKey, CString csValue, CString csValue, bool bCreate = false
	Out Parameters	: bool
	Purpose			: set string default data if not present
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
bool CSDRestriction::SetDefaultData(HKEY hHive, CString csKey, CString csValue, CString csData, bool bCreate)
{
	CString csCurData;

	if(!m_objReg.KeyExists(csKey, hHive) && !bCreate)
	{
		return true;
	}

	m_objReg.Get(csKey, csValue, csCurData, hHive);
	if(csCurData == csData)
	{
		return true;
	}

	return m_objReg.Set(csKey, csValue, csData, hHive);
}

/*-------------------------------------------------------------------------------------
	Function		: SetAssoc
	In Parameters	: CString csExtension
	Out Parameters	: -
	Purpose			: set file extension association
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
bool CSDRestriction::SetAssoc(CString csExtension)
{
	BYTE byRegData1[4] = {0x38, 0x07, 0x00, 0x00};
	BYTE byRegData2[4] = {0x00, 0x00, 0x00, 0x00};

	if(csExtension == _T("exe"))
	{
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile\\shell\\open\\command"), _T(""), _T("\"%1\" %*"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile\\shell\\runas\\command"), _T(""), _T("\"%1\" %*"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".exe\\shell\\open\\command"), _T(""), _T("\"%1\" %*"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".exe\\shell\\runas\\command"), _T(""), _T("\"%1\" %*"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("secfile\\shell\\open\\command"), _T(""), _T("\"%1\" %*"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("secfile\\shell\\runas\\command"), _T(""), _T("\"%1\" %*"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".exe"), _T(""), _T("exefile"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".exe"), _T("Content Type"), _T("application/x-msdownload"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".exe\\PersistentHandler"), _T(""), _T("{098f2470-bae0-11cd-b579-08002b30bfeb}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile"), _T(""), _T("Application"));
		m_objReg.Set(g_csSftCls + _T("exefile"), _T("EditFlags"), byRegData1, 4, REG_BINARY, HKEY_LOCAL_MACHINE);
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile"), _T("InfoTip"), _T("prop:FileDescription;Company;FileVersion;Create;Size"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile"), _T("TileInfo"), _T("prop:FileDescription;Company;FileVersion"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile\\DefaultIcon"), _T(""), _T("%1"));
		m_objReg.Set(g_csSftCls + _T("exefile\\shell\\open"), _T("EditFlags"), byRegData2, 4, REG_BINARY, HKEY_LOCAL_MACHINE);
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile\\shellex\\DropHandler"), _T(""), _T("{86C86720-42A0-1069-A2E8-08002B30309D}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile\\shellex\\PropertySheetHandlers\\PifProps"), _T(""), _T("{86F19A00-42A0-1069-A2E9-08002B30309D}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("exefile\\shellex\\PropertySheetHandlers\\ShimLayer Property Page"), _T(""), _T("{513D916F-2A8E-4F51-AEAB-0CBC76FB1AF8}"));
	}
	else if(csExtension == _T("lnk"))
	{
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".lnk"), _T(""), _T("lnkfile"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".lnk\\ShellEx\\{000214EE-0000-0000-C000-000000000046}"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".lnk\\ShellEx\\{000214F9-0000-0000-C000-000000000046}"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".lnk\\ShellEx\\{00021500-0000-0000-C000-000000000046}"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".lnk\\ShellEx\\{BB2E617C-0920-11d1-9A0B-00C04FC2D6C1}"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".lnk\\ShellNew"), _T("Command"), _T("rundll32.exe appwiz.cpl,NewLinkHere %1"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile"), _T(""), _T("Shortcut"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile"), _T("EditFlags"), 1);
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile"), _T("IsShortcut"), _T("Shortcut"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile"), _T("NeverShowExt"), _T(""));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile\\CLSID"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile\\shellex\\ContextMenuHandlers\\Offline Files"), _T(""), _T("{750fdf0e-2a26-11d1-a3ea-080036587f03}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile\\shellex\\DropHandler"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile\\shellex\\IconHandler"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("lnkfile\\shellex\\PropertySheetHandlers\\ShimLayer Property Page"), _T(""), _T("{513D916F-2A8E-4F51-AEAB-0CBC76FB1AF8}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("CLSID\\{00021401-0000-0000-C000-000000000046}"), _T(""), _T("Shortcut"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("CLSID\\{00021401-0000-0000-C000-000000000046}\\InProcServer32"), _T(""), _T("shell32.dll"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("CLSID\\{00021401-0000-0000-C000-000000000046}\\InProcServer32"), _T("ThreadingModel"), _T("Apartment"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("CLSID\\{00021401-0000-0000-C000-000000000046}\\PersistentAddinsRegistered\\{89BCB740-6119-101A-BCB7-00DD010655AF}"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("CLSID\\{00021401-0000-0000-C000-000000000046}\\PersistentHandler"), _T(""), _T("{00021401-0000-0000-C000-000000000046}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("CLSID\\{00021401-0000-0000-C000-000000000046}\\ProgID"), _T(""), _T("lnkfile"));
	}
	else if(csExtension == _T("reg"))
	{
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".reg"), _T(""), _T("regfile"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T(".reg\\PersistentHandler"), _T(""), _T("{5e941d80-bf96-11cd-b579-08002b30bfeb}"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile"), _T(""), _T("Registration Entries"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile"), _T("EditFlags"), 1048576);
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile\\DefaultIcon"), _T(""), _T("%SystemRoot%\\regedit.exe,1"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile\\shell\\edit\\command"), _T(""), _T("%SystemRoot%\\system32\\NOTEPAD.EXE %1"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile\\shell\\open"), _T(""), _T("Mer&ge"));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile\\shell\\open\\command"), _T(""), _T("regedit.exe \"%1\""));
		SetDefaultData(HKEY_LOCAL_MACHINE, g_csSftCls + _T("regfile\\shell\\print\\command"), _T(""), _T("%SystemRoot%\\system32\\NOTEPAD.EXE /p %1"));
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetOpt
	In Parameters	: CString csKey, CString csValue, BOOL bEnable
	Out Parameters	: -
	Purpose			: set options
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
void CSDRestriction::SetOpt(CStringArray &csArrayUserSID, LPCTSTR lpszSubKey, LPCTSTR lpszValue, DWORD dwData)
{
	UINT uTotalCnt = (UINT)csArrayUserSID.GetCount();
	for(UINT uCtr = 0; uCtr < uTotalCnt; uCtr++)
	{
		HKEY hKey = NULL;
		if(m_objReg.CreateKey(csArrayUserSID.GetAt(uCtr) + CString(BACK_SLASH) + lpszSubKey, hKey, HKEY_USERS))
		{
			m_objReg.CloseKey(hKey);
		}
		m_objReg.Set(csArrayUserSID.GetAt(uCtr) + CString(BACK_SLASH) + lpszSubKey, lpszValue, dwData, HKEY_USERS);
	}
	m_objReg.Set(lpszSubKey, lpszValue, dwData, HKEY_LOCAL_MACHINE);
}

/*-------------------------------------------------------------------------------------
	Function		: GetOpt
	In Parameters	: CString csKey, CString csValue
	Out Parameters	: -
	Purpose			: get options
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
bool CSDRestriction::GetOpt(CString csKey, CString csValue)
{
	DWORD dwDataUser = 0, dwDataLocal = 0;

	if(BLANKSTRING != m_csCurUserSID)
	{
		m_objReg.Get(m_csCurUserSID + _T("\\") + csKey, csValue, dwDataUser, HKEY_USERS);
	}

	m_objReg.Get(csKey, csValue, dwDataLocal, HKEY_LOCAL_MACHINE);
	return (ENABLE == dwDataUser && ENABLE == dwDataLocal);
}

/*-------------------------------------------------------------------------------------
	Function		: GetAllOptionsProperty
	In Parameters	: LPBYTE byCurSettings, SIZE_T nCurSettings
	Out Parameters	: bool
	Purpose			: get all options
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
bool CSDRestriction::GetAllOptionsProperty(LPBYTE byCurSettings, SIZE_T nCurSettings)
{
	if(nCurSettings < eRES_TotalCount)
	{
		return false;
	}

	if(BLANKSTRING == m_csCurUserSID)
	{
		m_csCurUserSID = m_objExecProc.GetCurrentUserSid();
		if(BLANKSTRING == m_csCurUserSID)
		{
			AddLogEntry(_T("Failed getting current user sid in get registry restrictions"));
			return false;
		}
	}

	byCurSettings[eRES_TaskMgr] = GetOpt(WIN_RESTRICTION_SYSTEM_KEY, DISABLE_TASKMGR);
	byCurSettings[eRES_Property] = GetOpt(WIN_RESTRICTION_SYSTEM_KEY, DISABLE_PROPERTY);
	byCurSettings[eRES_Password] = GetOpt(WIN_RESTRICTION_SYSTEM_KEY, DISABLE_PASSWORD);
	byCurSettings[eRES_LockComp] = GetOpt(WIN_RESTRICTION_SYSTEM_KEY, DISABLE_LOCK_COMPUTER);
	byCurSettings[eRES_RegEdit] = GetOpt(WIN_RESTRICTION_SYSTEM_KEY, DISABLE_REGISTRY);
	byCurSettings[eRES_Search] = GetOpt(WIN_RESTRICTION_EXPLORER_KEY, DISABLE_SEARCH);
	byCurSettings[eRES_Shutdown] = GetOpt(WIN_RESTRICTION_EXPLORER_KEY, DISABLE_SHUTDOWN);
	byCurSettings[eRES_TaskBarClk] = GetOpt(WIN_RESTRICTION_EXPLORER_KEY, DISABLE_TASKBAR_CLICK);
	byCurSettings[eRES_Run] = GetOpt(WIN_RESTRICTION_EXPLORER_KEY, DISABLE_RUN);
	byCurSettings[eRES_CtrlPnl] = GetOpt(WIN_RESTRICTION_EXPLORER_KEY, DISABLE_CONTROL_PANEL);
	byCurSettings[eRES_Cmd] = GetOpt(WIN_RESTRICTION_POLICIES_KEY, DISABLE_CMD);
	byCurSettings[eRES_ExeAssoc] = 0;
	byCurSettings[eRES_LnkAssoc] = 0;
	byCurSettings[eRES_RegAssoc] = 0;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetAllOptionsProperty
	In Parameters	: LPBYTE byCurSettings, SIZE_T nCurSettings
	Out Parameters	: bool
	Purpose			: set all options
	Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
bool CSDRestriction::SetAllOptionsProperty(LPBYTE byCurSettings, SIZE_T nCurSettings)
{
	if(nCurSettings < eRES_TotalCount)
	{
		return false;
	}
	
	CStringArray csArrayUserSID;
	m_objReg.EnumSubKeys(PROFILELIST_PATH, csArrayUserSID, HKEY_LOCAL_MACHINE);

	SetOpt(csArrayUserSID, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_TASKMGR, !byCurSettings[eRES_TaskMgr]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_PROPERTY, !byCurSettings[eRES_Property]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_PASSWORD, !byCurSettings[eRES_Password]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_LOCK_COMPUTER, !byCurSettings[eRES_LockComp]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_REGISTRY, !byCurSettings[eRES_RegEdit]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_SEARCH, !byCurSettings[eRES_Search]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_SHUTDOWN, !byCurSettings[eRES_Shutdown]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_TASKBAR_CLICK, !byCurSettings[eRES_TaskBarClk]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_RUN, !byCurSettings[eRES_Run]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_CONTROL_PANEL, !byCurSettings[eRES_CtrlPnl]);
	SetOpt(csArrayUserSID, WIN_RESTRICTION_POLICIES_KEY, DISABLE_CMD, !byCurSettings[eRES_Cmd]);

	if(byCurSettings[eRES_ExeAssoc])
	{
		SetAssoc(_T("exe"));
	}

	if(byCurSettings[eRES_LnkAssoc])
	{
		SetAssoc(_T("lnk"));
	}

	if(byCurSettings[eRES_RegAssoc])
	{
		SetAssoc(_T("reg"));
	}

	return true;
}
