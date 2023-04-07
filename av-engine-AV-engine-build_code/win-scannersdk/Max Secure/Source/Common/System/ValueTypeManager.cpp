#include "StdAfx.h"
#include "ValueTypeConst.h"
#include "ValueTypeManager.h"

CValueTypeManager::CValueTypeManager(void):m_oFileValueType(false), m_oRegistryValueType(false)
{
	FillValueType();
}

CValueTypeManager::~CValueTypeManager(void)
{
	m_oFileValueType.RemoveAll();
	m_oRegistryValueType.RemoveAll();
}

bool CValueTypeManager::SplitFileEntry(const CString &csFileEntry, int &iProfileType, int &iValueType, CString &csValue)
{
	CString csFullEntry(csFileEntry);
	csFullEntry.MakeLower();

	CString csValuePart, csDataPart;
	SlitValuePartAndDataPart(csFullEntry, csValuePart, csDataPart);
	m_iProfileType = 0;

	if(VerifyProfilePath(csFullEntry, csValue))
	{
		iProfileType = m_iProfileType;
		if(GetValueType(csValue, iValueType, m_oFileValueType))
		{
			int iPos = csValue.Find('@');
			if((iValueType == 511) && (iPos != -1))
			{
				csValue = csValue.Mid(iPos);
				iPos = csValue.Find('[');
				if(iPos != -1)
				{
					csValue = csValue.Left(iPos);
				}
			}
			return true;
		}
	}

	return false;
}

bool CValueTypeManager::VerifyProfilePath(CString &csFullEntry, CString &csValue)
{
	int iLen = csFullEntry.GetLength();
	if(iLen <= 3)	/* too short to consider for parsing c:\	*/
	{
		return false;
	}

	m_iProfileType = 0;
	if(iLen <= 25)	/* too short to consider for parsing c:\documents and settings	*/
	{
		csValue = csFullEntry;
		return true;
	}

	csFullEntry.SetAt(0, 'c');

	if(csFullEntry.Left(25) == VALTYPE_DOC_N_SET)
	{
		csFullEntry = csFullEntry.Mid(26);
		int iPos = csFullEntry.Find('\\');
		if(iPos != -1)
		{
			m_iProfileType = 1;
			csFullEntry = csFullEntry.Mid(iPos);
			csValue = VALTYPE_ALL_USERS + csFullEntry;
		}
		else
		{
			csValue = VALTYPE_ALL_USERS + CString(_T("\\")) + csFullEntry;
		}
	}
	else
	{
		csValue = csFullEntry;
	}
	return true;
}

bool CValueTypeManager::SplitRegistryEntry(CString &csRegistryEntry, int &iProfileType, 
											int &iValueType, CString &csKeyPart, 
											CString &csValuePart, CString &csDataPart, bool bSpliltValueData/* = true*/)
{
	if(csRegistryEntry.Left(VALTYPE_HKCR_CLSID_LEN) == VALTYPE_HKCR_CLSID)
	{
		csRegistryEntry = csRegistryEntry.Mid(VALTYPE_HKCR_CLSID_LEN);
		csRegistryEntry = CString(VALTYPE_HKLM_KEY_XML) + VALTYPE_CLSID_KEY + csRegistryEntry;
	}

	const int MIN_BREAKOFFLEN = VALTYPE_SYS_LEN;
	int iEntryLength = csRegistryEntry.GetLength();

	if(iEntryLength <= MIN_BREAKOFFLEN)
	{
		return false;
	}

	CString csFullEntry(csRegistryEntry);
	csFullEntry.MakeLower();
	if(bSpliltValueData)
	{
		SlitValuePartAndDataPart(csFullEntry, csValuePart, csDataPart);
	}

	m_iProfileType = 0;

	CString csUserSID;
	if(GetSoftwarePath(csFullEntry, csKeyPart, csUserSID))
	{
		iProfileType = m_iProfileType;
		if(GetValueType(csKeyPart, iValueType, m_oRegistryValueType))
		{
			return true;
		}
	}
	else if(GetSystemPath(csFullEntry, csKeyPart))
	{
		iProfileType = m_iProfileType;
		if(GetValueType(csKeyPart, iValueType, m_oRegistryValueType))
		{
			return true;
		}
	}
	else if(GetControlPath(csFullEntry, csKeyPart, csUserSID))
	{
		iProfileType = m_iProfileType;
		if(GetValueType(csKeyPart, iValueType, m_oRegistryValueType))
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: HandleHKLMOrUserPath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID
Out Parameters	: void
Purpose			: Removes the \registry\machine or \registry\user\sid from the given 
					registty entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CValueTypeManager::HandleHKLMOrUserPath(const CString &csRegistryEntry, 
										 CString &csReturnedPath, CString &csUserSID)
{
	if(csRegistryEntry.Left(VALTYPE_FULL_USERS_LEN) == VALTYPE_FULL_USERS_KEY)
	{
		m_iProfileType = 1;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_FULL_USERS_LEN);
		csUserSID = csReturnedPath.Left(csReturnedPath.Find('\\'));
		csReturnedPath = csReturnedPath.Mid(csReturnedPath.Find('\\') + 1);
	}
	else if(csRegistryEntry.Left(VALTYPE_USERS_LEN) == VALTYPE_USERS_KEY)
	{
		m_iProfileType = 1;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_USERS_LEN);
		csUserSID = csReturnedPath.Left(csReturnedPath.Find('\\'));
		csReturnedPath = csReturnedPath.Mid(csReturnedPath.Find('\\') + 1);
	}
	else if(csRegistryEntry.Left(VALTYPE_USERS_LEN_XML) == VALTYPE_USERS_KEY_XML)
	{
		m_iProfileType = 1;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_USERS_LEN_XML);
		csUserSID = csReturnedPath.Left(csReturnedPath.Find('\\'));
		csReturnedPath = csReturnedPath.Mid(csReturnedPath.Find('\\') + 1);
	}
	else if(csRegistryEntry.Left(VALTYPE_CURR_USER_LEN) == VALTYPE_CURR_USER_KEY)
	{
		m_iProfileType = 1;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_CURR_USER_LEN);
	}
	else if(csRegistryEntry.Left(VALTYPE_CURR_USER_LEN_XML) == VALTYPE_CURR_USER_KEY_XML)
	{
		m_iProfileType = 1;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_CURR_USER_LEN_XML);
	}
	else if(csRegistryEntry.Left(VALTYPE_FULL_HKLM_LEN) == VALTYPE_FULL_HKLM_KEY)
	{
		m_iProfileType = 0;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_FULL_HKLM_LEN);
	}
	else if(csRegistryEntry.Left(VALTYPE_HKLM_LEN) == VALTYPE_HKLM_KEY)
	{
		m_iProfileType = 0;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_HKLM_LEN);
	}
	else if(csRegistryEntry.Left(VALTYPE_HKLM_LEN_XML) == VALTYPE_HKLM_KEY_XML)
	{
		m_iProfileType = 0;
		csReturnedPath = csRegistryEntry.Mid(VALTYPE_HKLM_LEN_XML);
	}
	else
	{
		m_iProfileType = 0;
		csReturnedPath = csRegistryEntry;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetControlPath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID
Out Parameters	: bool return true if it is else false
Purpose			: This function will return true incase we find "CONTROL" in the 
					begning of the given registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CValueTypeManager::GetControlPath(const CString &csRegistryEntry, CString &csReturnedPath,
											CString &csUserSID)
{
	HandleHKLMOrUserPath(csRegistryEntry, csReturnedPath, csUserSID);

	if(csReturnedPath.Left(VALTYPE_CTRL_LEN) == VALTYPE_CTRL_KEY)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetSoftwarePath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID
Out Parameters	: bool return true if it is else false
Purpose			: This function will return true incase we find "SOFTWARE" in the 
					begning of the given registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CValueTypeManager::GetSoftwarePath(const CString &csRegistryEntry, CString &csReturnedPath,
											CString &csUserSID)
{
	HandleHKLMOrUserPath(csRegistryEntry, csReturnedPath, csUserSID);

	if(csReturnedPath.Left(VALTYPE_SOFT_LEN) == VALTYPE_SOFT_KEY)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetSystemPath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath
Out Parameters	: bool return true if it is else false
Purpose			: This function will return true incase we find "SYSTEM" in the 
					begning of the given registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CValueTypeManager::GetSystemPath(const CString &csRegistryEntry, CString &csReturnedPath)
{
	CString csUserSID;
	HandleHKLMOrUserPath(csRegistryEntry, csReturnedPath,csUserSID);

	if(csReturnedPath.Left(VALTYPE_SYS_LEN) == VALTYPE_SYS_KEY)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: FillValueType
In Parameters	: None
Out Parameters	: None
Purpose			: Loads the tree with value type path and respective value id
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CValueTypeManager::FillValueType()
{
	m_oFileValueType.AppendItem(VALTYPE_TEMP_INET, 501);
	m_oFileValueType.AppendItem(VALTYPE_HISTORY, 502);
	m_oFileValueType.AppendItem(VALTYPE_LOC_APP_DATA, 503);
	m_oFileValueType.AppendItem(VALTYPE_LOC_SET, 504);
	m_oFileValueType.AppendItem(VALTYPE_VIDEOS, 505);
	m_oFileValueType.AppendItem(VALTYPE_MUSIC, 506);
	m_oFileValueType.AppendItem(VALTYPE_PICTURES, 507);
	m_oFileValueType.AppendItem(VALTYPE_DOCUMENTS, 508);
	m_oFileValueType.AppendItem(VALTYPE_APP_DATA, 509);
	m_oFileValueType.AppendItem(VALTYPE_TEMPLATES, 510);
	m_oFileValueType.AppendItem(VALTYPE_COOKIES, 511);
	m_oFileValueType.AppendItem(VALTYPE_DESKTOP, 512);
	m_oFileValueType.AppendItem(VALTYPE_MY_VIDOE, 513);
	m_oFileValueType.AppendItem(VALTYPE_MY_MUSIC, 514);
	m_oFileValueType.AppendItem(VALTYPE_MY_PICTURES, 515);
	m_oFileValueType.AppendItem(VALTYPE_MY_DOCUMENTS, 516);
	m_oFileValueType.AppendItem(VALTYPE_PRINTHOOD, 517);
	m_oFileValueType.AppendItem(VALTYPE_NETHOOD, 518);
	m_oFileValueType.AppendItem(VALTYPE_FAVORITES, 519);
	m_oFileValueType.AppendItem(VALTYPE_STATUP, 520);
	m_oFileValueType.AppendItem(VALTYPE_PROGRAMS, 521);
	m_oFileValueType.AppendItem(VALTYPE_START_MENU, 522);
	m_oFileValueType.AppendItem(VALTYPE_RECENT, 523);
	m_oFileValueType.AppendItem(VALTYPE_SENDTO, 524);
	m_oFileValueType.AppendItem(VALTYPE_ALL_USERS, 525);
	m_oFileValueType.AppendItem(VALTYPE_DOC_N_SET, 526);
	m_oFileValueType.AppendItem(VALTYPE_COMM_FILE, 527);
	m_oFileValueType.AppendItem(VALTYPE_PROG_FILE, 528);
	m_oFileValueType.AppendItem(VALTYPE_DRIVERS, 529);
	m_oFileValueType.AppendItem(VALTYPE_DLLCACHE, 530);
	m_oFileValueType.AppendItem(VALTYPE_SYSTEM32, 531);
	m_oFileValueType.AppendItem(VALTYPE_SYSTEM, 532);
	m_oFileValueType.AppendItem(VALTYPE_WIN_APP_DATA, 533);
	m_oFileValueType.AppendItem(VALTYPE_SP_FILES, 534);
	m_oFileValueType.AppendItem(VALTYPE_FRAMEWORK, 535);
	m_oFileValueType.AppendItem(VALTYPE_DOT_NET, 536);
	m_oFileValueType.AppendItem(VALTYPE_FONTS, 537);
	m_oFileValueType.AppendItem(VALTYPE_HELP, 538);
	m_oFileValueType.AppendItem(VALTYPE_DOWNLOADS, 539);
	m_oFileValueType.AppendItem(VALTYPE_INSTALLER, 540);
	m_oFileValueType.AppendItem(VALTYPE_RESOURCE, 541);
	m_oFileValueType.AppendItem(VALTYPE_WINDOWS, 542);
	m_oFileValueType.AppendItem(VALTYPE_ROOT, 543);

	m_oRegistryValueType.AppendItem(VALTYPE_BHO_KEY, 1);
	m_oRegistryValueType.AppendItem(VALTYPE_BHO_KEY_X64, 1);
	m_oRegistryValueType.AppendItem(VALTYPE_SHAREDTASK_KEY, 2);
	m_oRegistryValueType.AppendItem(VALTYPE_SHAREDTASK_KEY_X64, 2);
	m_oRegistryValueType.AppendItem(VALTYPE_SSODL_KEY, 3);
	m_oRegistryValueType.AppendItem(VALTYPE_SSODL_KEY_X64, 3);
	m_oRegistryValueType.AppendItem(VALTYPE_RUN_KEY, 4);
	m_oRegistryValueType.AppendItem(VALTYPE_RUN_KEY_X64, 4);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNONCE_KEY, 5);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNONCE_KEY_X64, 5);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNONCEEX_KEY, 6);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNONCEEX_KEY_X64, 6);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNSERVICES_KEY, 7);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNSERVICES_KEY_X64, 7);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNSERVICESONCE_KEY, 8);
	m_oRegistryValueType.AppendItem(VALTYPE_RUNSERVICESONCE_KEY_X64, 8);
	m_oRegistryValueType.AppendItem(VALTYPE_UNINSTALL_KEY, 9);
	m_oRegistryValueType.AppendItem(VALTYPE_UNINSTALL_KEY_X64, 9);
	m_oRegistryValueType.AppendItem(VALTYPE_INSTALLER_KEY, 10);
	m_oRegistryValueType.AppendItem(VALTYPE_INSTALLER_KEY_X64, 10);
	m_oRegistryValueType.AppendItem(VALTYPE_SHAREDDLL_KEY, 11);
	m_oRegistryValueType.AppendItem(VALTYPE_SHAREDDLL_KEY_X64, 11);
	m_oRegistryValueType.AppendItem(VALTYPE_ARPCACHE_KEY, 12);
	m_oRegistryValueType.AppendItem(VALTYPE_ARPCACHE_KEY_X64, 12);
	m_oRegistryValueType.AppendItem(VALTYPE_INTERNET_SETIING_KEY, 13);
	m_oRegistryValueType.AppendItem(VALTYPE_INTERNET_SETIING_KEY_X64, 13);
	m_oRegistryValueType.AppendItem(VALTYPE_APP_PATH_KEY, 14);
	m_oRegistryValueType.AppendItem(VALTYPE_APP_PATH_KEY_X64, 14);
	m_oRegistryValueType.AppendItem(VALTYPE_EXPLORER_KEY, 15);
	m_oRegistryValueType.AppendItem(VALTYPE_EXPLORER_KEY_X64, 15);
	m_oRegistryValueType.AppendItem(VALTYPE_CURR_VER_KEY, 16);
	m_oRegistryValueType.AppendItem(VALTYPE_CURR_VER_KEY_X64, 16);
	m_oRegistryValueType.AppendItem(VALTYPE_WINDOWS_KEY, 17);
	m_oRegistryValueType.AppendItem(VALTYPE_WINDOWS_KEY_X64, 17);
	m_oRegistryValueType.AppendItem(VALTYPE_WINNT_WIN_KEY, 18);
	m_oRegistryValueType.AppendItem(VALTYPE_WINNT_WIN_KEY_X64, 18);
	m_oRegistryValueType.AppendItem(VALTYPE_NOTIFY_KEY, 19);
	m_oRegistryValueType.AppendItem(VALTYPE_NOTIFY_KEY_X64, 19);
	m_oRegistryValueType.AppendItem(VALTYPE_NT_CURR_VER_KEY, 20);
	m_oRegistryValueType.AppendItem(VALTYPE_NT_CURR_VER_KEY_X64, 20);
	m_oRegistryValueType.AppendItem(VALTYPE_WINNT_KEY, 21);
	m_oRegistryValueType.AppendItem(VALTYPE_WINNT_KEY_X64, 21);
	m_oRegistryValueType.AppendItem(VALTYPE_NAMESPACE_KEY, 22);
	m_oRegistryValueType.AppendItem(VALTYPE_NAMESPACE_KEY_X64, 22);
	m_oRegistryValueType.AppendItem(VALTYPE_DIST_UNITS_KEY, 23);
	m_oRegistryValueType.AppendItem(VALTYPE_DIST_UNITS_KEY_X64, 23);
	m_oRegistryValueType.AppendItem(VALTYPE_GLOBAL_NAMESPACE_KEY, 24);
	m_oRegistryValueType.AppendItem(VALTYPE_GLOBAL_NAMESPACE_KEY_X64, 24);
	m_oRegistryValueType.AppendItem(VALTYPE_EXT_KEY, 25);
	m_oRegistryValueType.AppendItem(VALTYPE_EXT_KEY_X64, 25);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOLBAR_KEY, 26);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOLBAR_KEY_X64, 26);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOL_EXP_KEY, 27);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOL_EXP_KEY_X64, 27);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOL_SHELL_KEY, 28);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOL_SHELL_KEY_X64, 28);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOL_WEB_KEY, 29);
	m_oRegistryValueType.AppendItem(VALTYPE_TOOL_WEB_KEY_X64, 29);
	m_oRegistryValueType.AppendItem(VALTYPE_SOFT_MIC_KEY, 30);
	m_oRegistryValueType.AppendItem(VALTYPE_SOFT_MIC_KEY_X64, 30);
	m_oRegistryValueType.AppendItem(VALTYPE_INT_KEY, 31);
	m_oRegistryValueType.AppendItem(VALTYPE_INT_KEY_X64, 31);
	m_oRegistryValueType.AppendItem(VALTYPE_CLSID_KEY, 32);
	m_oRegistryValueType.AppendItem(VALTYPE_CLSID_KEY_X64, 32);
	m_oRegistryValueType.AppendItem(VALTYPE_TYPELIB_KEY, 33);
	m_oRegistryValueType.AppendItem(VALTYPE_TYPELIB_KEY_X64, 33);
	m_oRegistryValueType.AppendItem(VALTYPE_CLS_INST_KEY, 34);
	m_oRegistryValueType.AppendItem(VALTYPE_CLS_INST_KEY_X64, 34);
	m_oRegistryValueType.AppendItem(VALTYPE_CLS_SOFT_KEY, 35);
	m_oRegistryValueType.AppendItem(VALTYPE_CLS_SOFT_KEY_X64, 35);
	m_oRegistryValueType.AppendItem(VALTYPE_APPID_KEY, 36);
	m_oRegistryValueType.AppendItem(VALTYPE_APPID_KEY_X64, 36);
	m_oRegistryValueType.AppendItem(VALTYPE_CLS_KEY, 37);
	m_oRegistryValueType.AppendItem(VALTYPE_CLS_KEY_X64, 37);
	m_oRegistryValueType.AppendItem(VALTYPE_SOFTWARE_KEY, 38);
	m_oRegistryValueType.AppendItem(VALTYPE_SOFTWARE_KEY_X64, 38);
	m_oRegistryValueType.AppendItem(VALTYPE_SERVICES1_KEY, 39);
	m_oRegistryValueType.AppendItem(VALTYPE_SERVICES2_KEY, 39);
	m_oRegistryValueType.AppendItem(VALTYPE_SERVICES3_KEY, 39);
	m_oRegistryValueType.AppendItem(VALTYPE_SERVICES4_KEY, 39);
	m_oRegistryValueType.AppendItem(VALTYPE_SERVICES5_KEY, 39);
	m_oRegistryValueType.AppendItem(VALTYPE_SERVICES6_KEY, 39);
	m_oRegistryValueType.AppendItem(VALTYPE_ENUM1_KEY, 40);
	m_oRegistryValueType.AppendItem(VALTYPE_ENUM2_KEY, 40);
	m_oRegistryValueType.AppendItem(VALTYPE_ENUM3_KEY, 40);
	m_oRegistryValueType.AppendItem(VALTYPE_ENUM4_KEY, 40);
	m_oRegistryValueType.AppendItem(VALTYPE_ENUM5_KEY, 40);
	m_oRegistryValueType.AppendItem(VALTYPE_ENUM6_KEY, 40);
	m_oRegistryValueType.AppendItem(VALTYPE_HARD_PRO1_KEY, 41);
	m_oRegistryValueType.AppendItem(VALTYPE_HARD_PRO2_KEY, 41);
	m_oRegistryValueType.AppendItem(VALTYPE_HARD_PRO3_KEY, 41);
	m_oRegistryValueType.AppendItem(VALTYPE_HARD_PRO4_KEY, 41);
	m_oRegistryValueType.AppendItem(VALTYPE_HARD_PRO5_KEY, 41);
	m_oRegistryValueType.AppendItem(VALTYPE_HARD_PRO6_KEY, 41);
	m_oRegistryValueType.AppendItem(VALTYPE_CONTROL1_KEY, 42);
	m_oRegistryValueType.AppendItem(VALTYPE_CONTROL2_KEY, 42);
	m_oRegistryValueType.AppendItem(VALTYPE_CONTROL3_KEY, 42);
	m_oRegistryValueType.AppendItem(VALTYPE_CONTROL4_KEY, 42);
	m_oRegistryValueType.AppendItem(VALTYPE_CONTROL5_KEY, 42);
	m_oRegistryValueType.AppendItem(VALTYPE_CONTROL6_KEY, 42);
	m_oRegistryValueType.AppendItem(VALTYPE_SYSTEM_KEY, 43);
}

/*-------------------------------------------------------------------------------------
Function		: GetValueType
In Parameters	: CString &csFullEntry, int &iValueType, CS2U &oValueType
Out Parameters	: true is successfully found a value type id
Purpose			: breaks the given key in reverse order to search in value type db
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CValueTypeManager::GetValueType(CString &csFullEntry, int &iValueType, CS2U &oValueType)
{
	bool bReturnVal = false;

	int iPos = -1;
	DWORD dwValueType = 0;
	CString csCheckKey = csFullEntry;
	while(true)
	{
		if(oValueType.SearchItem(csCheckKey, &dwValueType))
		{
			iValueType = dwValueType;
			bReturnVal = true;
			iPos = csCheckKey.GetLength();
			csFullEntry = csFullEntry.Mid(iPos + 1);
			break;
		}

		iPos = csCheckKey.ReverseFind('\\');
		if(iPos == -1)
		{
			break;
		}
		csCheckKey = csCheckKey.Left(iPos);
	}

	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
Function		: SlitValuePartAndDataPart
In Parameters	: const CString &csRegistryEntry, CString &csValuePart, CString &csDataPart
Out Parameters	: true if the seperator was found and we were able to split the two
Purpose			: splits the given value into value part and data part
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CValueTypeManager::SlitValuePartAndDataPart(CString &csRegistryEntry, CString &csValuePart, CString &csDataPart)
{
	int iPos = csRegistryEntry.Find(_T("\t#@#\t"));
	if(iPos != -1) //Registry Key & Value are seperated with a \t#@#\t
	{
		CString csFullValuePart = csRegistryEntry.Mid(iPos + 5);  // Pos + \t#@#\t
		csRegistryEntry = csRegistryEntry.Left(iPos);

		int iPos = csFullValuePart.Find(_T("\t#@#\t"));
		if(iPos == -1) //Registry Value & Data are seperated with a \t#@#\t
		{
			csValuePart = csFullValuePart;
			csValuePart.Trim();
			if(csValuePart.GetLength() != 0)
			{
				if(m_oDBPathExpander.SplitPathByValueType(csValuePart))
				{
					csValuePart = m_oDBPathExpander.m_csValueTAG + m_oDBPathExpander.m_csValue;
				}
			}
		}
		else
		{
			csValuePart = csFullValuePart.Left(iPos);
			csValuePart.Trim();
			if(csValuePart.GetLength() != 0)
			{
				if(m_oDBPathExpander.SplitPathByValueType(csValuePart))
				{
					csValuePart = m_oDBPathExpander.m_csValueTAG + m_oDBPathExpander.m_csValue;
				}
			}
			csDataPart = csFullValuePart.Mid(iPos + 5);  // Pos + \t#@#\t
			csDataPart.Trim();
			if(csDataPart.GetLength() != 0)
			{
				if(m_oDBPathExpander.SplitPathByValueType(csDataPart))
				{
					csDataPart = m_oDBPathExpander.m_csValueTAG + m_oDBPathExpander.m_csValue;
				}
			}
		}
		return true;
	}
	return false;
}