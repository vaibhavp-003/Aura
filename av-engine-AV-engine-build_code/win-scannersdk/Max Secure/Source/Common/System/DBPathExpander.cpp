/*======================================================================================
FILE             : DBPathExpander.cpp
ABSTRACT         :
DOCUMENTS	     :
AUTHOR		     :
COMPANY		     : Aura 
COPYRIGHT(NOTICE):
				  (C)Aura
				  Created as an unpublished copyright work. All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura. Hence, it may not be
				  used, copied, reproduced, transmitted, or stored in any form or by any
				  means, electronic, recording, photocopying, mechanical or otherwise,
				  without the prior written permission of Aura.

CREATION DATE    : 8/1/2009 7:53:31 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  :
======================================================================================*/
#include "pch.h"
//#include <shfolder.h>
#include <atlbase.h>
#include "DBPathExpander.h"
#include "Registry.h"
#pragma warning(disable : 4996)
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::CDBPathExpander
In Parameters  :
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CDBPathExpander::CDBPathExpander()
{
	m_bRunningOnVista = false;
	m_bRunningOnXP = false;
	m_bRunningOnWin7 = false;
	OSVERSIONINFOEX *lpOSVersionInfo = new OSVERSIONINFOEX;
	ZeroMemory(lpOSVersionInfo, sizeof(OSVERSIONINFOEX));
	lpOSVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if(GetVersionEx((OSVERSIONINFO *)lpOSVersionInfo))
	{
		if(lpOSVersionInfo->dwMajorVersion == 6)
		{
			if(lpOSVersionInfo->dwMinorVersion == 1)
			{
				m_bRunningOnWin7 = true;
			}
			else
			{
				m_bRunningOnVista = true;
			}
		}
		else if(lpOSVersionInfo->dwMajorVersion == 5)
		{
			m_bRunningOnXP = true;
		}
	}
	delete lpOSVersionInfo;
	lpOSVersionInfo = NULL;

	m_COOKIES				= this->GetFolderPath(CSIDL_COOKIES).MakeLower();
	m_HISTORY				= this->GetFolderPath(CSIDL_HISTORY).MakeLower();
	m_INTERNET_CACHE		= this->GetFolderPath(CSIDL_INTERNET_CACHE).MakeLower();
	m_LOCAL_APPDATA			= this->GetFolderPath(CSIDL_LOCAL_APPDATA).MakeLower();
	m_PERSONAL				= this->GetFolderPath(CSIDL_PERSONAL).MakeLower();
	m_SYSTEM				= this->GetFolderPath(CSIDL_SYSTEM).MakeLower();
	m_WINDOWS				= this->GetFolderPath(CSIDL_WINDOWS).MakeLower();
	m_CURRENT_USER			= this->GetFolderPath(CSIDL_PROFILE).MakeLower();
	m_PRINTHOOD				= this->GetFolderPath(CSIDL_PRINTHOOD).MakeLower();
	m_NETHOOD				= this->GetFolderPath(CSIDL_NETHOOD).MakeLower();
	m_RECENT				= this->GetFolderPath(CSIDL_RECENT).MakeLower();
	m_SENDTO				= this->GetFolderPath(CSIDL_SENDTO).MakeLower();
	m_FONTS					= this->GetFolderPath(CSIDL_FONTS).MakeLower();
	m_PROGRAM_FILES			= this->GetFolderPath(CSIDL_PROGRAM_FILES).MakeLower();
	m_PROGRAM_FILES_COMMON	= this->GetFolderPath(CSIDL_PROGRAM_FILES_COMMON).MakeLower();
	m_COMMON_FAVORITES		= this->GetFolderPath(CSIDL_FAVORITES).MakeLower();
	m_COMMON_STARTUP		= this->GetFolderPath(CSIDL_STARTUP).MakeLower();
	m_COMMON_STARTMENU		= this->GetFolderPath(CSIDL_STARTMENU).MakeLower();
	m_COMMON_APPDATA		= this->GetFolderPath(CSIDL_APPDATA).MakeLower();
	m_COMMON_DOCUMENTS		= this->GetFolderPath(CSIDL_COMMON_DOCUMENTS).MakeLower();
	m_COMMON_PROGRAMS		= this->GetFolderPath(CSIDL_PROGRAMS).MakeLower();
	m_COMMON_DESKTOP		= this->GetFolderPath(CSIDL_DESKTOPDIRECTORY).MakeLower();
	m_TEMPLATE				= this->GetFolderPath(CSIDL_TEMPLATES).MakeLower();
	m_MYPICTURES			= this->GetFolderPath(CSIDL_MYPICTURES).MakeLower();
	m_MYMUSIC				= this->GetFolderPath(CSIDL_MYMUSIC).MakeLower();
	m_MYVIDEO				= this->GetFolderPath(CSIDL_MYVIDEO).MakeLower();
	
	if(m_bRunningOnVista)
	{
		if(m_PERSONAL == L"")
		{
			m_PERSONAL = m_CURRENT_USER + L"\\documents";
		}
		if(m_COOKIES == L"")
		{
			m_COOKIES = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\cookies";
		}
		if(m_TEMPLATE == L"")
		{
			m_TEMPLATE = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\templates";
		}
		if(m_PRINTHOOD == L"")
		{
			m_PRINTHOOD = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\printer shortcuts";
		}
		if(m_NETHOOD == L"")
		{
			m_NETHOOD = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\network shortcuts";
		}
		if(m_COMMON_STARTUP == L"")
		{
			m_COMMON_STARTUP = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup";
		}
		else
		{
			m_COMMON_STARTUP.MakeLower();
			if(m_COMMON_STARTUP.Find(_T("default\\")) != -1)
			{
				m_COMMON_STARTUP.Replace(L"default\\", _T(""));
			}
		}
		if(m_COMMON_PROGRAMS == L"")
		{
			m_COMMON_PROGRAMS = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs";
		}
		if(m_COMMON_STARTMENU == L"")
		{
			m_COMMON_STARTMENU = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\start menu";
		}
		if(m_RECENT == L"")
		{
			m_RECENT = m_CURRENT_USER + L"\\appdata\\roaming\\microsoft\\windows\\recent";
		}
		if(m_COMMON_APPDATA == L"")
		{
			m_COMMON_APPDATA = m_CURRENT_USER + L"\\appdata\\roaming";
		}
		if(m_MYMUSIC == L"")
		{
			m_MYMUSIC = m_PERSONAL + L"\\music";
		}
		if(m_MYVIDEO == L"")
		{
			m_MYVIDEO = m_PERSONAL + L"\\videos";
		}
		if(m_MYPICTURES == L"")
		{
			m_MYPICTURES = m_PERSONAL + L"\\pictures";
		}
	}
	else
	{
		if(m_COOKIES == L"")
		{
			m_COOKIES = m_CURRENT_USER + L"\\cookies";
		}
		if(m_PERSONAL == L"")
		{
			m_PERSONAL = m_CURRENT_USER + L"\\my documents";
		}
		if(m_TEMPLATE == L"")
		{
			m_TEMPLATE = m_CURRENT_USER + L"\\templates";
		}
		if(m_PRINTHOOD == L"")
		{
			m_PRINTHOOD = m_CURRENT_USER + L"\\printhood";
		}
		if(m_NETHOOD == L"")
		{
			m_NETHOOD = m_CURRENT_USER + L"\\nethood";
		}
		if(m_COMMON_APPDATA == L"")
		{
			m_COMMON_APPDATA = m_CURRENT_USER + L"\\application data";
		}
		if(m_COMMON_STARTUP == L"")
		{
			m_COMMON_STARTUP = m_CURRENT_USER + L"\\start menu\\programs\\startup";
		}
		if(m_COMMON_PROGRAMS == L"")
		{
			m_COMMON_PROGRAMS = m_CURRENT_USER + L"\\start menu\\programs";
		}
		if(m_COMMON_STARTMENU == L"")
		{
			m_COMMON_STARTMENU = m_CURRENT_USER + L"\\start menu";
		}
		if(m_RECENT == L"")
		{
			m_RECENT = m_CURRENT_USER + L"\\recent";
		}
		if(m_SENDTO == L"")
		{
			m_SENDTO = m_CURRENT_USER + L"\\sendto";
		}
		if(m_MYMUSIC == L"")
		{
			m_MYMUSIC = m_PERSONAL + L"\\my music";
		}
		if(m_MYVIDEO == L"")
		{
			m_MYVIDEO = m_PERSONAL + L"\\my videos";
		}
		if(m_MYPICTURES == L"")
		{
			m_MYPICTURES = m_PERSONAL + L"\\my pictures";
		}
	}
	if(m_COMMON_FAVORITES == L"")
	{
		m_COMMON_FAVORITES = m_CURRENT_USER + L"\\favorites";
	}
	if(m_COMMON_DESKTOP == L"")
	{
		m_COMMON_DESKTOP = m_CURRENT_USER + L"\\desktop";
	}

	m_COMMON_MUSIC = m_COMMON_DOCUMENTS + L"\\my music";
	m_COMMON_VIDEO = m_COMMON_DOCUMENTS + L"\\my videos";
	m_COMMON_PICTURES = m_COMMON_DOCUMENTS + L"\\my pictures";

	m_ROOT = m_PROGRAM_FILES.Mid(0, m_PROGRAM_FILES.Find(L":") + 1);

	LoadUserProfilePath();

	m_COMMON_DOCUMENTS = ReplaceUsersName(m_ALL_USERS, m_CURRENT_USER, m_COMMON_DOCUMENTS);
	m_COMMON_MUSIC = ReplaceUsersName(m_ALL_USERS, m_CURRENT_USER, m_COMMON_MUSIC);
	m_COMMON_VIDEO = ReplaceUsersName(m_ALL_USERS, m_CURRENT_USER, m_COMMON_VIDEO);
	m_COMMON_PICTURES = ReplaceUsersName(m_ALL_USERS, m_CURRENT_USER, m_COMMON_PICTURES);

	m_DOCUMENT_AND_SETTING = m_csReplacementPath4;

	LoadValueTypeTag();
}

CDBPathExpander::~CDBPathExpander()
{
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::LoadValueTypeTag
In Parameters  :
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CDBPathExpander::LoadValueTypeTag()
{
	CString csTagPath = L"<user>";

	m_cs501 = ReplaceUsersNameTag(csTagPath, m_INTERNET_CACHE);
	m_cs502 = ReplaceUsersNameTag(csTagPath, m_HISTORY);
	m_cs503	= ReplaceUsersNameTag(csTagPath, m_LOCAL_APPDATA);
	m_cs504 = ReplaceUsersNameTag(csTagPath, m_LOCAL_APPDATA.Left(m_LOCAL_APPDATA.ReverseFind('\\')));
	m_cs505 = ReplaceUsersNameTag(csTagPath, m_MYVIDEO);
	m_cs506 = ReplaceUsersNameTag(csTagPath, m_MYMUSIC);
	m_cs507 = ReplaceUsersNameTag(csTagPath, m_MYPICTURES);
	m_cs508 = ReplaceUsersNameTag(csTagPath, m_PERSONAL);
	m_cs509 = ReplaceUsersNameTag(csTagPath, m_COMMON_APPDATA);
	m_cs510 = ReplaceUsersNameTag(csTagPath, m_TEMPLATE);
	m_cs511 = ReplaceUsersNameTag(csTagPath, m_COOKIES);
	m_cs512 = ReplaceUsersNameTag(csTagPath, m_COMMON_DESKTOP);
	m_cs513 = ReplaceUsersNameTag(csTagPath, m_COMMON_VIDEO);
	m_cs514 = ReplaceUsersNameTag(csTagPath, m_COMMON_MUSIC);
	m_cs515 = ReplaceUsersNameTag(csTagPath, m_COMMON_PICTURES);
	m_cs516 = ReplaceUsersNameTag(csTagPath, m_COMMON_DOCUMENTS);
	m_cs517 = ReplaceUsersNameTag(csTagPath, m_PRINTHOOD);
	m_cs518 = ReplaceUsersNameTag(csTagPath, m_NETHOOD);
	m_cs519 = ReplaceUsersNameTag(csTagPath, m_COMMON_FAVORITES);
	m_cs520 = ReplaceUsersNameTag(csTagPath, m_COMMON_STARTUP);
	m_cs521 = ReplaceUsersNameTag(csTagPath, m_COMMON_PROGRAMS);
	m_cs522 = ReplaceUsersNameTag(csTagPath, m_COMMON_STARTMENU);
	m_cs523 = ReplaceUsersNameTag(csTagPath, m_RECENT);
	m_cs524 = ReplaceUsersNameTag(csTagPath, m_SENDTO);
	m_cs525 = ReplaceUsersNameTag(csTagPath, m_CURRENT_USER);
	m_cs526 = m_DOCUMENT_AND_SETTING + L"\\";
	m_cs527 = ReplaceUsersNameTag(csTagPath, m_PROGRAM_FILES_COMMON);
	m_cs528 = ReplaceUsersNameTag(csTagPath, m_PROGRAM_FILES);
	m_cs529 = ReplaceUsersNameTag(csTagPath, m_SYSTEM + L"\\drivers");
	m_cs530 = ReplaceUsersNameTag(csTagPath, m_SYSTEM + L"\\dllcache");
	m_cs531 = ReplaceUsersNameTag(csTagPath, m_SYSTEM);
	m_cs532 = ReplaceUsersNameTag(csTagPath, m_SYSTEM.Left(m_SYSTEM.GetLength() - 2));
	m_cs533 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\application data");
	m_cs534 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\servicepackfiles");
	m_cs535 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\microsoft.net\\framework");
	m_cs536 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\microsoft.net");
	m_cs537 = ReplaceUsersNameTag(csTagPath, m_FONTS);
	m_cs538 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\help");
	m_cs539 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\downloaded program files");
	m_cs540 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\installer");
	m_cs541 = ReplaceUsersNameTag(csTagPath, m_WINDOWS + L"\\resources");
	m_cs542 = ReplaceUsersNameTag(csTagPath, m_WINDOWS);
	m_cs543 = ReplaceUsersNameTag(csTagPath, m_ROOT);
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::ReplaceUsersName
In Parameters  : CString &csSource, CString &csDestination, CString csStr,
Out Parameters : CString
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CString CDBPathExpander::ReplaceUsersName(CString &csSource, CString &csDestination, CString csStr)
{
	csStr.Replace(csSource, csDestination);
	if(csStr.GetLength() > 0)
	{
		if(csStr.GetAt(csStr.GetLength() - 1) != '\\')
		{
			csStr += L"\\";
		}
	}
	return csStr;
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::ReplaceUsersNameTag
In Parameters  : CString &csDestination, CString csStr,
Out Parameters : CString
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CString CDBPathExpander::ReplaceUsersNameTag(CString &csDestination, CString csStr)
{
#pragma warning (disable:4390)	//empty condition as only any one is required
	if(csStr.Replace(m_CURRENT_USER, csDestination) != 0);
	else if(csStr.Replace(m_csReplacementPath1, csDestination) != 0);
	else if(csStr.Replace(m_csReplacementPath2, csDestination) != 0);
	else if(csStr.Replace(m_csReplacementPath3, csDestination) != 0);
	else if(csStr.Replace(m_csDefaultUser, csDestination) != 0);
	else if(csStr.Replace(m_csReplacementPath4, csDestination) != 0);
	if(csStr.GetLength() > 0)
	{
		if(csStr.GetAt(csStr.GetLength() - 1) != '\\')
		{
			csStr += L"\\";
		}
	}
#pragma warning (default:4390)
	return csStr;
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::LoadUserProfilePath
In Parameters  :
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CDBPathExpander::LoadUserProfilePath()
{
	CRegKey m_objRegistry;
	if(m_objRegistry.Open(HKEY_LOCAL_MACHINE, 
						L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18",
						KEY_READ)== ERROR_SUCCESS)
	{
		ULONG ulLen = MAX_PATH;
		m_objRegistry.QueryStringValue(L"ProfileImagePath", m_szPath, &ulLen);
		m_csReplacementPath1 = ExpandSystemPath(m_szPath);
		m_objRegistry.Close();
	}

	if(m_objRegistry.Open(HKEY_LOCAL_MACHINE,
						L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-19",
						KEY_READ)== ERROR_SUCCESS)
	{
		ULONG ulLen = MAX_PATH;
		m_objRegistry.QueryStringValue(L"ProfileImagePath", m_szPath, &ulLen);
		m_csReplacementPath2 = ExpandSystemPath(m_szPath);
		m_objRegistry.Close();
	}

	if(m_objRegistry.Open(HKEY_LOCAL_MACHINE, 
						L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-20",
						KEY_READ)== ERROR_SUCCESS)
	{
		ULONG ulLen = MAX_PATH;
		m_objRegistry.QueryStringValue(L"ProfileImagePath", m_szPath, &ulLen);
		m_csReplacementPath3 = ExpandSystemPath(m_szPath);
		m_objRegistry.Close();
	}

	if(m_objRegistry.Open(HKEY_LOCAL_MACHINE,
						L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
						KEY_READ)== ERROR_SUCCESS)
	{
		ULONG ulLen = MAX_PATH;
		m_objRegistry.QueryStringValue(L"ProfilesDirectory", m_szPath, &ulLen);
		m_csReplacementPath4 = ExpandSystemPath(m_szPath);
		m_objRegistry.Close();
	}

	if(m_objRegistry.Open(HKEY_LOCAL_MACHINE,
						L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
						KEY_READ)== ERROR_SUCCESS)
	{
		ULONG ulLen = MAX_PATH;
		if(m_bRunningOnVista)
		{
			m_objRegistry.QueryStringValue(L"Public", m_szPath, &ulLen);
			m_ALL_USERS = ExpandSystemPath(m_szPath);
		}
		else
		{
			m_objRegistry.QueryStringValue(L"AllUsersProfile", m_szPath, &ulLen);
			m_ALL_USERS = m_csReplacementPath4 + L"\\" + ExpandSystemPath(m_szPath);
		}
		m_objRegistry.Close();
	}

	if(m_objRegistry.Open(HKEY_LOCAL_MACHINE,
						L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
						KEY_READ)== ERROR_SUCCESS)
	{
		ULONG ulLen = MAX_PATH;
		if(m_bRunningOnVista)
		{
			m_objRegistry.QueryStringValue(L"Default", m_szPath, &ulLen);
			m_csDefaultUser = ExpandSystemPath(m_szPath);
		}
		else
		{
			m_objRegistry.QueryStringValue(L"DefaultUserProfile", m_szPath, &ulLen);
			m_csDefaultUser = m_csReplacementPath4 + L"\\" + ExpandSystemPath(m_szPath);
		}
		m_objRegistry.Close();
	}
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::GetFolderPath
In Parameters  : int nFolder,
Out Parameters : CString
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CString CDBPathExpander::GetFolderPath(int nFolder)
{
	if(SUCCEEDED(SHGetFolderPath(0, nFolder, NULL, 0, m_szPath)))
	{
		return m_szPath;
	}
	else
	{
		m_szPath[0] = '\0';
		return m_szPath;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::SplitPathByValueType
In Parameters  : const CString &csFullFilePath,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CDBPathExpander::SplitPathByValueType(const CString &csFullFilePath)
{
	m_lProfileType = 0;
	m_lValueTypeID = 0;
	m_csValue.Empty();
	m_csValueTAG.Empty();

	if(csFullFilePath.GetLength()== 0)
	{
		return false;
	}

	CString csFullPath = ExpandSystemPath(csFullFilePath);

	if(csFullPath.GetLength()< 2)
	{
		return false;
	}

	if(csFullPath.GetAt(1) != ':')
	{
		return false;
	}

	csFullPath.MakeLower();
	csFullPath.SetAt(0, m_cs526.GetAt(0));
	bool bIsProfileType = false;

	// check if it's a profile path!
	if(m_cs526.Compare(csFullPath.Left(m_cs526.GetLength()))== 0)
	{
		bIsProfileType = true;
		csFullPath = csFullPath.Mid(m_cs526.GetLength());
		if(csFullPath.Find('\\') != -1)
		{
			m_lProfileType = 1;
			csFullPath = csFullPath.Mid(csFullPath.Find('\\'));
			csFullPath = L"<user>" + csFullPath;
		}
		else
		{
			csFullPath = csFullFilePath;
		}
	}

	if(bIsProfileType)
	{
		if(CheckValueTag(m_cs501, csFullPath, 501, L"%das.au.ls.temp-inet-files%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs502, csFullPath, 502, L"%das.au.ls.history%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs503, csFullPath, 503, L"%das.au.ls.app-data%\\"))
		{
			return true;
		}
		if(!m_bRunningOnVista)	// The sequence of checking tags changes incase of vista!
		{
			if(CheckValueTag(m_cs504, csFullPath, 504, L"%das.au.ls%\\"))
			{
				return true;
			}
		}
		if(CheckValueTag(m_cs505, csFullPath, 505, L"%das.au.md.myvideos%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs506, csFullPath, 506, L"%das.au.md.mymusic%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs507, csFullPath, 507, L"%das.au.md.mypictures%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs508, csFullPath, 508, L"%das.au.md%\\"))
		{
			return true;
		}
		if(!m_bRunningOnVista)	// The sequence of checking tags changes incase of vista!
		{
			if(CheckValueTag(m_cs509, csFullPath, 509, L"%das.au.app data%\\"))
			{
				return true;
			}
		}
		if(CheckValueTag(m_cs510, csFullPath, 510, L"%das.au.templates%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs511, csFullPath, 511, L"%das.au.cookies%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs512, csFullPath, 512, L"%das.au.desktop%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs513, csFullPath, 513, L"%das.au.doc.myvideos%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs514, csFullPath, 514, L"%das.au.doc.mymusic%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs515, csFullPath, 515, L"%das.au.doc.mypictures%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs516, csFullPath, 516, L"%das.au.doc%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs517, csFullPath, 517, L"%das.au.prn-hood%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs518, csFullPath, 518, L"%das.au.net-hood%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs519, csFullPath, 519, L"%das.au.fav-hood%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs520, csFullPath, 520, L"%das.au.sm.p-startup%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs521, csFullPath, 521, L"%das.au.sm.p%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs522, csFullPath, 522, L"%das.au.sm%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs523, csFullPath, 523, L"%das.au.my-recent-doc%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs524, csFullPath, 524, L"%das.au.sendto%\\"))
		{
			return true;
		}
		if(m_bRunningOnVista)	// The sequence of checking tags changes incase of vista!
		{
			if(CheckValueTag(m_cs509, csFullPath, 509, L"%das.au.app data%\\"))
			{
				return true;
			}
			if(CheckValueTag(m_cs504, csFullPath, 504, L"%das.au.ls%\\"))
			{
				return true;
			}
		}
		if(CheckValueTag(m_cs525, csFullPath, 525, L"%das.au%\\"))
		{
			return true;
		}
		if(CheckValueTag(m_cs526, csFullPath, 526, L"%das%\\"))
		{
			return true;
		}
	}
	if(CheckValueTag(m_cs527, csFullPath, 527, L"%pf.common%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs528, csFullPath, 528, L"%pf%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs529, csFullPath, 529, L"%win.sys32.drivers%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs530, csFullPath, 530, L"%win.sys32.dllcache%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs531, csFullPath, 531, L"%win.sys32%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs532, csFullPath, 532, L"%win.sys%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs533, csFullPath, 533, L"%win.app-data%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs534, csFullPath, 534, L"%win.sp-files%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs535, csFullPath, 535, L"%win.ms.net.frm%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs536, csFullPath, 536, L"%win.ms.net%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs537, csFullPath, 537, L"%win.fonts%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs538, csFullPath, 538, L"%win.help%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs539, csFullPath, 539, L"%win.dwn-pf%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs540, csFullPath, 540, L"%win.installer%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs541, csFullPath, 541, L"%win.resource%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs542, csFullPath, 542, L"%win%\\"))
	{
		return true;
	}
	if(CheckValueTag(m_cs543, csFullPath, 543, L"%root%\\"))
	{
		return true;
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::CheckValueTag
In Parameters  : const CString &csValueTag, const CString &csFullFilePath, ULONG lValueTypeID,
				LPCWSTR lstrValueTAG,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CDBPathExpander::CheckValueTag(const CString &csValueTag, const CString &csFullFilePath,
									ULONG lValueTypeID, LPCWSTR lstrValueTAG)
{
	if(csValueTag.CompareNoCase(csFullFilePath.Left(csValueTag.GetLength())) == 0)
	{
		m_csValueTAG = lstrValueTAG;
		m_csValue = csFullFilePath.Mid(csValueTag.GetLength());
		m_lValueTypeID = lValueTypeID;
		return true;
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::ExpandPath
In Parameters  : CString filePath, LPCTSTR wcsProfilePath,
Out Parameters : CString
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CString CDBPathExpander::ExpandPath(CString filePath, LPCTSTR wcsProfilePath)
{
	bool bIsPathStyle = false;
	filePath.MakeLower();
	if(filePath.Find(L"%da") != -1)
	{
		if(filePath.Replace(L"%das.au.ls.temp-inet-files%\\", m_cs501) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.ls.history%\\", m_cs502) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.ls.app-data%\\", m_cs503) != 0)
		{
			bIsPathStyle = true;
		}
		else if(!m_bRunningOnVista && filePath.Replace(L"%das.au.ls%\\", m_cs504) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.md.myvideos%\\", m_cs505) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.md.mymusic%\\", m_cs506) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.md.mypictures%\\", m_cs507) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.md%\\", m_cs508) != 0)
		{
			bIsPathStyle = true;
		}
		else if(!m_bRunningOnVista && filePath.Replace(L"%das.au.app data%\\", m_cs509) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.templates%\\", m_cs510) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.cookies%\\", m_cs511) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.desktop%\\", m_cs512) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.doc.myvideos%\\", m_cs513) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.doc.mymusic%\\", m_cs514) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.doc.mypictures%\\", m_cs515) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.doc%\\", m_cs516) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.prn-hood%\\", m_cs517) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.net-hood%\\", m_cs518) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.fav-hood%\\", m_cs519) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.sm.p-startup%\\", m_cs520) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.sm.p%\\", m_cs521) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.sm%\\", m_cs522) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.my-recent-doc%\\", m_cs523) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au.sendto%\\", m_cs524) != 0)
		{
			bIsPathStyle = true;
		}
		else if(m_bRunningOnVista && filePath.Replace(L"%das.au.app data%\\", m_cs509) != 0)
		{
			bIsPathStyle = true;
		}
		else if(m_bRunningOnVista && filePath.Replace(L"%das.au.ls%\\", m_cs504) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das.au%\\", m_cs525) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%das%\\", m_cs526) != 0)
		{
			bIsPathStyle = true;
		}
	}
	if(filePath.Find(L"%pf") != -1)
	{
		if(filePath.Replace(L"%pf.common%\\", m_cs527) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%pf%\\", m_cs528) != 0)
		{
			bIsPathStyle = true;
		}
	}
	if(filePath.Find(L"%wi") != -1)
	{
		if(filePath.Replace(L"%win.sys32.drivers%\\", m_cs529) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.sys32.dllcache%\\", m_cs530) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.sys32%\\", m_cs531) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.sys%\\", m_cs532) != 0)
		{
			bIsPathStyle = true;
		}
		else if(m_bRunningOnVista && filePath.Replace(L"%win.app-data%\\", m_cs533) != 0)
		{
			bIsPathStyle = true;
		}
		else if(m_bRunningOnVista && filePath.Replace(L"%win.sp-files%\\", m_cs534) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.ms.net.frm%\\", m_cs535) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.ms.net%\\", m_cs536) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.fonts%\\", m_cs537) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.help%\\", m_cs538) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.dwn-pf%\\", m_cs539) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.installer%\\", m_cs540) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win.resource%\\", m_cs541) != 0)
		{
			bIsPathStyle = true;
		}
		else if(filePath.Replace(L"%win%\\", m_cs542) != 0)
		{
			bIsPathStyle = true;
		}
	}
	if(filePath.Replace(L"%root%\\", m_cs543) != 0)
	{
		bIsPathStyle = true;
	}

	if(filePath.Replace(L"%systemroot%\\", m_WINDOWS + L"\\") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"\\systemroot\\", m_WINDOWS + L"\\") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"\\??\\", L"") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"%systemdrive%\\", m_ROOT + L"\\") != 0)
	{
		bIsPathStyle = true;
	}

	if(filePath.Find(L"<user>") != -1)
	{
		filePath.Replace(L"<user>", wcsProfilePath);
	}

	filePath.MakeLower();
	return filePath;
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::ExpandSystemPath
In Parameters  : CString filePath,
Out Parameters : CString
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CString CDBPathExpander::ExpandSystemPath(CString filePath, bool bSearchPathEnv)
{
	bool bIsPathStyle = false;
	if(filePath.Trim().GetLength()== 0)
		return filePath;

	filePath.MakeLower();
	if(filePath.Replace(L"%systemroot%\\", m_WINDOWS + L"\\") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"\\systemroot\\", m_WINDOWS + L"\\") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"\\??\\", L"") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"%systemdrive%\\", m_ROOT + L"\\") != 0)
	{
		bIsPathStyle = true;
	}
	else if(filePath.Replace(L"%programfiles%\\", m_PROGRAM_FILES + L"\\") != 0)
	{
		bIsPathStyle = true;
	}

	if(bSearchPathEnv)
	{
		TCHAR szNewPath[MAX_PATH] = {0};
		_tsearchenv_s(filePath, _T("PATH"), szNewPath, _countof(szNewPath));
		if(szNewPath[0])
		{
			filePath = szNewPath;
		}

		ExpandTildePath(filePath);
	}

	filePath.MakeLower();
	return filePath;
}
/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::GetCookiePath
In Parameters  : CString filePath,
Out Parameters : CString
Description    :
Author & Date  : Sandip sanap & o6 Nov, 2009.
--------------------------------------------------------------------------------------*/
CString CDBPathExpander::GetCookiePath()
{
	return m_COOKIES;
}

/*--------------------------------------------------------------------------------------
Function       : CDBPathExpander::ExpandTildePath
In Parameters  : CString& csString
Out Parameters : bool
Description    : expand and convert to long path and replace it with full file path
Author & Date  : Anand Srivastava & 18 March, 2010
--------------------------------------------------------------------------------------*/
bool CDBPathExpander::ExpandTildePath(CString& csString)
{
	TCHAR chChar1 = 0, chChar2 = 0, chChar3 = 0, szOrgPath[MAX_PATH] = {0}, szNewPath[MAX_PATH] = {0};
	LPCTSTR Ptr = NULL, TildePtr = NULL, StartPtr = NULL, EndPtr = NULL, OrgStringStart = NULL;

	csString.MakeLower();
	OrgStringStart = csString;
	TildePtr = _tcschr(OrgStringStart, _T('~'));
	while(TildePtr)
	{
		// find start of filepath with ~
		for(Ptr = TildePtr; Ptr >= OrgStringStart; Ptr--)
		{
			if(*Ptr == _T(':'))
			{
				if((Ptr - 1) >= OrgStringStart)
				{
					if(*(Ptr + 1)== _T('\\'))
					{
						StartPtr = Ptr - 1;
						break;
					}
				}
			}
		}

		// find end of filepath with ~. exe,com,dll,scr,ocx,sys,cpl,bin,pif
		for(Ptr = TildePtr; StartPtr; Ptr++)
		{
			if(*Ptr == _T('.'))
			{
				chChar1 = *(Ptr+1);
				chChar2 = *(Ptr+2);
				chChar3 = *(Ptr+3);

				if((chChar1 && chChar1 && chChar3) && (
					(chChar1 == _T('e') && chChar2 == _T('x') && chChar3 == _T('e')) ||
					(chChar1 == _T('c') && chChar2 == _T('o') && chChar3 == _T('m')) ||
					(chChar1 == _T('d') && chChar2 == _T('l') && chChar3 == _T('l')) ||
					(chChar1 == _T('s') && chChar2 == _T('c') && chChar3 == _T('r')) ||
					(chChar1 == _T('o') && chChar2 == _T('c') && chChar3 == _T('x')) ||
					(chChar1 == _T('s') && chChar2 == _T('y') && chChar3 == _T('s')) ||
					(chChar1 == _T('c') && chChar2 == _T('p') && chChar3 == _T('l')) ||
					(chChar1 == _T('b') && chChar2 == _T('i') && chChar3 == _T('n')) ||
					(chChar1 == _T('f') && chChar2 == _T('i') && chChar3 == _T('f'))))
				{
					EndPtr = Ptr + 4;
					break;
				}
			}
			else if(0 == *Ptr)
			{
				EndPtr = Ptr;
				break;
			}
		}

		if(StartPtr && EndPtr && EndPtr > StartPtr)
		{
			if(_countof(szOrgPath) > (EndPtr - StartPtr))
			{
				_tcsncpy_s(szOrgPath, _countof(szOrgPath), StartPtr, EndPtr - StartPtr);
				if(!_taccess_s(szOrgPath, 0))
				{
					if(GetLongPathName(szOrgPath, szNewPath, _countof(szNewPath)) != 0)
					{
						if(szNewPath[0])
						{
							csString.Replace(szOrgPath, szNewPath);
						}
					}
				}
			}
		}

		TildePtr++;
		TildePtr = _tcschr(TildePtr, _T('~'));
	}

	csString.MakeLower();
	return true;
}

bool CDBPathExpander::GetCompleteUsersPath(CStringArray &Arr, bool bTempIEPath)
{
	CStringArray arrUsers;
	
	CRegistry oRegistry;
	oRegistry.EnumSubKeys(PROFILELIST_PATH, Arr, HKEY_LOCAL_MACHINE);
	
	CString csPath = _T("");
	CString csTemp = _T("");
	int iIndex = 0;
	for(iIndex = 0; iIndex < Arr.GetCount(); iIndex++)
	{
		if(oRegistry.Get(CString(PROFILELIST_PATH) + _T("\\") + Arr.GetAt(iIndex), _T("ProfileImagePath"), csPath, HKEY_LOCAL_MACHINE))
			arrUsers.Add(csPath);
	}
	
	CString csFolder  =_T("");
	if(m_bRunningOnVista || m_bRunningOnWin7)
	{
		if(oRegistry.Get(CString(PROFILELIST_PATH), _T("Default"), csPath, HKEY_LOCAL_MACHINE))
			arrUsers.Add(csPath);	
		
		if(bTempIEPath)
			csFolder = _T("\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files");
		else
			csFolder = _T("\\AppData\\Roaming\\Microsoft\\Windows\\Cookies");
	}
	else
	{
		oRegistry.Get(CString(PROFILELIST_PATH), _T("ProfilesDirectory"), csPath, HKEY_LOCAL_MACHINE);
					
		if(oRegistry.Get(CString(PROFILELIST_PATH), _T("DefaultUserProfile"), csTemp, HKEY_LOCAL_MACHINE))
			arrUsers.Add(csPath + _T("\\") + csTemp);	
		
		if(bTempIEPath)
			csFolder = _T("\\Local Settings\\Temporary Internet Files");
		else
			csFolder = _T("\\Cookies");
	}	
	
	csTemp = _T("");
	Arr.RemoveAll();

	int iLength = arrUsers.GetCount();
	for(iIndex = 0; iIndex < iLength; iIndex++)
	{
		csTemp = arrUsers.GetAt(iIndex);
		csTemp.Replace(_T("%SystemDrive%"), m_ROOT);
		csTemp.Replace(_T("%systemroot%"), m_WINDOWS);
		
		CString path = csTemp + csFolder;
		if(PathFileExists(path))
		{
			Arr.Add(path);
		}
		else
		{
			path = csTemp + _T("\\AppData\\Local\\Microsoft\\Windows\\INetCookies");
			if(PathFileExists(path))
			{
				Arr.Add(path);
			}
		}
	}
	return true;
}