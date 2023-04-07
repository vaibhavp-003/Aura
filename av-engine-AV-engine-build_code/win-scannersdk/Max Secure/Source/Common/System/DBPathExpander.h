/*======================================================================================
FILE             : DBPathExpander.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 8/1/2009 7:54:54 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once

class CDBPathExpander
{
public:
	CDBPathExpander();
	~CDBPathExpander();

	CString ExpandPath(CString filePath, LPCTSTR wcsProfilePath);
	CString ExpandSystemPath(CString filePath, bool bSearchPathEnv = false);
	CString GetCookiePath();
	CString GetAllUsersPath()
	{
		return m_ALL_USERS;
	}
	CString GetDefaultUserPath()
	{
		return m_csDefaultUser;
	}
	CString GetCurrentUserPath()
	{
		return m_CURRENT_USER;
	}
	CString GetPublicUserPath()
	{
		return m_DOCUMENT_AND_SETTING + L"\\Public";
	}

	TCHAR GetOSDriveLetter()
	{
		return m_ROOT[0];
	}

	inline bool RunningOnVista(){return m_bRunningOnVista;}
	inline bool RunningOnXP(){return m_bRunningOnXP;}
	inline bool RunningOnWin7(){return m_bRunningOnWin7;}
	bool GetCompleteUsersPath(CStringArray &Arr, bool bTempIEPath = false);

	CString m_csValueTAG;
	CString m_csValue;
	ULONG m_lValueTypeID;
	ULONG m_lProfileType;
	bool SplitPathByValueType(const CString &csFullFilePath);

	CString m_cs501;
	CString m_cs502;
	CString m_cs503;
	CString m_cs504;
	CString m_cs505;
	CString m_cs506;
	CString m_cs507;
	CString m_cs508;
	CString m_cs509;
	CString m_cs510;
	CString m_cs511;
	CString m_cs512;
	CString m_cs513;
	CString m_cs514;
	CString m_cs515;
	CString m_cs516;
	CString m_cs517;
	CString m_cs518;
	CString m_cs519;
	CString m_cs520;
	CString m_cs521;
	CString m_cs522;
	CString m_cs523;
	CString m_cs524;
	CString m_cs525;
	CString m_cs526;
	CString m_cs527;
	CString m_cs528;
	CString m_cs529;
	CString m_cs530;
	CString m_cs531;
	CString m_cs532;
	CString m_cs533;
	CString m_cs534;
	CString m_cs535;
	CString m_cs536;
	CString m_cs537;
	CString m_cs538;
	CString m_cs539;
	CString m_cs540;
	CString m_cs541;
	CString m_cs542;
	CString m_cs543;
	
private:
	CString GetFolderPath(int nFolder);
	void LoadValueTypeTag();
	CString ReplaceUsersName(CString &csSource, CString &csDestination, CString csStr);
	CString ReplaceUsersNameTag(CString &csDestination, CString csStr);
	void LoadUserProfilePath();

	TCHAR m_szPath[MAX_PATH];
	CString m_csReplacementPath1;
	CString m_csReplacementPath2;
	CString m_csReplacementPath3;
	CString m_csReplacementPath4;
	CString m_csDefaultUser;

	CString m_ADMINTOOLS;
	CString m_COMMON_ADMINTOOLS;
	CString m_APPDATA;
	CString m_COMMON_APPDATA;
	CString m_COMMON_DOCUMENTS;
	CString m_COOKIES;
	CString m_FLAG_CREATE;
	CString m_HISTORY;
	CString m_INTERNET_CACHE;
	CString m_LOCAL_APPDATA;
	CString m_MYPICTURES;
	CString m_PERSONAL;
	CString m_PROGRAM_FILES;
	CString m_PROGRAM_FILES_COMMON;
	CString m_SYSTEM;
	CString m_WINDOWS;
	CString m_PROFILE;
	CString m_COMMON_PROGRAMS;
	CString m_COMMON_DESKTOP;
	CString m_COMMON_FAVORITES;
	CString m_ROOT;
	CString m_SYSTEMRESTORE;
	CString m_APPPATH;
	CString m_DAS;
	CString m_MYVIDEO;
	CString m_MYMUSIC;
	CString m_TEMPLATE;
	CString m_CURRENT_USER;
	CString m_PRINTHOOD;
	CString m_NETHOOD;
	CString m_RECENT;
	CString m_SENDTO;
	CString m_FONTS;
	CString m_COMMON_TEMPLATES;
	CString m_COMMON_VIDEO;
	CString m_COMMON_MUSIC;
	CString m_COMMON_PICTURES;
	CString m_COMMON_STARTUP;
	CString m_COMMON_STARTMENU;
	CString m_DRIVERS;
	CString m_DOCUMENT_AND_SETTING;
	CString m_ALL_USERS;
	
	bool CheckValueTag(const CString &csValueTag, const CString &csFullFilePath, ULONG lValueTypeID, LPCWSTR lstrValueTAG);
	bool ExpandTildePath(CString& csString);
	
	bool m_bRunningOnVista;
	bool m_bRunningOnXP;
	bool m_bRunningOnWin7;
};