/*======================================================================================
   FILE			: PathExpander.h
   ABSTRACT		: Expands the folder's/file path i.e. replace the tags with some defined tags.
   DOCUMENTS	: 
   AUTHOR		: Sudhakar Phule
   COMPANY		: Aura 
   COPYRIGHT NOTICE:
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  with out the prior written permission of Aura
   CREATION DATE: 25/12/2003
   NOTES		:
   VERSION HISTORY:  15.9, Dipali : Added support to scan classes entries of current user and class root
				   16.6, Dipali
======================================================================================*/
#pragma once
#ifdef _SPL_DLL
class CPathExpander
#else
class CPathExpander
#endif
{
public:
	CPathExpander(void);
	~CPathExpander(void);

	bool m_bIsWin64;
	bool m_bIsWin98;

	bool IsCurrentUserPath(const CString &sWormPath);
	bool IsLocalClassPath(const CString &sWormPath);
	bool IsLocalMachinePath(const CString &sWormPath);
	void ExpandCurrentUserPath(CString &sRegWorm, const CString &sUserPath);
	void ReplaceLocalMachineWithCurrentUser(CString &sRegWorm);
	void ReplaceLocalMachineClassWithClassRoot(CString &sRegWorm);

	bool IsProfilePath(const CString &sWormPath);
	bool IsRegProfilePath(CString &sWormPath);
	void ExpandProfilePath(CString &sPath, const CString &sProfilePath);
	void Expand(CString & filePath, bool bx86 = false);
	void Shrink(CString & filePath, bool bx86 = false);
	void ShrinkProfilePath(CString &sPath, const CArray<CString,CString> &sProfilePathArr);

	void ReplaceUserToAllUser(CString &csPath);
	bool ExpandSystemTags(CString& sWormPath, bool bx86 = false);
	CString GetRegPathX64(CString &csPath);

	TCHAR m_strOSVersion[MAX_PATH];
	CString m_SYSTEMRESTORE;
	CString m_ROOT;
	CString m_WINDOWS;
	CString m_PROFILE; //SunilApte : 29Sept04 : For User Profile.
	CString m_SVCPROFILE;
	CString m_CUPROFILE;
	CString m_DEFAULRUSER;
	CString m_LOCALSVCUSER;

private:
	CString GetFolderPath(int nFolder);
	TCHAR m_szPath[MAX_PATH];
	CString m_ADMINTOOLS;
	CString m_COMMON_ADMINTOOLS;
	CString m_COMMON_APPDATA;
	CString m_COMMON_DOCUMENTS;
	CString m_COOKIES;
	CString m_HISTORY;
	CString m_INTERNET_CACHE;
	CString m_LOCAL_APPDATA;
	CString m_MYPICTURES;
	CString m_PROGRAM_FILES;
	CString m_PROGRAM_FILESX86;
	CString m_PROGRAM_FILES_COMMON;
	CString m_PROGRAM_FILES_COMMONX86;
	CString m_PF_COMMON_FILES;
	CString m_PFX86_COMMON_FILES;

	CString m_SYSTEM;
	CString m_SYSTEM32;
	CString m_SYSWOW64;
	CString m_COMMON_DESKTOP;
	CString m_COMMON_FAVORITES;
	CString m_COMMON_LOCAL_SETTING;
	CString m_COMMON_MD_MYVIDEO;
	CString m_COMMON_MD_MYMUSIC;
	CString m_COMMON_MYDOC;
	CString m_COMMON_TEMPLATES;
	CString m_COMMON_MYVIDEO;
	CString m_COMMON_MYMUSIC;
	CString m_DAS;
	CString m_SYS32_DRIVERS;
	CString m_SYSWOW64_DRIVERS;
	CString m_SYS32_DLLCACHE;
	CString m_SYSWOW64_DLLCACHE;
	CString m_WIN_APP_DATA;
	CString m_WIN_SPFILES;
	CString m_WIN_MS_NET_FRM;
	CString m_WIN_MS_NET;
	CString m_FONTS;
	CString m_WIN_HELP;
	CString m_WIN_DWN_PF;
	CString m_WIN_INSTALLER;
	CString m_WIN_RESOURCE;
	CString m_COMMON_MYPIC;
	CString m_AU_PRN_HOOD;
	CString m_AU_NETHOOD;
	CString m_COMMON_STARTUP;
	CString m_AU_SM;
	CString m_AU_SM_PROG;
	CString m_AU_MY_RECENT_DOC;
	CString m_AU_SENDTO;
};
