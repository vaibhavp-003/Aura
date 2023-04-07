/*======================================================================================
   FILE			: PathExpander.Cpp
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

#include "pch.h"
#include <Afx.h>
//#include <shfolder.h>
#include "CPUInfo.h"
#include "SDSystemInfo.h"
#include "PathExpander.h"
#include "Registry.h"
#include "Executeprocess.h"

/*-----------------------------------------------------------------------------
Function		: CPathExpander
In Parameters	:
Out Parameters	:
Purpose			: Initialze CPathExpander class
Author			:
-----------------------------------------------------------------------------*/
CPathExpander::CPathExpander(void)
{
	try
	{
		wmemset(m_szPath,0,MAX_PATH);
		m_bIsWin98 = false;
		m_bIsWin64 = false;
		CString csOS = WNE;
		csOS += ENS;
#ifdef WIN64
		//if(CSystemInfo::m_bIsOSX64)
		{
			m_bIsWin64 = true;
		}
#endif
		CRegistry objReg;
		CExecuteProcess objExecProc;
		CString csSID = objExecProc.GetCurrentUserSid();
		objReg.Get(CString(PROFILELIST_PATH) + CString(BACK_SLASH) + csSID,L"ProfileImagePath",m_CUPROFILE,HKEY_LOCAL_MACHINE);



		m_COMMON_DOCUMENTS		= this->GetFolderPath(CSIDL_COMMON_DOCUMENTS).MakeLower();
		m_COMMON_MYVIDEO		= this->GetFolderPath(CSIDL_COMMON_VIDEO).MakeLower();
		if(m_COMMON_MYVIDEO == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"My videos",m_COMMON_MYVIDEO,HKEY_USERS);
			m_COMMON_MYVIDEO.MakeLower();
			if(m_COMMON_MYVIDEO == BLANKSTRING)
				m_COMMON_MYVIDEO = m_COMMON_DOCUMENTS + L"\\my videos";
		}

		m_COMMON_MYMUSIC		= this->GetFolderPath(CSIDL_COMMON_MUSIC).MakeLower();
		if(m_COMMON_MYMUSIC == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"My music",m_COMMON_MYMUSIC,HKEY_USERS);
			m_COMMON_MYMUSIC.MakeLower();
			if(m_COMMON_MYMUSIC == BLANKSTRING)
				m_COMMON_MYMUSIC = m_COMMON_DOCUMENTS + L"\\my music";
		}

		m_COMMON_MYPIC			= this->GetFolderPath(CSIDL_COMMON_PICTURES).MakeLower();
		if(m_COMMON_MYPIC == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"My pictures",m_COMMON_MYPIC,HKEY_USERS);
			m_COMMON_MYPIC.MakeLower();
			if(m_COMMON_MYPIC == BLANKSTRING)
				m_COMMON_MYPIC = m_COMMON_DOCUMENTS + L"\\my pictures";
		}


		m_INTERNET_CACHE		= this->GetFolderPath(CSIDL_INTERNET_CACHE).MakeLower();
		m_HISTORY				= this->GetFolderPath(CSIDL_HISTORY).MakeLower();
		m_LOCAL_APPDATA			= this->GetFolderPath(CSIDL_LOCAL_APPDATA).MakeLower();

		m_SVCPROFILE			= this->GetFolderPath(CSIDL_PROFILE).MakeLower();

		m_PROFILE				= m_COMMON_DOCUMENTS;
		if(m_PROFILE != L"")
		{
			int iFind = m_PROFILE.ReverseFind(L'\\');
			if(iFind != -1)
			{
				m_PROFILE = m_PROFILE.Mid(0,iFind);

			}
			else
				m_PROFILE = CSystemInfo::m_strRoot + L"\\documents and settings\\all users";
		}
		else
		{
			m_PROFILE = CSystemInfo::m_strRoot + L"\\documents and settings\\all users";
		}

		m_ROOT					= m_PROFILE.Mid(0,m_PROFILE.Find(_T(":")) +1).MakeLower();
		int iFind = m_PROFILE.ReverseFind(L'\\');
		if(iFind != -1)
		{
			m_DAS = m_PROFILE.Mid(0,iFind);
		}
		else
		{
			objReg.Get(PROFILELIST_PATH,L"ProfilesDirectory",m_DAS,HKEY_LOCAL_MACHINE);
			m_DAS.MakeLower();
			m_DAS.Replace(CONST_SYSTEM_DRIVE, m_ROOT);
		}

		objReg.Get(CString(PROFILELIST_PATH) + CString(_T("\\S-1-5-19")),_T("ProfileImagePath"),m_LOCALSVCUSER,HKEY_LOCAL_MACHINE);
		m_LOCALSVCUSER.MakeLower();
		m_LOCALSVCUSER.Replace((CONST_SYSTEM_DRIVE), (m_ROOT));
		m_LOCALSVCUSER.Replace((CONST_SYSTEM_ROOT), (m_ROOT));


		m_CUPROFILE.MakeLower();
		m_CUPROFILE.Replace(CONST_SYSTEM_DRIVE, m_ROOT);
		ReplaceUserToAllUser(m_COMMON_MYVIDEO);
		ReplaceUserToAllUser(m_COMMON_MYMUSIC);
		ReplaceUserToAllUser(m_COMMON_MYPIC);

		ReplaceUserToAllUser(m_LOCAL_APPDATA);
		m_COMMON_LOCAL_SETTING  = m_LOCAL_APPDATA;
		iFind = m_COMMON_LOCAL_SETTING.ReverseFind(L'\\');
		if(iFind != -1)
		{
			m_COMMON_LOCAL_SETTING = m_COMMON_LOCAL_SETTING.Mid(0,iFind);
		}

		m_COMMON_MYDOC			= m_COMMON_DOCUMENTS;
		if(CSystemInfo::m_strOS != WVISTA)
		{
			m_COMMON_MYDOC			+= L"\\";
			m_COMMON_MYDOC.Replace(L"\\documents\\", L"\\my documents");

			m_COMMON_MD_MYVIDEO		= m_COMMON_MYDOC + L"\\my videos";
			m_COMMON_MD_MYMUSIC		= m_COMMON_MYDOC + L"\\my music";
			m_MYPICTURES			= m_COMMON_MYDOC + L"\\my pictures";
		}
		else
		{
			m_COMMON_MD_MYVIDEO		= m_COMMON_MYVIDEO;
			m_COMMON_MD_MYMUSIC		= m_COMMON_MYMUSIC;
			m_MYPICTURES			= m_COMMON_MYPIC;
		}

		m_COMMON_APPDATA		= this->GetFolderPath(CSIDL_APPDATA).MakeLower();
		ReplaceUserToAllUser(m_COMMON_APPDATA);

		m_COOKIES				= this->GetFolderPath(CSIDL_COOKIES).MakeLower();
		ReplaceUserToAllUser(m_COOKIES);
		if(m_COOKIES == BLANKSTRING)
			m_COMMON_TEMPLATES		= this->GetFolderPath(CSIDL_COMMON_TEMPLATES).MakeLower();
		else
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"Templates",m_COMMON_TEMPLATES,HKEY_USERS);
			m_COMMON_TEMPLATES.MakeLower();
		}
		ReplaceUserToAllUser(m_COMMON_TEMPLATES);

		m_COMMON_DESKTOP		= this->GetFolderPath(CSIDL_COMMON_DESKTOPDIRECTORY).MakeLower();
		m_AU_PRN_HOOD			= this->GetFolderPath(CSIDL_PRINTHOOD).MakeLower();
		if(m_AU_PRN_HOOD == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"PrintHood",m_AU_PRN_HOOD, HKEY_USERS);
			m_AU_PRN_HOOD.MakeLower();
		}
		ReplaceUserToAllUser(m_AU_PRN_HOOD);

		m_AU_NETHOOD			= this->GetFolderPath(CSIDL_NETHOOD).MakeLower();
		if(m_AU_NETHOOD == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"NetHood",m_AU_NETHOOD, HKEY_USERS);
			m_AU_NETHOOD.MakeLower();
		}
		ReplaceUserToAllUser(m_AU_NETHOOD);

		m_COMMON_FAVORITES		= this->GetFolderPath(CSIDL_COMMON_FAVORITES).MakeLower();
		if(m_COMMON_FAVORITES == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"Favorites",m_COMMON_FAVORITES, HKEY_USERS);
			m_COMMON_FAVORITES.MakeLower();
		}
		ReplaceUserToAllUser(m_COMMON_FAVORITES);

		m_AU_SM_PROG			= this->GetFolderPath(CSIDL_PROGRAMS).MakeLower();

		if(m_AU_SM_PROG == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"Programs",m_AU_SM_PROG, HKEY_USERS);
			m_AU_SM_PROG.MakeLower();
		}
		ReplaceUserToAllUser(m_AU_SM_PROG);


		m_AU_SM					= this->GetFolderPath(CSIDL_STARTMENU).MakeLower();
		if(m_AU_SM == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"Start Menu",m_AU_SM, HKEY_USERS);
			m_AU_SM.MakeLower();
		}
		ReplaceUserToAllUser(m_AU_SM);

		//startup
		if(m_AU_SM_PROG != BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"Startup",m_COMMON_STARTUP, HKEY_USERS);
			if(m_COMMON_STARTUP == BLANKSTRING)
				m_COMMON_STARTUP		= m_AU_SM_PROG + L"\\startup";
			m_COMMON_STARTUP.MakeLower();
		}
		else
			m_COMMON_STARTUP		= this->GetFolderPath(CSIDL_COMMON_STARTUP).MakeLower();
		ReplaceUserToAllUser(m_COMMON_STARTUP);


		m_AU_MY_RECENT_DOC		= this->GetFolderPath(CSIDL_RECENT).MakeLower();
		if(m_AU_MY_RECENT_DOC == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"Recent",m_AU_MY_RECENT_DOC, HKEY_USERS);
			m_AU_MY_RECENT_DOC.MakeLower();
		}
		ReplaceUserToAllUser(m_AU_MY_RECENT_DOC);

		m_AU_SENDTO				= this->GetFolderPath(CSIDL_SENDTO).MakeLower();
		if(m_AU_SENDTO == BLANKSTRING)
		{
			objReg.Get(csSID + BACK_SLASH+ REG_SHELL_FOLDER, L"SendTo",m_AU_SENDTO, HKEY_USERS);
			m_AU_SENDTO.MakeLower();
		}
		ReplaceUserToAllUser(m_AU_SENDTO);


		m_PROGRAM_FILES_COMMON	= this->GetFolderPath(CSIDL_PROGRAM_FILES_COMMON).MakeLower();
		if(m_bIsWin64)
		{
			m_PROGRAM_FILES_COMMONX86	= this->GetFolderPath(CSIDL_PROGRAM_FILES_COMMONX86).MakeLower();
		}
		m_PROGRAM_FILES			= this->GetFolderPath(CSIDL_PROGRAM_FILES).MakeLower();
		if(m_bIsWin64)
		{
			m_PROGRAM_FILESX86  = this->GetFolderPath(CSIDL_PROGRAM_FILESX86).MakeLower();
		}
		m_PF_COMMON_FILES		= m_PROGRAM_FILES + _T("\\common files");
		if(m_bIsWin64)
		{
			m_PFX86_COMMON_FILES = m_PROGRAM_FILESX86 + _T("\\common files");
		}
		m_SYSTEM32				= this->GetFolderPath(CSIDL_SYSTEM).MakeLower();
		if(m_bIsWin64)
		{
			m_SYSWOW64			= this->GetFolderPath(CSIDL_SYSTEMX86).MakeLower();
		}
		m_SYS32_DRIVERS			= m_SYSTEM32 + _T("\\drivers");
		if(m_bIsWin64)
		{
			m_SYSWOW64_DRIVERS	= m_SYSWOW64 + _T("\\drivers");
		}
		m_SYS32_DLLCACHE		= m_SYSTEM32 + _T("\\dllcache");
		if(m_bIsWin64)
		{
			m_SYSWOW64_DLLCACHE	= m_SYSWOW64 + _T("\\dllcache");
		}
		m_WINDOWS				= this->GetFolderPath(CSIDL_WINDOWS).MakeLower();
		m_SYSTEM				= m_WINDOWS + _T("\\system");
		m_WIN_APP_DATA			= m_WINDOWS + _T("\\application data");
		m_WIN_SPFILES			= m_WINDOWS + _T("\\servicepackfiles");
		m_WIN_MS_NET_FRM		= m_WINDOWS + _T("\\microsoft.net\\framework");
		m_WIN_MS_NET			= m_WINDOWS + _T("\\microsoft.net");
		m_FONTS					= this->GetFolderPath(CSIDL_FONTS).MakeLower();
		m_WIN_HELP				= m_WINDOWS + _T("\\help");
		m_WIN_DWN_PF			= m_WINDOWS + _T("\\downloaded program files");
		m_WIN_INSTALLER			= m_WINDOWS + _T("\\installer");
		m_WIN_RESOURCE			= this->GetFolderPath(CSIDL_RESOURCES).MakeLower();
		if(m_WIN_RESOURCE == BLANKSTRING)
			m_WIN_RESOURCE = m_WINDOWS + _T("\\resources");


		m_ADMINTOOLS			= this->GetFolderPath(CSIDL_ADMINTOOLS).MakeLower();
		m_COMMON_ADMINTOOLS		= this->GetFolderPath(CSIDL_COMMON_ADMINTOOLS).MakeLower();
		m_ROOT					= m_PROGRAM_FILES.Mid(0,m_PROGRAM_FILES.Find(_T(":")) +1).MakeLower();
		m_SYSTEMRESTORE			= m_ROOT + _T("\\_restore");

		if(CSystemInfo::m_strOS  == WVISTA)
		{
			objReg.Get(PROFILELIST_PATH,L"Default",m_DEFAULRUSER,HKEY_LOCAL_MACHINE);
			m_DEFAULRUSER.MakeLower();
			m_DEFAULRUSER.Replace((CONST_SYSTEM_DRIVE), (m_ROOT));
		}
		else
		{
			m_DEFAULRUSER = m_DAS;
			objReg.Get(PROFILELIST_PATH,L"DefaultUserProfile",m_DEFAULRUSER,HKEY_LOCAL_MACHINE);
			m_DEFAULRUSER.MakeLower();
			m_DEFAULRUSER = m_DAS + BACK_SLASH + m_DEFAULRUSER;

		}

		ReplaceUserToAllUser(m_INTERNET_CACHE);
		ReplaceUserToAllUser(m_HISTORY);

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CPathExpander::CPathExpander"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CPathExpander
In Parameters	:
Out Parameters	:
Purpose			:destruct CPathExpander class
Author			:
-----------------------------------------------------------------------------*/
CPathExpander::~CPathExpander(void)
{
}
/*-----------------------------------------------------------------------------
Function		: Shrink
In Parameters	: CString - file path
bool bx86 - 32/64 bit
Out Parameters	: void
Purpose			: Shrink path to tag
Author			: Dipali
-----------------------------------------------------------------------------*/
void CPathExpander::Shrink(CString & filePath, bool bx86)
{

	filePath.Replace((m_INTERNET_CACHE), (CONST_AU_LS_TEMP_IE));
	filePath.Replace((m_HISTORY), (CONST_AU_LS_HISTORY));
	filePath.Replace((m_LOCAL_APPDATA), (CONST_AU_LS_APPDATA));
	filePath.Replace((m_COMMON_LOCAL_SETTING), (CONST_AU_LS));
	filePath.Replace((m_COMMON_MD_MYVIDEO), (CONST_AU_MD_MYVIDEOS));
	filePath.Replace((m_COMMON_MD_MYMUSIC), (CONST_AU_MD_MYMUSIC));
	filePath.Replace((m_MYPICTURES), (CONST_AU_MD_MYPIC));
	filePath.Replace((m_COMMON_MYDOC), (CONST_AU_MYDOC));
	filePath.Replace((m_COMMON_APPDATA), (CONST_AU_APPDATA));
	filePath.Replace((m_COMMON_TEMPLATES), (CONST_AU_TEMPLATES));
	filePath.Replace((m_COOKIES), (CONST_AU_COOKIES));
	filePath.Replace((m_COMMON_DESKTOP), (CONST_AU_DESKTOP));
	filePath.Replace((m_COMMON_MYVIDEO), (CONST_AU_D_MYVIDEOS));
	filePath.Replace((m_COMMON_MYMUSIC), (CONST_AU_D_MYMUSIC));
	filePath.Replace((m_COMMON_MYPIC), (CONST_AU_D_MYPIC));
	filePath.Replace((m_COMMON_DOCUMENTS), (CONST_AU_DOC));
	filePath.Replace((m_AU_PRN_HOOD), (CONST_AU_PRN_HOOD));
	filePath.Replace((m_AU_NETHOOD), (CONST_AU_NET_HOOD));
	filePath.Replace((m_COMMON_FAVORITES), (CONST_AU_FAVORITES));
	filePath.Replace((m_COMMON_STARTUP), (CONST_AU_SM_P_STARTUP));
	filePath.Replace((m_AU_SM_PROG), (CONST_AU_SM_PROG));
	filePath.Replace((m_AU_SM), (CONST_AU_SM));
	filePath.Replace((m_AU_MY_RECENT_DOC), (CONST_AU_MY_RECENT_DOC));
	filePath.Replace((m_PROFILE), (CONST_AU));
	filePath.Replace((m_DAS), (CONST_DAS));
	if(bx86)
	{
		filePath.Replace((m_PFX86_COMMON_FILES), (CONST_PF_COMMON));
		filePath.Replace((m_PROGRAM_FILESX86), (CONST_PF));
		filePath.Replace((m_SYSWOW64_DRIVERS), (CONST_WIN_SYS32_DRIVERS));
		filePath.Replace((m_SYSWOW64), (CONST_WIN_SYS32));
		//old tag- remove after db change
		filePath.Replace((m_SYSWOW64), (CONST_SYSTEM_DIR));
		filePath.Replace((m_PROGRAM_FILESX86), (CONST_PF_DIR));
		filePath.Replace((m_SYSWOW64_DLLCACHE), (CONST_WIN_SYS32_DLLCACHE));
	}
	else
	{
		filePath.Replace((m_PF_COMMON_FILES), (CONST_PF_COMMON));
		filePath.Replace((m_PROGRAM_FILES), (CONST_PF));
		filePath.Replace((m_SYS32_DRIVERS), (CONST_WIN_SYS32_DRIVERS));
		filePath.Replace((m_SYSTEM32), (CONST_WIN_SYS32));

	}

	filePath.Replace((m_SYSTEM), (CONST_WIN_SYS));
	filePath.Replace((m_WIN_APP_DATA), (CONST_WIN_APP_DATA));
	filePath.Replace((m_WIN_SPFILES), (CONST_WIN_SPFILES));
	filePath.Replace((m_WIN_MS_NET_FRM), (CONST_WIN_MS_NET_FRM));
	filePath.Replace((m_WIN_MS_NET), (CONST_WIN_MS_NET));
	filePath.Replace((m_FONTS), (CONST_WIN_FONT));
	filePath.Replace((m_WIN_HELP), (CONST_WIN_HELP));
	filePath.Replace((m_WIN_DWN_PF), (CONST_WIN_DWN_PF));
	filePath.Replace((m_WIN_INSTALLER), (CONST_WIN_INSTALLER));
	filePath.Replace((m_WIN_RESOURCE), (CONST_WIN_RESOURCE));
	filePath.Replace((m_WINDOWS), (CONST_WIN));
	filePath.Replace((m_ROOT), (CONST_ROOT));

	filePath.Replace((m_ADMINTOOLS), (CONST_ADMINTOOLS_DIR));
	filePath.Replace((m_COMMON_ADMINTOOLS), (CONST_COMMON_ADMINTOOLS_DIR));
}

/*-----------------------------------------------------------------------------
Function		: ReplaceUserToAllUser
In Parameters	: CString &csPath - path
Out Parameters	: -
Purpose			:Replace user name to All user
Author			:
-----------------------------------------------------------------------------*/
void CPathExpander::ReplaceUserToAllUser(CString &csPath)
{
	csPath.Replace(m_SVCPROFILE,m_PROFILE);
	csPath.Replace(m_CUPROFILE, m_PROFILE);
	if(m_LOCALSVCUSER == BLANKSTRING)
		csPath.Replace(m_DAS + _T("\\localservice"), m_PROFILE);
	else
	{
		csPath.Replace(m_LOCALSVCUSER, m_PROFILE);
	}

	if(m_DEFAULRUSER == BLANKSTRING)
		csPath.Replace(m_DAS + _T("\\default user"), m_PROFILE);
	else
		csPath.Replace(m_DEFAULRUSER, m_PROFILE);
}

/*-----------------------------------------------------------------------------
Function		: ShrinkProfilePath
In Parameters	: CString sPath - path
CStringArray &sProfilePathArr - profile path array
Out Parameters	: void
Purpose			: Shrin profile path to tag
Author			: Dipali Pawar
-----------------------------------------------------------------------------*/
void CPathExpander::ShrinkProfilePath(CString &sPath, const CArray<CString,CString> &sProfilePathArr)
{
	{
		for(int i=0; i < sProfilePathArr.GetCount(); i++)
		{
			sPath.Replace(sProfilePathArr.GetAt(i) + BACK_SLASH, m_PROFILE + BACK_SLASH);
		}
	}
}

/*-----------------------------------------------------------------------------
Function		: Expand
In Parameters	: CString
Out Parameters	: void
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
void CPathExpander::Expand(CString & filePath,bool bx86)
{
	filePath.MakeLower();
	filePath.Replace((CONST_AU_LS_TEMP_IE), (m_INTERNET_CACHE));
	filePath.Replace((CONST_AU_LS_HISTORY), (m_HISTORY));
	filePath.Replace((CONST_AU_LS_APPDATA), (m_LOCAL_APPDATA));
	filePath.Replace((CONST_AU_LS), (m_COMMON_LOCAL_SETTING));
	filePath.Replace((CONST_AU_MD_MYVIDEOS), (m_COMMON_MD_MYVIDEO));
	filePath.Replace((CONST_AU_MD_MYMUSIC), (m_COMMON_MD_MYMUSIC));
	filePath.Replace((CONST_AU_MD_MYPIC), (m_MYPICTURES));
	filePath.Replace((CONST_AU_MYDOC), (m_COMMON_MYDOC));
	filePath.Replace((CONST_AU_APPDATA), (m_COMMON_APPDATA));
	filePath.Replace((CONST_AU_TEMPLATES), (m_COMMON_TEMPLATES));
	filePath.Replace((CONST_AU_COOKIES), (m_COOKIES));
	filePath.Replace((CONST_AU_DESKTOP), (m_COMMON_DESKTOP));
	filePath.Replace((CONST_AU_D_MYVIDEOS), (m_COMMON_MYVIDEO));
	filePath.Replace((CONST_AU_D_MYMUSIC), (m_COMMON_MYMUSIC));
	filePath.Replace((CONST_AU_D_MYPIC), (m_COMMON_MYPIC));
	filePath.Replace((CONST_AU_DOC), (m_COMMON_DOCUMENTS));
	filePath.Replace((CONST_AU_PRN_HOOD), (m_AU_PRN_HOOD));
	filePath.Replace((CONST_AU_NET_HOOD), (m_AU_NETHOOD));
	filePath.Replace((CONST_AU_FAVORITES), (m_COMMON_FAVORITES));
	filePath.Replace((CONST_AU_SM_P_STARTUP), (m_COMMON_STARTUP));
	filePath.Replace((CONST_AU_SM_PROG), (m_AU_SM_PROG));
	filePath.Replace((CONST_AU_SM), (m_AU_SM));
	filePath.Replace((CONST_AU_MY_RECENT_DOC), (m_AU_MY_RECENT_DOC));
	filePath.Replace((CONST_AU_SENDTO), (m_AU_SENDTO));
	filePath.Replace((CONST_AU), (m_PROFILE));
	filePath.Replace((CONST_DAS), (m_DAS));
	if(bx86)
	{
		filePath.Replace((CONST_PF_COMMON), (m_PFX86_COMMON_FILES));
		filePath.Replace((CONST_PF), (m_PROGRAM_FILESX86));
		filePath.Replace((CONST_WIN_SYS32_DRIVERS), (m_SYSWOW64_DRIVERS));
		filePath.Replace((CONST_WIN_SYS32), (m_SYSWOW64));
		//old tag- remove after db change
		filePath.Replace((CONST_SYSTEM_DIR), (m_SYSWOW64));
		filePath.Replace((CONST_PF_DIR), (m_PROGRAM_FILESX86));
		filePath.Replace((CONST_WIN_SYS32_DLLCACHE), (m_SYSWOW64_DLLCACHE));
	}
	else
	{
		filePath.Replace((CONST_PF_COMMON), (m_PF_COMMON_FILES));
		filePath.Replace((CONST_PF), (m_PROGRAM_FILES));
		filePath.Replace((CONST_WIN_SYS32_DRIVERS), (m_SYS32_DRIVERS));
		filePath.Replace((CONST_WIN_SYS32), (m_SYSTEM32));
		//old tag-  remove after db change
		filePath.Replace((CONST_SYSTEM_DIR), (m_SYSTEM32));
		filePath.Replace((CONST_PF_DIR), (m_PROGRAM_FILES));
		filePath.Replace((CONST_WIN_SYS32_DLLCACHE), (m_SYS32_DLLCACHE));
	}

	filePath.Replace((CONST_WIN_SYS), (m_SYSTEM));
	filePath.Replace((CONST_WIN_APP_DATA), (m_WIN_APP_DATA));
	filePath.Replace((CONST_WIN_SPFILES), (m_WIN_SPFILES));
	filePath.Replace((CONST_WIN_MS_NET_FRM), (m_WIN_MS_NET_FRM));
	filePath.Replace((CONST_WIN_MS_NET), (m_WIN_MS_NET));
	filePath.Replace((CONST_WIN_FONT), (m_FONTS));
	filePath.Replace((CONST_WIN_HELP), (m_WIN_HELP));
	filePath.Replace((CONST_WIN_DWN_PF), (m_WIN_DWN_PF));
	filePath.Replace((CONST_WIN_INSTALLER), (m_WIN_INSTALLER));
	filePath.Replace((CONST_WIN_RESOURCE), (m_WIN_RESOURCE));
	filePath.Replace((CONST_WIN), (m_WINDOWS));
	filePath.Replace((CONST_ROOT), (m_ROOT));

	filePath.Replace((CONST_ADMINTOOLS_DIR), (m_ADMINTOOLS));
	filePath.Replace((CONST_COMMON_ADMINTOOLS_DIR), (m_COMMON_ADMINTOOLS));

	//System tag
	filePath.Replace((CONST_PROGRAM_FILES_DIR), (m_PROGRAM_FILES));
	filePath.Replace((CONST_WINDOWS_DIR), (m_WINDOWS));
	filePath.Replace((CONST_SYSTEM_ROOT), (m_WINDOWS));
	filePath.Replace((CONST_SYSTEM_DRIVE), (m_ROOT));
	filePath.Replace((CONST_PROFILE_DIR_2), (m_PROFILE));
	filePath.Replace((CONST_LOCAL_APPDATA_DIR_2),(m_LOCAL_APPDATA));
}

/*-----------------------------------------------------------------------------
Function		: GetFolderPath
In Parameters	: int
Out Parameters	: CString
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
CString CPathExpander::GetFolderPath(int nFolder)
{
	try
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
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CPathExpander::GetFolderPath"));
	}
	return _T("");
}

/*-----------------------------------------------------------------------------
Function		: ExpandProfilePath
In Parameters	: CString, const CString
Out Parameters	: void
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
void CPathExpander::ExpandProfilePath(CString &sPath, const CString &sProfilePath)
{
	sPath.Replace(m_PROFILE, sProfilePath);
	if(m_SVCPROFILE != BLANKSTRING)
		sPath.Replace(m_SVCPROFILE, sProfilePath);
	sPath.Replace(m_DAS + _T("\\localservice"), sProfilePath);
	sPath.Replace(m_DAS + _T("\\default user"), sProfilePath);
}

/*-----------------------------------------------------------------------------
Function		: ExpandProfilePath
In Parameters	: CString, const CString
Out Parameters	: void
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
bool CPathExpander::IsProfilePath(const CString &sWormPath)
{
	if(m_bIsWin98)// for windows 98 we dont need any special handling!
		return false;

	if(sWormPath.Find(L"%das.au") != -1)
		return true;
	return false;
}

/*-----------------------------------------------------------------------------
Function		: IsRegProfilePath
In Parameters	: CString
Out Parameters	: bool
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
bool CPathExpander::IsRegProfilePath(CString &sWormPath)
{
	if(m_bIsWin98)// for windows 98 we dont need any special handling!
		return false;

	if(sWormPath.GetLength()< 9)
		return false;

	if(sWormPath.Find(_T("%profile%")) != -1)
		return true;
	if(sWormPath.Find(_T("%appdata%")) != -1)
		return true;
	if(sWormPath.Find(_T("%personal%")) != -1)
		return true;
	if(sWormPath.Find(_T("%favorites%")) != -1)
		return true;
	if(sWormPath.Find(_T("%mypictures%")) != -1)
		return true;
	if(sWormPath.Find(_T("%local_appdata%")) != -1)
		return true;
	return false;
}

/*-----------------------------------------------------------------------------
Function		: IsCurrentUserPath
In Parameters	: const CString
Out Parameters	: bool
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
bool CPathExpander::IsCurrentUserPath(const CString &sWormPath)
{
	if(sWormPath.GetLength()< 17)
		return false;

	if(sWormPath.Left(17).CompareNoCase(HKCU) == 0)
		return true;

	return false;
}

/*-----------------------------------------------------------------------------
Function		: IsCurrentUserPath
In Parameters	: const CString
Out Parameters	: bool
Purpose			: Check for local machine path
Author			: Dipali
-----------------------------------------------------------------------------*/
bool CPathExpander::IsLocalMachinePath(const CString &sWormPath)
{
	if(sWormPath.GetLength()< 18)
		return false;

	if(sWormPath.Left(18) == _T("hkey_local_machine"))
		return true;

	return false;
}

/*-----------------------------------------------------------------------------
Function		: ExpandCurrentUserPath
In Parameters	: CString, const CString
Out Parameters	: void
Purpose			:
Author			:
-----------------------------------------------------------------------------*/
void CPathExpander::ExpandCurrentUserPath(CString &sRegWorm, const CString &sUserPath)
{
	sRegWorm.Replace(_T("hkey_current_user"), sUserPath);
}

/*-----------------------------------------------------------------------------
Function		: ReplaceLocalMachineWithCurrentUser
In Parameters	: CString
Out Parameters	: void
Purpose			:
Author			: Dipali
-----------------------------------------------------------------------------*/
void CPathExpander::ReplaceLocalMachineWithCurrentUser(CString &sRegWorm)
{
	sRegWorm.Replace(_T("hkey_local_machine"), _T("hkey_current_user"));
}

/*-----------------------------------------------------------------------------
Function		: ReplaceLocalMachineClassWithClassRoot
In Parameters	: CString
Out Parameters	: void
Purpose			:
Author			: Dipali
-----------------------------------------------------------------------------*/
void CPathExpander::ReplaceLocalMachineClassWithClassRoot(CString &sRegWorm)
{
	sRegWorm.Replace(_T("hkey_local_machine\\software\\classes"), _T("hkey_classes_root"));
}

/*-----------------------------------------------------------------------------
Function		: IsLocalClassPath
In Parameters	: const CString
Out Parameters	: bool
Purpose			:
Author			: Dipali
-----------------------------------------------------------------------------*/
bool CPathExpander::IsLocalClassPath(const CString &sWormPath)
{
	CString csClassPath = _T("hkey_local_machine\\software\\classes");
	if(sWormPath.GetLength()< csClassPath.GetLength())
		return false;

	if(sWormPath.Left(csClassPath.GetLength()) == csClassPath)
		return true;

	return false;
}

/*-----------------------------------------------------------------------------
Function		: IsLocalClassPath
In Parameters	: const CString
Out Parameters	: bool
Purpose			: replace the tags with full qualified path[no 64 paths to resolve]
Author			: Anand Srivastava
-----------------------------------------------------------------------------*/
bool CPathExpander::ExpandSystemTags(CString& filepath, bool bx86)
{
	filepath.MakeLower();

	if(filepath.Find(L"system32\\") == 0)
	{
		filepath.Replace(_T("system32"), m_SYSTEM32);
		return true;
	}

	filepath.Replace(_T("%systemroot%"), m_WINDOWS);
	filepath.Replace(_T("%%systemroot%%"), m_WINDOWS);
	filepath.Replace(_T("%%systemdrive%%"), m_ROOT);
	filepath.Replace(_T("%%systemdirectory%%"), m_WINDOWS);
	filepath.Replace(_T("%%windir%%"), m_WINDOWS);
	filepath.Replace(_T("%%homedrive%%"), m_ROOT);
	filepath.Replace(_T("%programfiles%"), m_PROGRAM_FILES);

	if(-1 == filepath.Find(_T('\\')))
	{
		TCHAR szFullname[MAX_PATH]={0};
		_tsearchenv_s(filepath, _T("Path"), szFullname, _countof(szFullname));
		if(0 != szFullname[0])filepath = szFullname;
		else
		{
			if(!bx86)
			{
				filepath = m_SYSTEM32 + BACK_SLASH + filepath;
			}
			else
			{
				filepath = m_SYSWOW64 + BACK_SLASH + filepath;
			}

		}
	}

	return (true);
}

/*-----------------------------------------------------------------------------
Function		: GetRegPathX64
In Parameters	: const CString - path
Out Parameters	: bool
Purpose			: convert path from 64 bit to 32 bit
Author			: Dipali
-----------------------------------------------------------------------------*/
CString CPathExpander::GetRegPathX64(CString &csPath)
{
	CString cs64bitPath(csPath);
	cs64bitPath.MakeLower();
	cs64bitPath.Replace(REG_SW_MS_PATH, REG_SW_MS_PATH_X86);
	return cs64bitPath;
}