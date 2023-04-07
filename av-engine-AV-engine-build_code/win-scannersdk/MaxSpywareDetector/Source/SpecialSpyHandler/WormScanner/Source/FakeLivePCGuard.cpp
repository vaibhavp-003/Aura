/*======================================================================================
   FILE				: FakeLivePCGuard.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware FakeLivePCGuard
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Yuvraj 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 2-2-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "FakeLivePCGuard.h"
#include "ExecuteProcess.h"
#include <io.h>
#include <list>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load
//HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
//HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler

#define  RUNONCE_REG_PATH						_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce") 
#define  UNDERWOW_RUNONCR_REG_PATH				_T("Microsoft\\Windows\\CurrentVersion\\RunOnce")
#define  RUNONCESERVICE_REG_PATH				_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce")
#define  UNDERWOW_RUNONCESERVICE_REG_PATH		_T("Microsoft\\Windows\\CurrentVersion\\RunServicesOnce")
#define  RUNONCESERVICES_REG_PATH				_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices")
#define  UNDERWOW_RUNONCESERVICES_REG_PATH		_T("Microsoft\\Windows\\CurrentVersion\\RunServices")
#define  RUNONCEEX_REG_PATH						_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx")
#define  UNDERWOW_RUNONCEEX_REG_PATH			_T("Microsoft\\Windows\\CurrentVersion\\RunOnceEx")
#define	 HKEY_USERS_WINLOGON_SHELL				_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");

std::list<std::wstring> m_ListReported;
std::vector<std::wstring> m_ListAllFiles;
std::vector<CFakeAvData*> m_AllDataStructs;
std::vector<std::wstring> m_UserInitList;
std::vector<std::wstring> m_ShellInitList;
std::vector<std::wstring> m_LoadInitList;

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: 
	Purpose			: 
	Author			: Yuvraj
	Description		: main entry point of this class for spyware scanning
--------------------------------------------------------------------------------------*/
bool CFakeLivePCGuard::IsSameSize(std::wstring& wStr1, std::wstring& wStr2)
{
	HANDLE hFile;
	DWORD dwFileSizeStr1;
	DWORD dwFileSizeStr2;
	hFile = CreateFile(wStr1.c_str(), GENERIC_READ , FILE_SHARE_READ,0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return (false);
	}

	dwFileSizeStr1 = GetFileSize(hFile,NULL);
	CloseHandle(hFile);

	hFile = CreateFile(wStr2.c_str(), GENERIC_READ , FILE_SHARE_READ,0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return (false);
	}

	dwFileSizeStr2 = GetFileSize(hFile,NULL);
	CloseHandle(hFile);

	if(dwFileSizeStr1 > 0 &&  dwFileSizeStr2 > 0 && dwFileSizeStr1 == dwFileSizeStr2)
	{
		return true;
	}

	return false;
}
bool CFakeLivePCGuard  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
 	try
	{
		if(bToDelete)
			return false;

		CExecuteProcess objExeProc;
		CString csSid = objExeProc.GetCurrentUserSid();
		InitFolderData();
		ShellServiceObjectDelayLoad();
		m_csINIFileName = CSystemInfo::m_strAppPath + _T("Setting\\InstantScan.ini");
		m_pFileSig = new CFileSig;
		

		if(IsStopScanningSignaled())
		{
			return(m_bSplSpyFound);
		}

		
		ParseWinlogonUserInit();
		ParseWinlogonShell(HKEY_LOCAL_MACHINE);
		ParseWinlogonShell(HKEY_USERS);
		

		ScanEnrtyInRun(HKEY_LOCAL_MACHINE, RUN_REG_PATH);
		ScanEnrtyInRun(HKEY_LOCAL_MACHINE, RUNONCE_REG_PATH);

		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUN_REG_PATH);
		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCE_REG_PATH);

		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCESERVICE_REG_PATH);
		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCESERVICE_REG_PATH);

		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCESERVICES_REG_PATH);
		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCESERVICES_REG_PATH);

		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCEEX_REG_PATH);
		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUNONCEEX_REG_PATH);


		if(m_bScanOtherLocations)
		{
			CString csWowPath = CString(WOW6432NODE_REG_PATH) + UNDERWOW_RUN_REG_PATH;
			CString csWowRunOncePath = CString(WOW6432NODE_REG_PATH) + UNDERWOW_RUNONCR_REG_PATH;

			ScanEnrtyInRun(HKEY_LOCAL_MACHINE, csWowPath);
			ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + csWowPath);

			ScanEnrtyInRun(HKEY_LOCAL_MACHINE, csWowRunOncePath);
			ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + csWowRunOncePath);

			ScanEnrtyInRun(HKEY_LOCAL_MACHINE, UNDERWOW_RUNONCESERVICE_REG_PATH);
			ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + UNDERWOW_RUNONCESERVICE_REG_PATH);

			ScanEnrtyInRun(HKEY_LOCAL_MACHINE, UNDERWOW_RUNONCESERVICES_REG_PATH);
			ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + UNDERWOW_RUNONCESERVICES_REG_PATH);

			ScanEnrtyInRun(HKEY_LOCAL_MACHINE, UNDERWOW_RUNONCEEX_REG_PATH);
			ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + UNDERWOW_RUNONCEEX_REG_PATH);
		}

		

		m_ShortCutPath1.Append(L"\\*lnk");
		EnumerateFolder((std::wstring) m_ShortCutPath1);

		m_ShortCutPath2.Append(L"\\*lnk");
		EnumerateFolder((std::wstring) m_ShortCutPath2);

		m_ShortCutPath3.Append(L"\\*lnk");
		EnumerateFolder((std::wstring) m_ShortCutPath3);

		m_ListReported.sort();
		m_ListReported.unique();
		

		
		std::list<std::wstring>::iterator itr;
		
		for(int i=0; i< m_AllDataStructs.size(); i++)
		{
			std::wstring wStrFile(m_AllDataStructs[i]->m_FilePath);
			for(itr = m_ListReported.begin(); itr != m_ListReported.end(); itr++)
			{
				if((*itr).find((std::wstring)(m_AllDataStructs[i]->m_FilePath)) == std::wstring::npos)
				{
					if(IsSameSize(m_ListAllFiles[i],*itr))
					{
						CString csFilePath(m_ListAllFiles[i].c_str());
						DWORD dwAttrib = ::GetFileAttributes(csFilePath);
						if(dwAttrib & FILE_ATTRIBUTE_HIDDEN)
							::SetFileAttributes(csFilePath,FILE_ATTRIBUTE_NORMAL);

							if(_waccess(csFilePath,0) != -1)
							{
								SendScanStatusToUI(Special_File, m_ulSpyName, csFilePath);
								WriteSignatureToIni((CString) m_ListAllFiles[i].c_str());

								SendScanStatusToUI(Special_RegVal, m_ulSpyName , m_AllDataStructs[i]->hHive, m_AllDataStructs[i]->m_RegLocation ,
									m_AllDataStructs[i]->m_RegKey, REG_SZ, (LPBYTE)m_ListAllFiles[i].c_str(), m_ListAllFiles[i].size()*2);
							}
						}	
				}
			}
		}

		for(int i=0; i< m_AllDataStructs.size(); i++)
		{
			if(m_AllDataStructs[i])
				delete m_AllDataStructs[i];
		}

		for(itr = m_ListReported.begin(); itr != m_ListReported.end(); itr++)
		{
			CString cLinkFile((*itr).c_str());
			cLinkFile.MakeLower();
			ScanLinkFile((LPCTSTR) cLinkFile);
		}

		
		for(int i= 0; i < m_UserInitList.size(); i++)
		{
			if(_waccess(m_UserInitList[i].c_str(),0) != -1)
			{
				SendScanStatusToUI(Special_File, m_ulSpyName, m_UserInitList[i].c_str());
				CString csSig(m_UserInitList[i].c_str());
				WriteSignatureToIni(csSig);
			}
		}

		for(int i= 0; i < m_ShellInitList.size(); i++)
		{
			if(_waccess(m_ShellInitList[i].c_str(),0) != -1)
			{
				SendScanStatusToUI(Special_File, m_ulSpyName, m_ShellInitList[i].c_str());
				CString csSig(m_ShellInitList[i].c_str());
				WriteSignatureToIni(csSig);
			}
		}


		m_UserInitList.clear();
		m_ShellInitList.clear();
		m_ListReported.clear();
		m_AllDataStructs.clear();
		m_ListAllFiles.clear();
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}
	catch( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CFakeLivePCGuard::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry( csErr, 0, 0 );
	}
	
	return( false );
}

/*-------------------------------------------------------------------------------------
	Function		: ScanEnrtyInRun
	In Parameters	: HKEY, CString
	Out Parameters	: 
	Purpose			: To scan entry in Run Registry
	Author			: Yuvraj
	Description		: To scan data part in Run registry and search the pattern to catch 
					  infection	
--------------------------------------------------------------------------------------*/
bool CFakeLivePCGuard :: ScanEnrtyInRun(HKEY hHive, CString csLocation)
{
	int iFileInd, iAppInd;
	CStringArray csArrValues, csArrData;
	CRegistry m_objRegLocal;
	

	m_objRegLocal.QueryDataValue(csLocation, csArrValues, csArrData, hHive);

	for(INT_PTR i = 0, iTotal = csArrValues.GetCount() ; i < iTotal ; i++)
	{
		
	}

	for(INT_PTR i = 0, iTotal = csArrValues.GetCount() ; i < iTotal ; i++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		CString csFilePath;
		CString csAppPath;
		
		CString csTempOriginalFilePath;
		
		CString csData(csArrData.GetAt(i));
		CString csOriginalFilePath(csArrData.GetAt(i));
		csData.Remove(L'"');
		csOriginalFilePath.Remove(L'"');
		
		
		TCHAR szNewPath[512];
		memset(szNewPath,'\0',512);
		GetLongPathName(csOriginalFilePath.GetBuffer(), szNewPath, _countof(szNewPath));	
		CString temData(szNewPath);

		csData = temData;
		csOriginalFilePath = temData;

		csData.MakeLower();
		csOriginalFilePath  = temData;
		csOriginalFilePath.MakeLower();
		m_ListAllFiles.push_back((std::wstring)csOriginalFilePath.GetBuffer()) ;

		CFakeAvData *pData = new CFakeAvData();

		pData->m_FilePath = csOriginalFilePath;
		pData->m_RegKey = csArrValues.GetAt(i);
		pData->m_RegLocation = csLocation;
		pData->hHive = hHive;
		m_AllDataStructs.push_back(pData);


		if(csData.Find(L"\\programdata\\") >= 0 || csData.Find(L"\\application data\\") >= 0 || csData.Find(L"\\appdata\\roaming\\") >= 0){} 
		else
		{
			continue;
		}

		int iFileIndExe = csData.Find(_T(".exe"));
		int iFileIndCom = csData.Find(_T(".com"));
		int iFileIndBat = csData.Find(_T(".bat"));
		bool IsAllowed = false;

		if(iFileIndExe != -1 || iFileIndCom != -1 || iFileIndBat != -1)
		{
			IsAllowed = true;
		}

		if(!IsAllowed)
		{
			continue;
		}
		
		if(!IsRootFolder(csOriginalFilePath))
		{
			if(!IsSameFolderFileName(csOriginalFilePath))
			{
				continue;
			}
		}

		m_bSplSpyFound = true;
		iFileInd = csData.ReverseFind(_T('\\'));
		csFilePath = csData.Left(iFileInd);
		csFilePath.Remove(_T('"'));
		
		if(m_bSplSpyFound)
		{
			bool isReportedEarliar = false;
			int iSizeOfData = csData.GetLength()*2;
			
			if(_waccess(csOriginalFilePath,0) != -1)
			{
				SendScanStatusToUI(Special_File, m_ulSpyName, csOriginalFilePath);
				m_ListReported.push_back(std::wstring(csOriginalFilePath.GetBuffer()));			

				SendScanStatusToUI(Special_RegVal, m_ulSpyName , hHive, csLocation ,
									csArrValues.GetAt(i), REG_SZ, (LPBYTE)csData.GetBuffer(), 
									iSizeOfData);

				WriteSignatureToIni(csOriginalFilePath);

			}
		}
		
	}

	return m_bSplSpyFound;
}
bool CFakeLivePCGuard::IsRootFolder(CString& csData)
{
	bool bRootFolder = false;
	std::wstring wsAppdata(L"application data");
	std::wstring wsProgramData(L"programdata");
	std::wstring wsRoaming(L"roaming");
	std::wstring wsMicroSoft(L"microsoft");

	std::wstring wsRoot(csData);
	size_t nPos = wsRoot.find_last_of(L"\\");
	
	if(nPos != std::wstring::npos)
	{
		std::wstring wsRootLeft(wsRoot);
		wsRootLeft.erase(nPos,wsRootLeft.size());
		nPos = wsRootLeft.find_last_of(L"\\");
		
		if(nPos != std::wstring::npos)
		{
			wsRootLeft.erase(0, nPos+1);
			
			if(wsRootLeft.find(wsAppdata) != std::wstring::npos)
			{
				if(wsAppdata.size() == wsRootLeft.size())
				{
					bRootFolder = true;
				}
			}

			if(wsRootLeft.find(wsProgramData) != std::wstring::npos)
			{
				if(wsProgramData.size() == wsRootLeft.size())
				{
					bRootFolder = true;
				}
			}

			if(wsRootLeft.find(wsRoaming) != std::wstring::npos)
			{
				if(wsRoaming.size() == wsRootLeft.size())
				{
					bRootFolder = true;
				}
			}

			if(wsRootLeft.find(wsMicroSoft) != std::wstring::npos)
			{
				if(wsMicroSoft.size() == wsRootLeft.size())
				{
					OutputDebugStringA("Match found");
					bRootFolder = true;
				}
			}
		}
	}

	return bRootFolder;
}
bool CFakeLivePCGuard::IsSameFolderFileName(CString& csData)
{
	bool bSameFF = false;
	std::wstring strLocalData(csData.GetBuffer());

	std::wstring strFirstRemoval(strLocalData);
	size_t nPos = strFirstRemoval.find_last_of(L"\\");
	if(nPos != std::wstring::npos)
	{
		std::wstring leftPostRemoval(strFirstRemoval);
		std::wstring RightPostRemoval(strFirstRemoval);
		leftPostRemoval.erase(nPos,leftPostRemoval.size());

		RightPostRemoval.erase(0,nPos+1);
		RightPostRemoval.erase(RightPostRemoval.size() - 4,RightPostRemoval.size());

		nPos = leftPostRemoval.find_last_of(L"\\");
		if(nPos != std::wstring::npos)
		{
			leftPostRemoval.erase(0,nPos +1);
		}
	

		if(RightPostRemoval.find(leftPostRemoval) != wstring::npos)
		{
			if(leftPostRemoval.size() == RightPostRemoval.size())
			{
				bSameFF = true;
			}
		}
	}

	return bSameFF;
}

void CFakeLivePCGuard::InitFolderData()
{
	TCHAR strPath[ MAX_PATH ];
     SHGetSpecialFolderPath(0,strPath, CSIDL_APPDATA,FALSE );
	_tcsupr(strPath);

	m_UsrPath = (CString) strPath;
	m_UsrPath.MakeLower();

	SHGetSpecialFolderPath(0,strPath,CSIDL_LOCAL_APPDATA,FALSE );
	_tcsupr(strPath);

	m_LocalPath = (CString) strPath;
	m_LocalPath.MakeLower();
	


	SHGetSpecialFolderPath(0,strPath, CSIDL_COMMON_APPDATA,FALSE );
	_tcsupr(strPath);

	m_wsPath = (CString) strPath;
	m_wsPath.MakeLower();

	
	memset(strPath,'\0',MAX_PATH);

	SHGetSpecialFolderPath(0,strPath,CSIDL_STARTUP,FALSE );
	m_ShortCutPath1 = (CString) strPath;
	m_ShortCutPath1.MakeLower();
	m_ShortCutPath1.Append(L"\\");

	memset(strPath,'\0',MAX_PATH);
	SHGetSpecialFolderPath(0,strPath,CSIDL_COMMON_STARTUP,FALSE );
	m_ShortCutPath2 = (CString) strPath;
	m_ShortCutPath2.MakeLower();
	m_ShortCutPath2.Append(L"\\");

	memset(strPath,'\0',MAX_PATH);
	SHGetSpecialFolderPath(0,strPath,CSIDL_DESKTOPDIRECTORY,FALSE );
	m_ShortCutPath3 = (CString) strPath;
	m_ShortCutPath3.MakeLower();
	m_ShortCutPath3.Append(L"\\");

	
}

bool CFakeLivePCGuard::ScanLinkFile(LPCTSTR szFilePath)
{
	CString csFullFilePath(szFilePath);
	CString csFileName;
	CString csArguments;
	TCHAR szFullCommandLine [ MAX_PATH ] = { 0 } ;
	TCHAR szDirPath [ MAX_PATH ] = { 0 } ;
	bool bRet = false;

	

	csFullFilePath.MakeLower();
	if(csFullFilePath.Right(4) == _T(".lnk"))
	{
		
		csFullFilePath.Replace(_T(".lnk"),_T(""));
		int iPos = csFullFilePath.ReverseFind(_T('\\'));
		csFileName = csFullFilePath.Mid (iPos + 1);

		DWORD dwAttrib = ::GetFileAttributes(csFullFilePath);
		if(dwAttrib & FILE_ATTRIBUTE_HIDDEN)
			::SetFileAttributes(csFullFilePath,FILE_ATTRIBUTE_NORMAL);

		
		if(_waccess(csFullFilePath,0) != -1)
		{	
			if(ResolveShortcut(szFilePath, szFullCommandLine,  _countof(szFullCommandLine), szDirPath, false))
			{		
				csArguments = (CString)szFullCommandLine;
				csArguments.MakeLower();
				
				if(csArguments.Find(L"\\programdata\\") >= 0 || csArguments.Find(L"\\application data\\") >= 0 || csArguments.Find(L"\\appdata\\roaming\\") >= 0)
				{
					
					if(IsRootFolder(csArguments))
					{
						if(_waccess(csArguments,0) != -1)
						{
							SendScanStatusToUI(Special_File, m_ulSpyName, csArguments);
							SendScanStatusToUI(Special_File, m_ulSpyName, szFilePath);
							WriteSignatureToIni(csArguments);
							WriteSignatureToIni(szFilePath);
						}
					}
				}
			}
		}
	}
	return bRet;
}

bool CFakeLivePCGuard::ResolveShortcut(LPCTSTR szShortcutFileName, LPTSTR szArguments, DWORD cbArguments, LPTSTR strworkdir ,bool bGetArgs)
{
    HRESULT hRes = E_FAIL;
    CComPtr<IShellLink> ipShellLink = NULL ;
    TCHAR szPath [ MAX_PATH ] = { 0 } ;
    TCHAR szDesc [ MAX_PATH ] = { 0 } ;
    WIN32_FIND_DATA wfd = { 0 } ;
    WCHAR wszTemp [ MAX_PATH ] = { 0 } ;

	// Removed Coinit as this is already done in AuScanner
	hRes = CoInitialize ( NULL ) ;
	COINITIALIZE_OUTPUTDEBUGSTRING(hRes);

	// Get a pointer to the IShellLink interface

	hRes = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&ipShellLink);
	
	COCREATE_OUTPUTDEBUGSTRING(hRes);
	if ( FAILED ( hRes ) )
	{
		CoUninitialize() ;
		return ( false ) ;
	}

	

    // Get a pointer to the IPersistFile interface
    CComQIPtr<IPersistFile> ipPersistFile ( ipShellLink ) ;

    // IMP: IPersistFile is using LPCOLESTR, so make sure that the string is Unicode
    // Open the shortcut file and initialize it from its contents
    hRes = ipPersistFile -> Load ( szShortcutFileName , STGM_READ ) ;
    if ( FAILED ( hRes ) )
    {
        CoUninitialize() ;
        return ( false ) ;
    }


    /*
    INFO: This was commented because if the file was moved or renamed a mesage window appears
          which needs a user response. This mesage windows hangs the special spyware scanning
          as the message box has come from service and is not viewable to the user.
    // Try to find the target of a shortcut, even if it has been moved or renamed
    hRes = ipShellLink -> Resolve ( NULL , SLR_UPDATE ) ;
    if ( FAILED ( hRes ) ) 
    {
        CoUninitialize() ;
        return ( false ) ;
    }
    */

	// Get the path to the shortcut target
	if(bGetArgs)
	{
		hRes = ipShellLink->GetArguments(szArguments, cbArguments);
	}
	else
	{
		hRes = ipShellLink->GetPath(szArguments, cbArguments, &wfd, SLGP_UNCPRIORITY );
		ipShellLink->GetWorkingDirectory(strworkdir,MAX_PATH);
		
		
		AddLogEntry(L"RAWPATH: %s", szArguments, 0, true, LOG_DEBUG);
	//	ResolveVariablesAndDoubleQuotes(szArguments, cbArguments);
		AddLogEntry(L"RESPATH: %s", szArguments, 0, true, LOG_DEBUG);

		_tcslwr_s(szArguments, cbArguments);
		if(_tcsstr(szArguments, _T("windows\\system32\\config\\systemprofile")))
		{
			CoUninitialize() ;
			return false;
		}

	}

	if ( FAILED ( hRes ) )
	{
		CoUninitialize() ;
		return ( false ) ;
	}

	CoUninitialize() ;
	return ( true ) ;
}



void CFakeLivePCGuard::EnumerateFolder(std::wstring& wsData)
{
	WIN32_FIND_DATA data;
	HANDLE h = FindFirstFile(wsData.c_str(),&data);
	
	if( h!=INVALID_HANDLE_VALUE ) 
	{
		do
		{
			char*   nPtr = new char [lstrlen( data.cFileName ) + 1];
			for( int i = 0; i < lstrlen( data.cFileName ); i++ )
				nPtr[i] = char( data.cFileName[i] );

			nPtr[lstrlen( data.cFileName )] = '\0';

			_wcsupr(data.cFileName);

			std::wstring wsFullPath(wsData);
			wsFullPath.erase(wsFullPath.size() -5, wsFullPath.size());
			
			wsFullPath.append(data.cFileName);
			CString csData(wsFullPath.c_str());
			csData.MakeLower();

			m_ListReported.sort();
			m_ListReported.unique();
			m_ListReported.push_back(wsFullPath);
			 
		} while(FindNextFile(h,&data));
	} 
	else 
	{
		;
	}
	
	FindClose(h);
}

void CFakeLivePCGuard::ParseWinlogonUserInit()
{
	CRegistry objReg;
	CString csUserInit;
	std::wstring strUserInit;
	objReg.Get(_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), _T("Userinit"),csUserInit, HKEY_LOCAL_MACHINE);
	strUserInit = (std::wstring) csUserInit.GetBuffer();

	size_t nPos = -1;
	nPos = strUserInit.find_last_of(L",");
	while(nPos != std::wstring::npos)
	{
		std::wstring strPath(strUserInit);
		strPath.erase(0,nPos+1);
		CString csData(strPath.c_str());
		csData.MakeLower();
		if(csData.Find(L"\\programdata\\") >= 0 || csData.Find(L"\\application data\\") >= 0 || csData.Find(L"\\appdata\\roaming\\") >= 0)
		{
			csData.Remove(L'"');
			if(IsRootFolder(csData))
			{
				strPath = csData;
				m_UserInitList.push_back(strPath);
			}
		}
		strUserInit.erase(nPos,strUserInit.size());
		nPos = strUserInit.find_last_of(L",");	
	}

	CString csData(strUserInit.c_str());
	csData.MakeLower();
	if(csData.Find(L"\\programdata\\") >= 0 || csData.Find(L"\\application data\\") >= 0 || csData.Find(L"\\appdata\\roaming\\") >= 0)
	{
		csData.Remove(L'"');
		if(IsRootFolder(csData))
		{
			strUserInit = csData;
			m_UserInitList.push_back(strUserInit);
		}
	}
}

void CFakeLivePCGuard::ParseWinlogonShell(HKEY hHive)
{
	CRegistry objReg;
	CString csUserShell;
	std::wstring strUserShell;
	CString csMainKey;

	if(hHive != HKEY_USERS)
	{
		objReg.Get(_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"), _T("Shell"),csUserShell, hHive);
	}
	else
	{
		CExecuteProcess objExeProc;
		CString csSid = objExeProc.GetCurrentUserSid();
		csMainKey = csSid + BACK_SLASH + HKEY_USERS_WINLOGON_SHELL; 
		objReg.Get(csMainKey, _T("Shell"),csUserShell, hHive);
	}
	
	strUserShell = (std::wstring) csUserShell.GetBuffer();

	size_t nPos = -1;
	nPos = strUserShell.find_last_of(L",");
	while(nPos != std::wstring::npos)
	{
		std::wstring strPath(strUserShell);
		strPath.erase(0,nPos+1);
		CString csData(strPath.c_str());
		csData.MakeLower();
		if(csData.Find(L"\\programdata\\") >= 0 || csData.Find(L"\\application data\\") >= 0 || csData.Find(L"\\appdata\\roaming\\") >= 0)
		{
			csData.Remove(L'"');
			if(IsRootFolder(csData))
			{
				strPath = csData;
				m_ShellInitList.push_back(strPath);
			}
		}
		strUserShell.erase(nPos,strUserShell.size());
		nPos = strUserShell.find_last_of(L",");	
	}
	CString csData(strUserShell.c_str());
	csData.MakeLower();
	if(csData.Find(L"\\programdata\\") >= 0 || csData.Find(L"\\application data\\") >= 0 || csData.Find(L"\\appdata\\roaming\\") >= 0)
	{
		csData.Remove(L'"');
		if(IsRootFolder(csData))
		{
			strUserShell = csData;
			m_ShellInitList.push_back(strUserShell);
		}
	}	
	
	if(hHive == HKEY_USERS)
	{
		if(m_ShellInitList.size() >0)
		{
			for(int i= 0; i< m_ShellInitList.size(); i++)
			{
				CString ShellEntry("Shell");
				SendScanStatusToUI(Special_RegVal, m_ulSpyName , hHive, csMainKey,
					ShellEntry, REG_SZ, (LPBYTE) m_ShellInitList[i].c_str(), m_ShellInitList[i].size()*2);
			}
		}
	}
}

void CFakeLivePCGuard::ParseWindowsLoad()
{
	CRegistry objReg;
	CString csUserLoad;
	objReg.Get(_T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), _T("load"),csUserLoad, HKEY_LOCAL_MACHINE);
}

void CFakeLivePCGuard::ShellServiceObjectDelayLoad()
{
	CRegistry objReg;
	CStringArray csArrValues, csArrData;
	CRegistry m_objRegLocal;
	m_objRegLocal.QueryDataValue(_T("Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad"), csArrValues, csArrData, HKEY_LOCAL_MACHINE);
}

void CFakeLivePCGuard::WriteSignatureToIni(CString csOriginalFilePath)
{
	ULONG64 ulSignature = 0;
	UINT iCount = 0;
	TCHAR szCount[20] = {0};
	TCHAR szSigPlusFilePath[MAX_PATH] = {0};
	
	csOriginalFilePath.Trim();
	
	if(m_pFileSig && SIG_STATUS_PE_SUCCESS == m_pFileSig->CreateSignature(csOriginalFilePath, ulSignature))
	{
		bool bAlreadyPresent = false;
		TCHAR szCount[50] = {0}, szSignature[100] = {0}, szExistingSig[100] = {0};
		int iCount = 0;

		GetPrivateProfileString(_T("Signature"), _T("Count"), _T("0"), szCount, _countof(szCount), m_csINIFileName);
		iCount = _tcstol(szCount, 0, 10);
		_stprintf_s(szSignature, _countof(szSignature), _T("%016I64X*NoFileName"), ulSignature);

		for(int i = 0; i < iCount; i++)
		{
			memset(szExistingSig, 0, sizeof(szExistingSig));
			_stprintf_s(szCount, _countof(szCount), _T("%i"), i);
			GetPrivateProfileString(_T("Signature"), szCount, _T(""), szExistingSig, _countof(szExistingSig), m_csINIFileName);		
	
			CString strExisting(szExistingSig);
			CString strNewSig(szSignature);

			if(strExisting.Find(szSignature) >= 0)
			{
				bAlreadyPresent = true;
				break;
			}
		}

		if(!bAlreadyPresent)
		{
			if(_tcslen(csOriginalFilePath) + 1 < _countof(szSigPlusFilePath))
			{
				iCount = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);
				iCount++;
				_stprintf_s(szCount, _countof(szCount), _T("%u"), iCount);
				WritePrivateProfileString(_T("Signature"), _T("Count"), szCount, m_csINIFileName);

				_stprintf_s(szSigPlusFilePath, _countof(szSigPlusFilePath), _T("%016I64X*%s"), ulSignature, L"NoFileName");
				WritePrivateProfileString(_T("Signature"), szCount, szSigPlusFilePath, m_csINIFileName);
			}
		}
	}
}

bool CFakeLivePCGuard::FindInfectionAtDepth(CString& csData, int iDepth)
{
	bool isNDepthFolder;
	int iLocalDepth;

	std::wstring wstrLocalData(csData.GetBuffer());
	return true;
}