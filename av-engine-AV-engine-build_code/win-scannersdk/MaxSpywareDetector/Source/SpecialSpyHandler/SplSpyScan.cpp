/*=====================================================================================
   FILE				: SplSpyScan.Cpp
   ABSTRACT			: This class contains commonly used functions among the spcecial spyware classes
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
					version: 2.5.0.31
					Resource : sandip
					Description: change in EnumAndReportCOMKeys to avoid crash					
					version: 2.5.0.31
					Resource : Shweta
					Description: Change in CheckReportKeyValueData for Send Messege to UI 
					version: 2.5.0.31
					Resource : Shweta
					Description: Moved function RandomVersion random version number.
								 Added CheckForUninstallKey for getting the random uninstall key
					version : 2.5.0.32
					Resource : Shweta
					Description: Change for th new version 2.5.1
					version : 2.5.0.32
					Resource : Sandip	
					Description: Remove the Code to append Quarantine value
					version : 2.5.0.35
					Resource : Sandip	
					Description: Add the code for ignore the crash at the time of quarantine.
								 Set default parameter to OptionTabAction export function
					version : 2.5.0.49
					Resource : Shweta M	
					Description: Added the code for ignore the more than one element.
					
					version		: 2.5.0.55
					Date		: 29 Sep 2008
					Resource	: Nitin Shekokar	
					Description	: Add function to Compare MD5 values ,File Path and File name with respect to
								  given registry value. 

				    version		: 2.5.0.57
					Date		: 22 Oct 2008
					Resource	: Shweta Mulay
					Description	: Added code for RegfixData 

					version		: 2.5.0.59
					Date		: 3 Nov 2008
					Resource	: Shweta Mulay
					Description	: Fix for Desktop Issue 

					version		: 2.5.0.62
					Date		: 22 Dec 2008
					Resource	: Shweta Mulay
					Description	: Changes in EnumkeysnSubkeys

					version		: 2.5.0.66
					Date		: 22 Dec 2008
					Resource	: Shweta Mulay
					Description	: Changes in EnumkeysnSubkeys for all types of hive

========================================================================================*/

#include "pch.h"
#include <io.h>
#include <fcntl.h>
#include <sys\stat.h>
#include "SplSpyScan.h"
#include "StringFunctions.h"
#include "RemoteService.h"
#include "SplSpyWrapper.h"
#include "ExecuteProcess.h"
#include "PathExpander.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CS2S CSplSpyScan::m_objAvailableUsers(false);
CRegistry CSplSpyScan::m_oRegistry;
CDBPathExpander CSplSpyScan::m_oDBPathExpander;

BOOL CALLBACK EnumWindowsProc ( HWND hwnd , LPARAM lParam );

// function pointers for ntdll.dll functions
LP_NtCreateKey		NtCreateKey = NULL ;
LP_NtDeleteKey		NtDeleteKey = NULL ;
LP_NtEnumerateKey	NtEnumerateKey = NULL ;
LP_NtQueryKey		NtQueryKey = NULL ;
LP_NtClose			NtClose = NULL ;

/*--------------------------------------------------------------------------------------
Function       : CSplSpyScan::CSplSpyScan
In Parameters  : CSplSpyWrapper *pSplSpyWrapper, ULONG ulSpyName 
Out Parameters : 
Description    : constructor of the class, creates wrapper and spyname objects
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CSplSpyScan:: CSplSpyScan( CSplSpyWrapper *pSplSpyWrapper, ULONG ulSpyName): 
						   m_pSplSpyWrapper( pSplSpyWrapper), m_ulSpyName(ulSpyName)
{
	TCHAR szHoldPath[MAX_PATH] = {0};

	GetWindowsDirectory(szHoldPath, _countof(szHoldPath));
	if(szHoldPath[0])
	{
		m_csWinDir = szHoldPath;
	}

	memset(szHoldPath, 0, sizeof(szHoldPath));
	GetSystemDirectory(szHoldPath, _countof(szHoldPath));
	if(szHoldPath[0])
	{
		m_csSysDir = szHoldPath;
	}

	m_bSplSpyFound = false;
	m_bStatusbar = false;

	//Darshan
	//25-June-2007
	m_objReg.EnumSubKeys(BLANKSTRING, m_arrAllUsers, HKEY_USERS);
	InitWhiteListDB() ;
	CheckToScanOtherLocations() ;
	CallToStatusBarFucn();
}

/*--------------------------------------------------------------------------------------
Function       : CSplSpyScan::~CSplSpyScan
In Parameters  : void
Out Parameters : 
Description    : destructor of the class
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CSplSpyScan::~CSplSpyScan(void)
{
	DeInitWhiteListDB() ;
}

/*--------------------------------------------------------------------------------------
Function       : CSplSpyScan::SendScanStatusToUI
In Parameters  : SD_Message_Info eTypeOfScanner, 
Out Parameters : void
Description    : forward the call to scanner wrapper to report the entry to UI
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSplSpyScan::SendScanStatusToUI(SD_Message_Info eTypeOfScanner)
{
    if ( m_pSplSpyWrapper )
		m_pSplSpyWrapper->SendScanStatusToUI ( eTypeOfScanner) ;
}

void CSplSpyScan :: SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR *strValue)
{
    if ( m_pSplSpyWrapper )
			m_pSplSpyWrapper->SendScanStatusToUI ( eTypeOfScanner, ulSpyName, strValue) ;
}

void CSplSpyScan :: SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData)
{
    if ( m_pSplSpyWrapper )	
        	m_pSplSpyWrapper->SendScanStatusToUI ( eTypeOfScanner, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data, lpbData,iSizeOfData) ;
	
}

void CSplSpyScan :: SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData)
{
	if(m_pSplSpyWrapper)
		m_pSplSpyWrapper->SendScanStatusToUI(eTypeOfScanner, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data, lpbData, iSizeOfData, psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData);
}

/*-------------------------------------------------------------------------------------
Function		: 
In Parameters	: CString
Out Parameters	: bool
Purpose			: Checks for spywware key and reports key, value and data 
Author			: Shweta
Description		: Enumerate Keys and values from HKLM/Software where value = esurvey and number of value = 1
Nupur: Function Renamed to CheckReportKeyValueData from CheckRandomKey
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckReportKeyValueData( ULONG ulSpywareName, CString csMainKey, HKEY hive )
{
	try
	{
		CStringArray csSubKey ;
		CString csHive  = m_objReg.RootKey2String( hive);

		m_objReg.EnumSubKeys ( csMainKey , csSubKey, hive ) ;
		int nSubKeys = (int)csSubKey.GetCount();

		for (int i = 0; i < nSubKeys; i++)
		{
			//CStringArray csArrSpywarerValue, csArrSpywareData;
			CString csSpywareSubKey = csMainKey + CString(BACK_SLASH) + csSubKey.GetAt(i);
			
			//Enumerate Values            
            vector<REG_VALUE_DATA> vecRegValues;
	        m_objReg.EnumValues(csSpywareSubKey, vecRegValues, HKEY_LOCAL_MACHINE);
			//if(m_objReg.QueryDataValue(csSpywareSubKey, csArrSpywarerValue, csArrSpywareData, HKEY_LOCAL_MACHINE, ptrDataTypes,iDataTypeSize))
			{
				if (vecRegValues.size() == 1 && _wcsicmp(vecRegValues[0].strValue, _T("eSurvey")) == 0) 
				{
                    SendScanStatusToUI(Special_RegKey, ulSpywareName, HKEY_LOCAL_MACHINE, csSpywareSubKey,0,0,0,0);
                    SendScanStatusToUI(Special_RegVal, ulSpywareName, HKEY_LOCAL_MACHINE, csSpywareSubKey, vecRegValues[0].strValue ,vecRegValues[0].Type_Of_Data ,vecRegValues[0].bData , vecRegValues[0].iSizeOfData);                    
					
				}
			}
		}
		return true  ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckReportKeyValueData, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CSplSpyScan::SearchStringsInFile
In Parameters  :  LPCTSTR szFileName, CArray<CStringA, CStringA> &csArrList, 
Out Parameters : bool 
Description    : 
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::SearchStringsInFile( LPCTSTR szFileName , CArray<CStringA,CStringA> &csArrList)
{
	int hFile = -1 ;
	int i = 1 , iStrFound = 0 ;
	bool bStringFound = false ;
	bool bAllEntriesFound = true ;
	char * pHold = NULL ;

	_tsopen_s ( &hFile , szFileName , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
	if ( hFile == -1 )
	{
		return ( false ) ;
	}

	for ( i = 0 ; i < csArrList.GetCount() && bAllEntriesFound ; i++ )
	{
		bStringFound = false ;
		if ( !SearchString ( hFile , csArrList [ i ] , &bStringFound ) )
		{
			_close ( hFile ) ;
			return(false) ;
		}

		bAllEntriesFound = bStringFound ? bAllEntriesFound : false ;
		if(IsStopScanningSignaled())
		{
			_close ( hFile ) ;
			return ( false ) ;
		}
	}

	_close ( hFile ) ;
	return ( bAllEntriesFound ) ;
}


/*-------------------------------------------------------------------------------------
	Function		: RemoveFolders
	In Parameters	: CString , CString , bool
	Out Parameters	: 
	Purpose			: Deletes and makes entries to UI for folder
	Author			: 
	Description		: Searches a given folder and removes all entries recursively
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::RemoveFolders(CString csFolderPath, ULONG ulSpyName, bool bDeleteEntries, bool bAddRestartDel)
{
	try
	{
		// Darshan
		// 25-June-2007
		if(IsStopScanningSignaled())
			return false;

		bool bRetValue = false;
		CFileFind findfile;
		CString csFilePath;
		BOOL bCheck = FALSE;

		bCheck = findfile.FindFile(csFolderPath + _T("\\*")); 	//To Check Whether The File Is Exist Or Not
		if(FALSE == bCheck)
		{
			return true;
		}

		while(bCheck)
		{
			if(IsStopScanningSignaled())
				break;

			bCheck = findfile.FindNextFile(); //To Find Next File In Same Directory
			if(findfile.IsDots())
				continue;

			csFilePath = findfile.GetFilePath();

			if(findfile.IsDirectory())
			{
				//To Remove The Files & Folders Recursively In that directory
				if(!RemoveFolders(csFilePath, ulSpyName, bDeleteEntries, bAddRestartDel))
				{
					bRetValue = false;
				}
			}
			else
			{
				if(csFilePath.Right(4).CompareNoCase(_T(".exe")) == 0)
				{
					if(m_objEnumProcess.IsProcessRunning(csFilePath, bDeleteEntries))
					{
						if(!bDeleteEntries)
						{
							SendScanStatusToUI(Special_Process, ulSpyName, csFilePath);
						}
					}
				}

				if(bDeleteEntries)
				{
					if(FALSE == DeleteFile(csFilePath))
					{
						AddInRestartDeleteList(RD_FILE_DELETE, ulSpyName, csFilePath);
					}
				}
				else
				{
					SendScanStatusToUI(Special_File, ulSpyName, csFilePath);
				}

				if(bAddRestartDel)
				{
					AddInRestartDeleteList(RD_FILE_DELETE, ulSpyName, csFilePath);
				}
			}
		}

		findfile.Close();

		//To delete an existing empty directory.
		if(bDeleteEntries)
		{
			if(!RemoveDirectory(csFolderPath))
			{
				AddInRestartDeleteList(RD_FOLDER, ulSpyName, csFolderPath);
			}
		}
		else
		{
			SendScanStatusToUI(Special_Folder, ulSpyName, csFolderPath);
		}

		if(bAddRestartDel)
		{
			AddInRestartDeleteList(RD_FOLDER, ulSpyName, csFolderPath);
		}

		return true;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::RemoveFolders, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveBHOWithKey
	In Parameters	: CString , bool , CString 
	Out Parameters	: 
	Purpose			: remove bho reg key and files
	Author			: 
	Description		: send all entries of a BHO to UI
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::RemoveBHOWithKey(CString sClasssID, bool bToDelete, ULONG ulSpywareName)
{
	try
	{
		if((sClasssID.Trim()).GetLength() == 0)
			return false;
	
		CString sFileName;
		CString csStringToDisPlay;
		CStringArray csArrLocations ;
		
		if(m_objReg.KeyExists( BHO_REGISTRY_PATH + CString(BACK_SLASH) + sClasssID, HKEY_LOCAL_MACHINE))
		{
			if(!bToDelete)
				SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , BHO_REGISTRY_PATH + CString(BACK_SLASH) + sClasssID, 0, 0, 0 ,0) ;

			if(m_objReg.KeyExists( CLSID_KEY + sClasssID + CString(BACK_SLASH) + INPROCSERVER32 , HKEY_LOCAL_MACHINE))
			{
				if(!bToDelete)					
                    SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , CLSID_KEY + sClasssID + CString(BACK_SLASH) + INPROCSERVER32, 0, 0, 0 ,0) ;

				m_objReg.Get( CLSID_KEY + sClasssID + CString(BACK_SLASH) + INPROCSERVER32 , BLANKSTRING , sFileName, HKEY_LOCAL_MACHINE);
				sFileName.Trim();
				if(sFileName.GetLength() != 0)
				{
					if(!bToDelete)
						SendScanStatusToUI(Special_File, ulSpywareName, sFileName);
				}
			}

			return true ;
		}
		else if(m_objReg.KeyExists( BHO_REGISTRY_PATH + CString(BACK_SLASH) + _T("b") + sClasssID, HKEY_LOCAL_MACHINE))
		{
			if(!bToDelete)				
                SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , BHO_REGISTRY_PATH + CString(BACK_SLASH) + _T("b") + sClasssID, 0, 0, 0 ,0) ;

			if(m_objReg.KeyExists( CLSID_KEY + sClasssID + CString(BACK_SLASH) + INPROCSERVER32 , HKEY_LOCAL_MACHINE))
			{
				if(!bToDelete)					
                    SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , CLSID_KEY + sClasssID + CString(BACK_SLASH) + INPROCSERVER32, 0, 0, 0 ,0) ;

				m_objReg.Get( CLSID_KEY + sClasssID+ CString(BACK_SLASH) + INPROCSERVER32 , BLANKSTRING , sFileName, HKEY_LOCAL_MACHINE);
				if( (sFileName.Trim()).GetLength() != 0)
				{
					if(!bToDelete)
						SendScanStatusToUI(Special_File, ulSpywareName, sFileName);
				}
			}
			return true ;
		}

		if ( m_bScanOtherLocations )
		{
			if(m_objReg.KeyExists( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_BHO_REGISTRY_PATH) + CString(BACK_SLASH) + sClasssID, HKEY_LOCAL_MACHINE))
			{
				if(!bToDelete)					
                    SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_BHO_REGISTRY_PATH) + CString(BACK_SLASH) + sClasssID, 0, 0, 0 ,0) ;

				if(m_objReg.KeyExists( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid\\")) + sClasssID + CString(BACK_SLASH) + CString(INPROCSERVER32) , HKEY_LOCAL_MACHINE))
				{
					if(!bToDelete)						
                        SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , (CString)WOW6432NODE_REG_PATH + _T("classes\\clsid\\") + sClasssID + CString(BACK_SLASH) + INPROCSERVER32, 0, 0, 0 ,0) ;

					m_objReg.Get( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid\\")) + sClasssID + CString(BACK_SLASH) + CString(INPROCSERVER32) , BLANKSTRING , sFileName, HKEY_LOCAL_MACHINE);
					sFileName.Trim();
					if(sFileName.GetLength() != 0)
					{
						if(!bToDelete)
							SendScanStatusToUI(Special_File, ulSpywareName, sFileName);
					}
				}

				return true ;
			}
			else if(m_objReg.KeyExists( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_BHO_REGISTRY_PATH) + CString(BACK_SLASH) + CString(_T("b")) + sClasssID, HKEY_LOCAL_MACHINE))
			{
				if(!bToDelete)					
                    SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , (CString)WOW6432NODE_REG_PATH + UNDERWOW_BHO_REGISTRY_PATH + CString(BACK_SLASH) + _T("b") + sClasssID, 0, 0, 0 ,0) ;

				if(m_objReg.KeyExists( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid\\")) + sClasssID + CString(BACK_SLASH) + CString(INPROCSERVER32) , HKEY_LOCAL_MACHINE))
				{
					if(!bToDelete)
                        SendScanStatusToUI(Special_RegKey ,  ulSpywareName , HKEY_LOCAL_MACHINE , (CString)WOW6432NODE_REG_PATH + _T("classes\\clsid\\") + sClasssID + CString(BACK_SLASH) + INPROCSERVER32, 0, 0, 0 ,0) ;						

					m_objReg.Get( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid\\")) + sClasssID + CString(BACK_SLASH) + CString(INPROCSERVER32) , BLANKSTRING , sFileName, HKEY_LOCAL_MACHINE);
					if( (sFileName.Trim()).GetLength() != 0)
					{
						if(!bToDelete)
							SendScanStatusToUI(Special_File, ulSpywareName, sFileName);
					}
				}
				return true ;
			}
		}

		return false ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::RemoveBHOWithKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetServiceFileName
	In Parameters	: SC_HANDLE 
	Out Parameters	: CString& , CString& 
	Purpose			: Gets service filenams and Folder
	Author			: Anand
	Description		: Gets service filenams and Folder
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetServiceFileName ( SC_HANDLE hService, CString& csServiceFileName,	CString& csServiceFolder)
{
	DWORD dwBytesNeeded	= 0 ;
	LPQUERY_SERVICE_CONFIG	lpqscBuf = NULL ;

	if ( FALSE == QueryServiceConfig ( hService , 0 , 0 , &dwBytesNeeded ) )
	{
		//TODO: GetLastError and AddLogEntry(...) to add here
		return ( false ) ;
	}

	lpqscBuf = (LPQUERY_SERVICE_CONFIG) malloc ( dwBytesNeeded ) ;
	if ( NULL != lpqscBuf )
	{
		// Get the configuration information
		if ( QueryServiceConfig ( hService , lpqscBuf , dwBytesNeeded , &dwBytesNeeded ) )
		{
			csServiceFileName = lpqscBuf -> lpBinaryPathName ;
			csServiceFolder = csServiceFileName ;
			csServiceFolder = csServiceFolder . Left ( csServiceFolder . ReverseFind ( _T('\\') ) ) ;
			csServiceFolder . Delete ( 0 , csServiceFolder . ReverseFind ( _T('\\') ) + 1 ) ;
			if ( !csServiceFolder . IsEmpty() )
			{
				free ( lpqscBuf ) ;
				return  ( true ) ;
			}
		}
		free ( lpqscBuf ) ;
	}
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckUnInstaller
	In Parameters	: const char *, const char * , bool 
	Out Parameters	: 
	Purpose			: check and run uninstaller
	Author			: 
	Description		: check and run uninstaller if present in given path, make entry in UI
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckUnInstaller(ULONG ulSpyName, LPCTSTR sFolderName, LPCTSTR sExeName, bool bRunSetup)
{
	if(IsStopScanningSignaled())
		return false;

	CStringArray csArrLocations ;

	csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
	if ( m_bScanOtherLocations )
		csArrLocations . Add ( m_csOtherPFDir ) ;
	
	for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
	{
		CString csUnInstallExe;
		csUnInstallExe.Format(_T("%s\\%s\\%s"), 
								static_cast<LPCTSTR>(csArrLocations[i]), 
								static_cast<LPCTSTR>(sFolderName), 
								static_cast<LPCTSTR>(sExeName));

		CFileFind oFileFind;
		if(oFileFind.FindFile(csUnInstallExe) == FALSE)
		{
			oFileFind.Close();
			//Add to continue for loop to scan into other locations
			if(m_bScanOtherLocations)
				continue;
			return false;
		}
		else
		{
			if(bRunSetup)
			{
				AddInRestartDeleteList(RD_FOLDER, ulSpyName, csArrLocations [ i ] + CString(BACK_SLASH) + CString(sFolderName));
				ShellExecute(0, _T("open"), csUnInstallExe, _T("/S"), 0, SW_HIDE);
				Sleep(5000);
				return true ;
			}
			else
			{
				SendScanStatusToUI(Special_Folder, ulSpyName, csArrLocations [ i ] + CString(BACK_SLASH) + CString(sFolderName));
				SendScanStatusToUI(Special_File,ulSpyName, csUnInstallExe);
			}
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndRunUnInstallerWithParam
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and Run WinFixer Uninstaller
	Author			: 
	Description		: This function makes entries to UI when the 'bToDelete' flag is true
					  and runs the uninstaler when the flag is false to remove the spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckAndRunUnInstallerWithParam ( CString csFullFolderName, CString csFileName , CString csParameters , 
												    bool bToDelete , ULONG ulSpywareName)
{
	try
	{
		CString csFullFileName = csFullFolderName + CString(BACK_SLASH) + csFileName;
		if( _taccess_s ( csFullFileName , 0 ) != 0)
			return false;

		if(bToDelete)
		{
			ShellExecute ( 0 , _T("open") , csFullFileName , csParameters , 0 , SW_HIDE ) ;
		}
		else
		{
			// only importance of this is to increment special spyware count
			SendScanStatusToUI( Special_File, ulSpywareName , csFullFileName  ) ;
		}
		return true;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckAndRunUnInstallerWithParam, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DelKeyLocalMachine
	In Parameters	: char *
	Out Parameters	: 
	Purpose			: delete a registry key
	Author			: Anand
	Description		: delete a registry key 
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::DelKeyLocalMachine ( LPCTSTR FullRegKey )
{
	WCHAR wDelKeyName [ MAX_PATH ] = L"\\Registry\\Machine\\" ;
	
	// Load the entry points required
	if ( !LocateNTDLLEntryPoints() )
		return ( false ) ;

	// make hardware registry path
	if ( wcslen ( wDelKeyName ) + _tcslen ( FullRegKey ) >= _countof ( wDelKeyName ) )
		return ( false ) ;

    _tcscat_s ( wDelKeyName , FullRegKey ) ;

	// Delete the key recursively
	if ( !DelKey ( wDelKeyName , (DWORD)wcslen ( wDelKeyName ) * sizeof ( WCHAR ) ) )
		return ( false ) ;

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: DelKey
	In Parameters	: WCHAR * , ULONG 
	Out Parameters	: 
	Purpose			: delete a key
	Author			: Anand
	Description		: delete a key using wide chars
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::DelKey ( WCHAR * wDelKeyName , ULONG NameLength )
{
	try
	{
		UNICODE_STRING KeyName = { 0 } , ValueName = { 0 } ;
		HANDLE SoftwareKeyHandle = NULL , SysKeyHandle = NULL , HiddenKeyHandle = NULL ;
		ULONG Status = NULL ;
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 } ;
		ULONG Disposition = 0 , ResultLength = 0 , TotalSubKeys = 0 , i = 0 ;
		KEY_BASIC_INFORMATION KeyInfo = { 0 } ;
		KEY_FULL_INFORMATION FullKeyInfo = { 0 } ;
		WCHAR wFullSubKeyName [ MAX_PATH ] = { 0 } ;

		if ( !wDelKeyName ) return ( false ) ;

		KeyName.Buffer = wDelKeyName ;
		KeyName.Length = (SHORT) NameLength ;

		InitializeObjectAttributes ( &ObjectAttributes , &KeyName , OBJ_CASE_INSENSITIVE, NULL, NULL ) ;
		
		// Open the key
		Status = NtCreateKey( &SoftwareKeyHandle, KEY_ALL_ACCESS, &ObjectAttributes, 0,
							NULL, REG_OPTION_NON_VOLATILE, &Disposition ) ;
		if( !NT_SUCCESS( Status ))
			return ( false ) ;

		if ( REG_CREATED_NEW_KEY == Disposition )
		{
			NtDeleteKey ( SoftwareKeyHandle ) ;
			return ( true ) ;
		}

		Status = NtQueryKey ( SoftwareKeyHandle, KeyFullInformation, &FullKeyInfo , 
							sizeof ( FullKeyInfo ), &ResultLength ) ;
		if( !NT_SUCCESS( Status ))
		{
			NtClose ( SoftwareKeyHandle ) ;
			return ( false ) ;
		}

		TotalSubKeys = FullKeyInfo.SubKeys ;
		for ( i = 0 ; i < TotalSubKeys ; i++ )
		{
			Status = NtEnumerateKey ( SoftwareKeyHandle , i , KeyBasicInformation , &KeyInfo ,
									sizeof ( KEY_BASIC_INFORMATION ) , &ResultLength ) ;

			if ( !NT_SUCCESS ( Status ) )
			{
				if ( Status == ERROR_NO_MORE_ITEMS )
					break ;
				else
				{
					NtClose ( SoftwareKeyHandle ) ;
					return ( false ) ;
				}
			}

			if ( wcscpy_s ( wFullSubKeyName , wDelKeyName ) )
			{
				NtClose ( SoftwareKeyHandle ) ;
				return ( false ) ;
			}

			if ( wcscat_s ( wFullSubKeyName , _T("\\") ) )
			{
				NtClose ( SoftwareKeyHandle ) ;
				return ( false ) ;
			}

			if ( wcscat_s ( wFullSubKeyName , KeyInfo.Name ) )
			{
				NtClose ( SoftwareKeyHandle ) ;
				return ( false ) ;
			}

			if ( !DelKey ( wFullSubKeyName , NameLength + KeyInfo.NameLength + 2 ) )
			{
				NtClose ( SoftwareKeyHandle ) ;
				return ( false ) ;
			}

			i-- ;
			TotalSubKeys-- ;
		}

		NtDeleteKey ( SoftwareKeyHandle ) ;
		return ( true ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::DelKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: LocateNTDLLEntryPoints
	In Parameters	: 
	Out Parameters	: 
	Purpose			: load ntdll.dll functions
	Author			: Anand
	Description		: load ntdll.dll functions
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::LocateNTDLLEntryPoints ( void )
{
	//TODO: This function has some scope for code optimization.

	HMODULE hMod = NULL;

	try
	{
		hMod = GetModuleHandle(_T("ntdll.dll")) ;
		
		if ( NULL == hMod )
		{
			return ( false ) ;
		}

		NtCreateKey = (LP_NtCreateKey) GetProcAddress ( hMod , "NtCreateKey" ) ;
		if( !NtCreateKey )
		{
			//FreeLibrary ( hMod );
			return ( false ) ;
		}

		NtDeleteKey = (LP_NtDeleteKey) GetProcAddress ( hMod , "NtDeleteKey" ) ;
		if( !NtDeleteKey )
		{
			//FreeLibrary ( hMod );
			return ( false ) ;
		}

		NtEnumerateKey = (LP_NtEnumerateKey) GetProcAddress ( hMod, "NtEnumerateKey" ) ;
		if( !NtEnumerateKey )
		{
			//FreeLibrary ( hMod ); 		
			return ( false ) ;
		}

		NtQueryKey = (LP_NtQueryKey) GetProcAddress ( hMod, "NtQueryKey" ) ;
		if( !NtQueryKey )
		{
			//FreeLibrary ( hMod );		
			return ( false ) ;
		}

		NtClose = (LP_NtClose) GetProcAddress ( hMod, "NtClose" ) ;
		if( !NtClose )
		{
			//FreeLibrary ( hMod );		
			return ( false ) ;
		}

		//FreeLibrary ( hMod );
		return ( true ) ;

	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::LocateNTDLLEntryPoints, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	/*if (hMod)
	{
		FreeLibrary ( hMod ) ;
	}*/

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndRemoveDriver
	In Parameters	: CString , CString , CString , bool 
	Out Parameters	: CStringArray &
	Purpose			: check and legacy or sevice entry in registry
	Author			: Sudeep
	Description		: This function checks for any legacy, services entry in ControlSet001..002..003
					  And in CurrentControleSet. deletes all entries and the driver file
					  This function is sample to Scan and Quarantine any identfied spyware Driver
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckAndRemoveDriver ( ULONG ulSpyware , CString csDriverName , CString csDriverFullPath , CStringArray &csArrInfectedKeys , bool bToDelete )
{
	try
	{
		if ( !bToDelete )
		{
			CStringArray csSystemSubKeys;
			m_objReg.EnumSubKeys(_T("SYSTEM"), csSystemSubKeys, HKEY_LOCAL_MACHINE);
            int nSubKeys = (int)csSystemSubKeys.GetCount();

            for ( int i = 0; i < nSubKeys; i ++ )  
			{
				int iPos = 0;
				(csSystemSubKeys.GetAt(i)).Find(_T("ControlSet0"), iPos); //Check for ControlSet001 , 002, 003...
				if(iPos != -1)
					FindAndAddDriverKey ( ulSpyware, csDriverName, _T("SYSTEM\\") + csSystemSubKeys.GetAt(i), csArrInfectedKeys, m_bSplSpyFound, bToDelete) ;
			}
						
			if ( _taccess_s( csDriverFullPath, 0 ) == 0 )
			{
				m_bSplSpyFound = true ;
				SendScanStatusToUI ( Special_File, ulSpyware , csDriverFullPath ) ;
			}
		}
		else
		{
			if ( EnablePrivilegesToHandleReg() )
			{
				for ( int i = 0 ; i < csArrInfectedKeys.GetCount(); i++ )
				{
					// delete all the values in this key, so that driver is not loaded next time
					if ( DeleteAllTheValues ( HKEY_LOCAL_MACHINE , csArrInfectedKeys.GetAt(i)))
					{
						CString csKeyToDelete = CString(_T("Generic^")) + CString(HKLM) + CString(BACK_SLASH) ;
						csKeyToDelete = csKeyToDelete + csArrInfectedKeys.GetAt(i)+ _T("Dummy");

						AddInRestartDeleteList(RD_KEY, m_ulSpyName, csKeyToDelete);
						RemoveRegistryKey ( csArrInfectedKeys . GetAt ( i ) , HKEY_LOCAL_MACHINE , ulSpyware ) ;
					}
				}
			}

			if ( _taccess_s ( csDriverFullPath, 0) == 0 )
				AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csDriverFullPath);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckAndRemoveDriver, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: FindAndAddDriverKey
	In Parameters	: CString , CString , CString
	Out Parameters	: CStringArray & , bool &
	Purpose			: look for all driver keys
	Author			: Sudeep
	Description		: This function Finds the driver keys from thr registry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindAndAddDriverKey( ULONG ulSpyware, CString csDriverName, CString csRegMainKey, CStringArray &csArrInfectedKeys, bool &bDriverKeyFound, bool isdelete)
{
	try
	{
		//SEARCH FOR LEGACY ENTRY for this DRIVER
		if( FindReportRegKey( csRegMainKey + _T("\\Enum\\Root\\LEGACY_") + csDriverName, ulSpyware, HKEY_LOCAL_MACHINE, isdelete, true ))
		{
			m_bSplSpyFound = true;
			csArrInfectedKeys.Add( csRegMainKey + _T("\\Enum\\Root\\LEGACY_") + csDriverName);
		}
		
		//SEARCH FOR MAIN SERVICES ENTRY for this DRIVER
		if( FindReportRegKey( csRegMainKey + _T("\\Services\\") + csDriverName, ulSpyware, HKEY_LOCAL_MACHINE, isdelete, true ))
		{
			m_bSplSpyFound = true;
			csArrInfectedKeys.Add( csRegMainKey + _T("\\Services\\") + csDriverName);
		}
		
   		//SEARCH FOR SAFEBOOT Minimal KEYS
		if( FindReportRegKey( csRegMainKey + _T("\\Control\\SafeBoot\\Minimal\\") + csDriverName + _T(".sys"), ulSpyware, HKEY_LOCAL_MACHINE, isdelete, true ))
		{
			m_bSplSpyFound = true;
			csArrInfectedKeys.Add( csRegMainKey + _T("\\Control\\SafeBoot\\Minimal\\") + csDriverName + _T(".sys"));
		}
		
		//SEARCH FOR SAFEBOOT Network KEYS
		if( FindReportRegKey( csRegMainKey + _T("\\Control\\SafeBoot\\Network\\") + csDriverName + _T(".sys") , ulSpyware, HKEY_LOCAL_MACHINE, isdelete, true ))
		{
			m_bSplSpyFound = true;
			csArrInfectedKeys.Add( csRegMainKey + _T("\\Control\\SafeBoot\\Network\\") + csDriverName + _T(".sys") );
		}

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::FindAndAddDriverKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: EnableTokenPrivilege
	In Parameters	: HANDLE , LPCTSTR , BOOL 
	Out Parameters	: 
	Purpose			: Enable or Disable the given privilege
	Author			: 
	Description		: Enable or Disable the given privilege
--------------------------------------------------------------------------------------*/
BOOL CSplSpyScan::EnableTokenPrivilege ( HANDLE hToken , LPCTSTR lpszPrivilege , BOOL bEnablePrivilege ) 
{ 
	try
	{
		TOKEN_PRIVILEGES        tp ;
		TOKEN_PRIVILEGES        tpPrevious ;
		LUID                    luid ;
		DWORD                   cb ;

		if ( !LookupPrivilegeValue ( NULL , lpszPrivilege , &luid ) )
		{ 
			return ( FALSE ) ;
		}
		
		// Get current privilege settings 
		cb = sizeof ( TOKEN_PRIVILEGES ) ;
		tp.PrivilegeCount           = 1 ; 
		tp.Privileges[0].Luid       = luid ; 
		tp.Privileges[0].Attributes = 0 ; 

		if ( !AdjustTokenPrivileges ( hToken , FALSE , &tp , sizeof(TOKEN_PRIVILEGES),
									&tpPrevious, &cb ) )
		{ 
			return ( FALSE ) ;
		} 

		// Set privilege based on current settings. 
 		tpPrevious . PrivilegeCount = 1 ; 
		tpPrevious . Privileges [ 0 ] . Luid = luid ;

		if ( bEnablePrivilege )
			tpPrevious . Privileges [ 0 ] . Attributes |= SE_PRIVILEGE_ENABLED ;
		else 
			tpPrevious . Privileges [ 0 ] . Attributes = 0 ;

		if ( !AdjustTokenPrivileges ( hToken , FALSE , &tpPrevious , sizeof(TOKEN_PRIVILEGES) , 
									NULL , NULL ) )
		{ 
			return ( FALSE ) ;
		}

		return ( TRUE ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::EnableTokenPrivilege, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: EnablePrivilegesToHandleReg
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Acquire all the privileges to handle registry
	Author			: Anand
	Description		: Acquire all the privileges to handle registry
--------------------------------------------------------------------------------------*/
BOOL CSplSpyScan::EnablePrivilegesToHandleReg(void)
{
	try
	{
		HANDLE hToken;

		if ( ! OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			return ( FALSE ) ;
		}

		if ( !EnableTokenPrivilege ( hToken , SE_BACKUP_NAME , TRUE ) )
		{
			CloseHandle( hToken );
			return ( FALSE ) ;
		}

		if ( !EnableTokenPrivilege ( hToken , SE_RESTORE_NAME , TRUE ) )
		{
			CloseHandle( hToken );
			return ( FALSE ) ;
		}

		CloseHandle ( hToken ) ;
		return ( TRUE ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::EnablePrivilegesToHandleReg, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DeleteAllTheValues
	In Parameters	: HKEY , CString
	Out Parameters	: 
	Purpose			: deletes all values under key
	Author			: Anand
	Description		: deletes all the values under a key by regrestore method
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: DeleteAllTheValues ( HKEY hParent , CString csRegKey )
{
	try
	{
		HKEY hKey = 0 ;
		LONG RetValue = 0 ;
		CString csKeyName ;
		CString csDummyFile = _T("dummy.hiv") ;

		if ( csRegKey.IsEmpty() )
			return ( false ) ;

		RegOpenKey ( hParent , csRegKey , &hKey ) ;
		if ( NULL == hKey )
			return ( false ) ;

		RegCloseKey ( hKey ) ;

		csKeyName = csRegKey + _T("Dummy") ;
		RetValue = RegCreateKeyEx ( hParent , csKeyName , 0 , 0 , REG_OPTION_NON_VOLATILE ,
									KEY_ALL_ACCESS , NULL , &hKey , 0 ) ;
		if ( RetValue != ERROR_SUCCESS )
			return ( false ) ;

		// caution... :- if the file is already present, delete it
		_tunlink ( csDummyFile ) ;//No need to check return value

		// save the dummy key to restore later
		RetValue = RegSaveKey ( hKey , csDummyFile , 0 ) ;
		if ( ERROR_SUCCESS != RetValue )
		{
			RegCloseKey ( hKey ) ;
			RegDeleteKey ( hParent , csKeyName ) ;
			_tunlink ( csDummyFile ) ;//No need to check return value
			return ( false ) ;
		}

		RegCloseKey ( hKey ) ;
		hKey = 0 ;
		DWORD dwDisp ;
		RetValue = RegCreateKeyEx ( hParent , csRegKey , 0 , 0 ,
									REG_OPTION_BACKUP_RESTORE ,
									ACCESS_SYSTEM_SECURITY | KEY_ALL_ACCESS ,
									NULL , &hKey , &dwDisp ) ;
		if ( ERROR_SUCCESS != RetValue )
		{
			RegDeleteKey ( hParent , csKeyName ) ;
			_tunlink ( csDummyFile ) ;//No need to check return value
			return ( false ) ;
		}

		// restore the hiv file on the main key
		RetValue = RegRestoreKey ( hKey , csDummyFile , REG_OPTION_BACKUP_RESTORE ) ;
		if ( ERROR_SUCCESS != RetValue )
		{
			RegCloseKey ( hKey ) ;
			RegDeleteKey ( hParent , csKeyName ) ;
			_tunlink ( csDummyFile ) ;//No need to check return value
			return ( false ) ;
		}

		RegDeleteKey ( hParent , csKeyName ) ;
		RegCloseKey ( hKey ) ;
		_tunlink ( csDummyFile ) ;//No need to check return value
		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::DeleteAllTheValues, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveRegistryKey
	In Parameters	: CString : Parent Key
					  HKEY : Hive
					  CString : Spyware Name
					  void * : Scanner object pointer
	Out Parameters	: void
	Purpose			: enumerate subkeys under parent key
					: 
	Author			: Dipali Pawar
	Note			: This function will be changed later.
--------------------------------------------------------------------------------------*/
void CSplSpyScan::RemoveRegistryKey(CString csMainKey, HKEY hMainHive, ULONG ulSpyName)
{
	try
	{
		if(IsStopScanningSignaled()) 
			return;

		TCHAR     achKey[1096]=_T(""); 
		TCHAR     achClass[MAX_PATH] = _T("");	// buffer for class name 
		DWORD    cchClassName = MAX_PATH;	// length of class string 
		DWORD    cSubKeys;					// number of subkeys 
		DWORD    cbMaxSubKey = 1096;		// longest subkey size 
		DWORD    cchMaxClass;				// longest class string 
		DWORD    cValues;					// number of values for key 
		DWORD    cchMaxValue;				// longest value name 
		DWORD    cbMaxValueData;			// longest value data 
		DWORD    cbSecurityDescriptor;		// size of security descriptor 
		FILETIME ftLastWriteTime;			// last write time 
		
		DWORD i; 
		DWORD retCode; 
		
		DWORD cchValue = MAX_PATH; 
		
		HKEY hKey ;
		DWORD dwType =REG_SZ;

		// Key Found!
		if(IsStopScanningSignaled()) 
			return;
		//Verson 15.6
		//Resource: Dipali
		//Set not quarantine flag ,Because this is child entry
		
		EnumerateValuesAndData(csMainKey, hMainHive, ulSpyName, false);
		
		if(IsStopScanningSignaled()) 
			return;
		long lVal = RegOpenKeyEx(hMainHive,csMainKey,0,KEY_READ |KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE,&hKey);
		if(hKey)
		{
			// Get the class name and the value count. 
			RegQueryInfoKey(hKey,        // key handle 
				achClass,                // buffer for class name 
				&cchClassName,           // length of class string 
				NULL,                    // reserved 
				&cSubKeys,               // number of subkeys 
				&cbMaxSubKey,            // longest subkey size 
				&cchMaxClass,            // longest class string 
				&cValues,                // number of values for this key 
				&cchMaxValue,            // longest value name 
				&cbMaxValueData,         // longest value data 
				&cbSecurityDescriptor,   // security descriptor 
				&ftLastWriteTime);       // last write time 
			
			
			DWORD    dwSubKeySize= 1096;              // longest subkey size 
			 
			for (i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; i++) 
			{ 
				if(IsStopScanningSignaled()) 
					break;

				retCode = RegEnumKeyEx(	hKey, i, achKey, &dwSubKeySize, NULL, NULL, 
										NULL, &ftLastWriteTime); 
				if (retCode == (DWORD)ERROR_SUCCESS) 
				{
					dwSubKeySize = 1096;
				}
				if(retCode == (DWORD)ERROR_MORE_DATA)
				{
					retCode = ERROR_SUCCESS ;
					dwSubKeySize = 1096;
				}
				else if(retCode == (DWORD)ERROR_NO_MORE_ITEMS)
				{
					break;
				}

				CString csKeys ;
				csKeys.Empty();
				csKeys = csMainKey + _T("\\") + achKey;
				if(IsStopScanningSignaled()) 
					break;
				RemoveRegistryKey(csKeys, hMainHive, ulSpyName);
			}
			::RegCloseKey(hKey);
		}
		return; 
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::RemoveRegistryKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}
/*-------------------------------------------------------------------------------------
	Function		: EnumerateValuesAndData
	In Parameters	: CString : Parent Key
					  HKEY : Hive
					  CString : Spyware Name
					  void * : Scanner object pointer
	Out Parameters	: void
	Purpose			: enumerate value and data under parent key
					: 
	Author			: Dipali Pawar
	Note			: This function will be changed later.
--------------------------------------------------------------------------------------*/
void CSplSpyScan::EnumerateValuesAndData(CString csParentKey, HKEY hHiveKey, ULONG ulSpyName, bool bCheckForFile)
{
	try
	{
		if(IsStopScanningSignaled()) 
			return;

		HKEY hKey;
		DWORD lpcbValueName;
		DWORD lpcData;

		long lVal = RegOpenKeyEx(hHiveKey,csParentKey,0,KEY_READ |KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE,&hKey);

		if(lVal != ERROR_SUCCESS)
			return;

		RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,NULL,&lpcbValueName,&lpcData,NULL,NULL);
		lpcbValueName = lpcbValueName * (sizeof(TCHAR) + sizeof(TCHAR));
		lpcData = lpcData * (sizeof(TCHAR) + sizeof(TCHAR));

		TCHAR *lpValueName = new TCHAR[lpcbValueName];       ////char lpValueName[6*MAX_PATH];
		DWORD lpType;										   ////DWORD lpcbValueName = 6*MAX_PATH + 1;
		
		BYTE *lpData = new BYTE[lpcData];				   //BYTE lpData[6*MAX_PATH];
		int i = 0;											   //DWORD lpcData = 6*MAX_PATH + 1;

		while(TRUE)
		{
			if(IsStopScanningSignaled()) 
				 break;

			LONG lReturn = RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,NULL,&lpcbValueName,&lpcData,
				NULL,NULL);
			lpcbValueName = lpcbValueName * (sizeof(TCHAR) + sizeof(TCHAR));
			lpcData = lpcData * (sizeof(TCHAR) + sizeof(TCHAR));

			if(lReturn != ERROR_SUCCESS)
				return;

			if(lpcData <= 1024)//Solved bufferoverrun  problem
			{
				lReturn = RegEnumValue(hKey,i,lpValueName,&lpcbValueName,NULL,&lpType,lpData,&lpcData);
			}
			else
			{
				ZeroMemory(lpData,lpcData);
				lReturn = RegEnumValue(hKey,i,lpValueName,&lpcbValueName,NULL,NULL,NULL,NULL);
			}
			
			if(lReturn == ERROR_NO_MORE_ITEMS || lReturn == ERROR_MORE_DATA  )
			{
				delete [] lpValueName;
				delete [] lpData;
				RegCloseKey(hKey);
				return;
			}

			if(lReturn != ERROR_SUCCESS)
			{
				delete [] lpValueName;
				delete [] lpData;
				RegCloseKey(hKey);
				return;
			}

			DWORD dwType; 
			DWORD cchData = MAX_VALUE_NAME;
			lReturn = RegQueryValueEx(hKey, lpValueName, NULL, &dwType, NULL, &cchData);
			if(lReturn == ERROR_NO_MORE_ITEMS)
			{
				break;
			} 
			if(lReturn != ERROR_SUCCESS)
			{
				i++;
				continue;
			}

			CString csData;
			if(dwType == REG_DWORD)
				csData.Format(_T("%d"),*lpData);
			else if(dwType == REG_BINARY)
				csData = _T("");
			else
				csData = lpData;

			if(lpcData > 1024)
				csData = _T("");

			try
			{
				if(_tcscmp(lpValueName,_T("")) != 0)
				{
					if(IsStopScanningSignaled()) 
						break;
				}	
				else
				{
					//Version 15.4:
					//Resource: Dipali
					if(IsStopScanningSignaled()) 
						break;
				}
			}
			catch(...)
			{
			}
			i++;
		}
		delete [] lpValueName;
		delete [] lpData;
		if(hKey)
			RegCloseKey(hKey);
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::EnumerateValuesAndData, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndRemoveSSODLEntries
	In Parameters	: CString , bool
	Out Parameters	: CStringArray & , CStringArray &
	Purpose			: check and fix ssodl winfixer entries
	Author			: 
	Description		: checks and removes winfixer ssodl registry and file ( dll ) entries 
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckAndRemoveSSODLEntries ( ULONG ulSpywareName ,CStringArray & csArrSSODLRegEntries ,
												 CStringArray & csArrSSODLFileEntries , bool bToDelete )
{
	bool bInfectionFound = false ;

	try
	{
		if(IsStopScanningSignaled())
			return false;

        if ( !bToDelete )
		{
			//CStringArray csArrVal , csArrData ;
			CFileVersionInfo objFileVersionInfo;
			CStringArray csArrLocations ;

			csArrLocations . Add ( SSODL_PATH ) ;
			if ( m_bScanOtherLocations )
				csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_SSODL_PATH) ) ;

			for ( int j = 0 ; j < csArrLocations . GetCount() ; j++ )
			{
				// get all the values in ssodl key
                vector<REG_VALUE_DATA> vecRegValues;
	            m_objReg.EnumValues(csArrLocations [ j ], vecRegValues, HKEY_LOCAL_MACHINE);
				//if ( m_objReg . QueryDataValue ( csArrLocations [ j ] , csArrVal , csArrData , HKEY_LOCAL_MACHINE,ptrDataTypes, iDataTypeSize) )
				{
					// loop for each key found in ssodl key
                    int iCount = (int)vecRegValues.size();
					for ( int i = 0 ; i < iCount ; i++ )
					{
						CStringArray csArrSTSLocations ;

						csArrSTSLocations . Add ( STS_PATH ) ;
						if ( m_bScanOtherLocations )
							csArrSTSLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_STS_PATH) ) ;

						for ( int k = 0 ; k < csArrSTSLocations . GetCount() ; k++ )
						{
							// check if there is a same value in STS key as the data in ssodl value
							if ( m_objReg . ValueExists ( csArrSTSLocations [ k ] , CString(vecRegValues[i].bData) , HKEY_LOCAL_MACHINE ) )
							{
								CString csFullKeyName ;
								CString csData ;
								CStringArray csArrCLSIDLocations ;

								csArrCLSIDLocations . Add ( CLSID_KEY ) ;
								if ( m_bScanOtherLocations )
									csArrCLSIDLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid")) ) ;

								for ( int l = 0 ; l < csArrCLSIDLocations . GetCount() ; l++ )
								{
									// make full calss id key name by attaching same class id found in ssodl and sts
									csFullKeyName = csArrCLSIDLocations [ l ] + CString(vecRegValues[i].bData) + CString(BACK_SLASH) + INPROCSERVER32 ;

									// get the dll file name from the Default value in class id in CLSID
									if ( m_objReg . Get ( csFullKeyName , BLANKSTRING , csData , HKEY_LOCAL_MACHINE ) )
									{
										TCHAR szDllFileName [ MAX_PATH ] = { 0 } ;

										_tcscpy_s ( szDllFileName , csData ) ;

										// check if the dll exists
										if ( IsFilePresentInSystem ( szDllFileName , _countof ( szDllFileName ) ) )
										{
											// check against white list
											if ( !LookUpWhiteList ( szDllFileName , KEY_ID_SSODL ) )
											{
												// search for the key words
												if ( objFileVersionInfo . DoTheVersionJob ( szDllFileName , false ) )
												{          
                                                    EnumAndReportCOMKeys ( ulSpywareName , csFullKeyName , HKEY_LOCAL_MACHINE ) ;													
													SendScanStatusToUI ( Special_RegVal , ulSpywareName , HKEY_LOCAL_MACHINE , csArrLocations [ j ] , vecRegValues[i].strValue , vecRegValues[i].Type_Of_Data ,vecRegValues[i].bData ,vecRegValues[i].iSizeOfData ) ;
                                                    SendScanStatusToUI ( Special_RegVal , ulSpywareName , HKEY_LOCAL_MACHINE , csArrSTSLocations [ k ] , 0 , vecRegValues[i].Type_Of_Data ,vecRegValues[i].bData ,vecRegValues[i].iSizeOfData ) ;													
													SendScanStatusToUI ( Special_File, ulSpywareName , csData ) ;
													break ;
												}
											}
										}

										memset ( szDllFileName , 0 , sizeof ( szDllFileName ) ) ;
									}
								}
							}
						}
					}
				}                
			}
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckAndRemoveSSODLEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	bInfectionFound = bToDelete ? false : bInfectionFound ;
	return ( bInfectionFound ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: InitWhiteListDB
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: initializes white list database
	Author			: Anand
	Description		: loads a list of hardcode files names in CMap object
	Version			: 18.7.0.001
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: InitWhiteListDB ( void )
{
	//Resource: Anand
	//Version: 18.8.0.001
	//changed all entries to lower case

	//Resource: Anand
	//Version: 19.0.0.29
	//added App path to avoid any being scanned from SD folder

	//Resource: Anand
	//Version: 2.5.0.23
	//added this to check for exception files

	// array of white list in appinit key
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\aakah.dll") ,			_T("%sysdir%\\aakah.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\akdllnt.dll") , 		_T("%sysdir%\\akdllnt.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\rousrnt.dll") , 		_T("%sysdir%\\rousrnt.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\ssohook.dll") ,			_T("%sysdir%\\ssohook.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\katrack.dll") ,			_T("%sysdir%\\katrack.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\apitrap.dll") ,			_T("%sysdir%\\apitrap.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\umxsbxexw.dll") ,		_T("%sysdir%\\umxsbxexw.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\sockspy.dll") ,			_T("%sysdir%\\sockspy.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\scorillont.dll") ,		_T("%sysdir%\\scorillont.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\wbsys.dll") ,			_T("%sysdir%\\wbsys.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\nvdesk32.dll") ,		_T("%sysdir%\\nvdesk32.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\hplun.dll") ,			_T("%sysdir%\\hplun.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\mfaphook.dll") ,		_T("%sysdir%\\mfaphook.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\pavwait.dll") ,			_T("%sysdir%\\pavwait.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\ocmapihk.dll") ,		_T("%sysdir%\\ocmapihk.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\msgplusloader.dll") ,	_T("%sysdir%\\msgplusloader.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\iconcodecservice.dll") ,_T("%sysdir%\\iconcodecservice.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\wl_hook.dll") ,			_T("%sysdir%\\wl_hook.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%pfdir%\\google\\google~1\\goec62~1.dll") , _T("%pfdir%\\google\\google~1\\goec62~1.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\adialhk.dll") ,			_T("%sysdir%\\adialhk.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\wmfhotfix.dll") ,		_T("%sysdir%\\wmfhotfix.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\interceptor.dll") ,		_T("%sysdir%\\interceptor.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\qaphooks.dll") ,		_T("%sysdir%\\qaphooks.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\rmprocesslink.dll") ,	_T("%sysdir%\\rmprocesslink.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\msgrmate.dll") ,		_T("%sysdir%\\msgrmate.dll") ) ;
	m_objAppInitWhiteList . SetAt ( _T("%sysdir%\\wxvault.dll") ,			_T("%sysdir%\\wxvault.dll") ) ;
	

	// array of white list in ssodl%sysdir%\\ key
	m_objSSODLWhiteList . SetAt ( _T("%sysdir%\\auhook.dll") , _T("%sysdir%\\auhook.dll") ) ;
	m_objSSODLWhiteList . SetAt ( _T("%sysdir%\\iprepair.dll") , _T("%sysdir%\\iprepair.dll") ) ;
	m_objSSODLWhiteList . SetAt ( _T("%sysdir%\\stobject.dll") , _T("%sysdir%\\stobject.dll") ) ;
	m_objSSODLWhiteList . SetAt ( _T("%sysdir%\\webcheck.dll") , _T("%sysdir%\\webcheck.dll") ) ;
	m_objSSODLWhiteList . SetAt ( _T("%sysdir%\\wpdshserviceobj.dll") , _T("%sysdir%\\wpdshserviceobj.dll") ) ;
	

	// array of white list in winlogon\notify key
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\avldr.dll") ,			_T("%sysdir%\\avldr.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\caveosvr.dll") ,		_T("%sysdir%\\caveosvr.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\ckpnotify.dll") ,		_T("%sysdir%\\ckpnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\command antivirus download.dll") , _T("%sysdir%\\command antivirus download.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\catsrvut.dll") ,		_T("%sysdir%\\catsrvut.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\cwplc001.dll") , 		_T("%sysdir%\\cwplc001.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\dimsntfy.dll") , 		_T("%sysdir%\\dimsntfy.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\dpwlevhd.dll") , 		_T("%sysdir%\\dpwlevhd.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\fguard32.dll") , 		_T("%sysdir%\\fguard32.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\g2winlogon.dll") ,		_T("%sysdir%\\g2winlogon.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\ifxwlxen.dll") , 		_T("%sysdir%\\ifxwlxen.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\igfxsrvc.dll") , 		_T("%sysdir%\\igfxsrvc.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\igfxsrvc.dll") , 		_T("%sysdir%\\igfxsrvc.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\lgnotify.dll") , 		_T("%sysdir%\\lgnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\klogon.dll") ,			_T("%sysdir%\\klogon.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\lmiinit.dll") ,		_T("%sysdir%\\lmiinit.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\loginkey.dll") ,		_T("%sysdir%\\loginkey.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\mcpstub.dll") ,		_T("%sysdir%\\mcpstub.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\ctxnotif.dll") ,		_T("%sysdir%\\ctxnotif.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\navlogon.dll") ,		_T("%sysdir%\\navlogon.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\xtnotify.dll") ,		_T("%sysdir%\\xtnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\nwprovau.dll") ,		_T("%sysdir%\\nwprovau.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\opxpgina.dll") ,		_T("%sysdir%\\opxpgina.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\pcanotify.dll") ,		_T("%sysdir%\\pcanotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\umxwnp.dll") ,			_T("%sysdir%\\umxwnp.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\ppeclt.dll") ,			_T("%sysdir%\\ppeclt.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\prismapi.dll") ,		_T("%sysdir%\\prismapi.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\prismgna.dll") ,		_T("%sysdir%\\prismgna.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\psfus.dll") ,			_T("%sysdir%\\psfus.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\psqlpwd.dll") ,		_T("%sysdir%\\psqlpwd.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\fusstub.dll") ,		_T("%sysdir%\\fusstub.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\qcongina.dll") ,		_T("%sysdir%\\qcongina.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\rainit.dll") ,			_T("%sysdir%\\rainit.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\regcompact.dll") ,		_T("%sysdir%\\regcompact.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\sabwinlo.dll") , 		_T("%sysdir%\\sabwinlo.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\saswinlo.dll") , 		_T("%sysdir%\\saswinlo.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\sdnotify.dll") , 		_T("%sysdir%\\sdnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\lgnotify.dll") , 		_T("%sysdir%\\lgnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\is3wlhandler.dll") ,	_T("%sysdir%\\is3wlhandler.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\t3notify.dll") ,		_T("%sysdir%\\t3notify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\tabbtnwl.dll") ,		_T("%sysdir%\\tabbtnwl.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\hook32.dll") ,			_T("%sysdir%\\hook32.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\notifyf2.dll") , 		_T("%sysdir%\\notifyf2.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\tpgwlnot.dll") , 		_T("%sysdir%\\tpgwlnot.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\tphklock.dll") , 		_T("%sysdir%\\tphklock.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\veswinlogon.dll") ,	_T("%sysdir%\\veswinlogon.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\fastload.dll") ,		_T("%sysdir%\\fastload.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wbsrv.dll") ,			_T("%sysdir%\\wbsrv.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wgalogon.dll") ,		_T("%sysdir%\\wgalogon.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wintask.dll") ,		_T("%sysdir%\\wintask.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wlogon.dll") ,			_T("%sysdir%\\wlogon.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wrlogonntf.dll") ,		_T("%sysdir%\\wrlogonntf.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\winlognotif.dll") ,	_T("%sysdir%\\winlognotif.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\zsnotify.dll") ,		_T("%sysdir%\\zsnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\ati2evxx.dll") ,		_T("%sysdir%\\ati2evxx.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\crypt32.dll") ,		_T("%sysdir%\\crypt32.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\cryptnet.dll") ,		_T("%sysdir%\\cryptnet.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\cscdll.dll") ,			_T("%sysdir%\\cscdll.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\sclgntfy.dll") ,		_T("%sysdir%\\sclgntfy.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\ippspw.dll") ,			_T("%sysdir%\\ippspw.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\pcip\\ippspw.dll") ,	_T("%sysdir%\\pcip\\ippspw.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wlnotify.dll") ,		_T("%sysdir%\\wlnotify.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%sysdir%\\wzcdlg.dll") ,			_T("%sysdir%\\wzcdlg.dll") ) ;
	m_objNotifyWhiteList . SetAt ( _T("%pfdir%\\softex\\omnipass\\opxpgina.dll") , _T("%pfdir%\\softex\\omnipass\\opxpgina.dll") ) ;
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: DeInitWhiteListDB
	In Parameters	: 
	Out Parameters	: 
	Purpose			: deinitializes white list database
	Author			: Anand
	Description		: frees memory used by CMap object
	Version			: 18.7.0.001
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: DeInitWhiteListDB ( void )
{
	m_objAppInitWhiteList . RemoveAll() ;
	m_objSSODLWhiteList . RemoveAll() ;
	m_objNotifyWhiteList . RemoveAll() ;
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsFilePresentInSystem
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check if the file is present
	Author			: Anand
	Description		: check if the file has full path or is in system path
	Version			: 18.3
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::IsFilePresentInSystem ( TCHAR * szFile , DWORD cbszFile )
{
	try
	{
		// check if the value is blank
		if ( !szFile || !(*szFile) )
			return ( false ) ;

		// returns true if full filename is present
		if ( !_taccess_s ( szFile , 0 ) )
			return ( true ) ;

		int i = 0 ;
		CStringArray csArrSysDirLocations ;

		csArrSysDirLocations . Add ( CSystemInfo::m_strSysDir ) ;
		if ( m_bScanOtherLocations ) csArrSysDirLocations . Add ( m_csOtherSysDir ) ;

		for ( i = 0 ; i < csArrSysDirLocations . GetCount() ; i++ )
		{
			// check file in system path
			if ( !_taccess_s ( ( csArrSysDirLocations [ i ] + CString(BACK_SLASH) + szFile ) , 0 ) )
			{
				CString csHold = szFile ;

				if ( _tcslen ( csArrSysDirLocations [ i ] ) + _tcslen ( szFile ) + 1 >= cbszFile )
					return ( false ) ;

				memset ( szFile , 0 , cbszFile * sizeof ( TCHAR ) ) ;
				_tcscpy_s ( szFile , cbszFile , csArrSysDirLocations [ i ] ) ;
				_tcscat_s ( szFile , cbszFile , CString(BACK_SLASH) ) ;
				_tcscat_s ( szFile , cbszFile , csHold ) ;
				return ( true ) ;
			}
		}

		CStringArray csArrPFDirLocations ;
		csArrPFDirLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations ) csArrSysDirLocations . Add ( m_csOtherPFDir ) ;

		for ( i = 0 ; i < csArrPFDirLocations . GetCount() ; i++ )
		{
			// check file in program files path
			if ( !_taccess_s ( ( csArrPFDirLocations [ i ] + CString(BACK_SLASH) + szFile ) , 0 ) )
			{
				CString csHold = szFile ;

				if ( _tcslen ( csArrPFDirLocations [ i ] ) + _tcslen ( szFile ) + 1 >= cbszFile )
					return ( false ) ;

				memset ( szFile , 0 , cbszFile * sizeof ( TCHAR ) ) ;
				_tcscpy_s ( szFile , cbszFile , csArrPFDirLocations [ i ] ) ;
				_tcscat_s ( szFile , cbszFile , CString(BACK_SLASH) ) ;
				_tcscat_s ( szFile , cbszFile , csHold ) ;
				return ( true ) ;
			}
		}

		return ( false ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::IsFilePresentInSystem, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: LookUpWhiteList
	In Parameters	: char const * , bool
	Out Parameters	: bool
	Purpose			: checks a file in white list
	Author			: Anand
	Description		: check the given filename in the list of white list filenames
					  and return true when found
	Version			: 18.7.0.001
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::LookUpWhiteList ( LPCTSTR szFileName , DWORD dwRegistryEntryID )
{
	try
	{
		bool bFoundWhite = false ;
		CString csNoUse ;
		CString csNameToSearch = szFileName ;
		CString csSysDir = CSystemInfo::m_strSysDir ;
		CString csPFDir = CSystemInfo::m_strProgramFilesDir ;

		csNameToSearch . MakeLower() ;
		csSysDir . MakeLower() ;
		csPFDir . MakeLower() ;

		if ( !_tcsnicmp ( szFileName , csSysDir , _tcslen ( csSysDir ) ) )
			csNameToSearch . Replace ( csSysDir , _T("%sysdir%") ) ;
		else if ( !_tcsnicmp ( szFileName , csPFDir , _tcslen ( csPFDir ) ) )
			csNameToSearch . Replace ( csPFDir , _T("%pfdir%") ) ;

		if ( ( KEY_ID_NOTIFY & dwRegistryEntryID ) == dwRegistryEntryID )
			bFoundWhite = m_objNotifyWhiteList . Lookup ( csNameToSearch , csNoUse ) ? true : false ;

		if ( ( KEY_ID_APPINIT & dwRegistryEntryID ) ==  dwRegistryEntryID )
			bFoundWhite = bFoundWhite || m_objAppInitWhiteList . Lookup ( csNameToSearch , csNoUse ) ? true : false ;

		if ( ( KEY_ID_SSODL & dwRegistryEntryID ) == dwRegistryEntryID )
			bFoundWhite = bFoundWhite || m_objSSODLWhiteList . Lookup ( csNameToSearch , csNoUse ) ? true : false ;

		return ( bFoundWhite ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::LookUpWhiteList, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: KillProcess
	In Parameters	: CString , CString 
	Out Parameters	: 
	Purpose			: kill the process
	Author			: 
	Description		: kill the process
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: KillProcess ( CString csFolder , CString csFile )
{
	try
	{
		CString csFullFileName = _T("") ;

		if ( csFolder.IsEmpty() || csFile.IsEmpty() )
			return ( false ) ;

		csFullFileName = m_objSysInfo.m_strProgramFilesDir + CString(BACK_SLASH) + csFolder + CString(BACK_SLASH) + csFile ;
		if ( _taccess_s ( csFullFileName , 0 ) )
		{
			if ( m_bScanOtherLocations )
			{
				csFullFileName = m_csOtherPFDir + CString(BACK_SLASH) + csFolder + CString(BACK_SLASH) + csFile ;
				if ( _taccess_s ( csFullFileName , 0 ) )
					return ( true ) ;
			}
			else
			{
				return ( true ) ;
			}
		}

		// this process needs be killed for running uninstaller
		m_objEnumProcess.IsProcessRunning ( csFullFileName , true ) ;
		m_objEnumProcess.IsProcessRunning ( csFullFileName , true ) ;
		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::KillProcess, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: SearchStringInRunKeyData
	In Parameters	: CString,CString
	Out Parameters	: bool
	Purpose			: checks the run reg key for searching specified string
	Author			: Prajakta
	Description		: searches and notifies the UI of Spyware entry from registry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::SearchStringInRunKeyData ( ULONG ulSpywareName , CString csSearchString , CString& csRegValue , CString& csRegData , HKEY hHive )
{
	try
	{
		//CStringArray csArrVal , csArrData ;
		CString		 csRunDataPath ;
		bool bReturnValue = false ;
		CStringArray csArrLocations ;		
		CExecuteProcess objExeProcess;
		CString csSid ;

		csSid = objExeProcess.GetCurrentUserSid();

		csArrLocations . Add ( RUN_REG_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;

		csSearchString . MakeLower() ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{	
			// Enumeratre HKLM\software\microsoft\windows\current version\run            
            vector<REG_VALUE_DATA> vecRegValues;	        
			if ( hHive == HKEY_USERS )
                m_objReg.EnumValues(csSid + CString(BACK_SLASH) + csArrLocations [ i ], vecRegValues, hHive);				
			else
                m_objReg.EnumValues(csArrLocations [ i ], vecRegValues, hHive);				

            int iValueCount = (int)vecRegValues.size();
			for (int icount = 0 ; icount < iValueCount ; icount++)
			{
				CString csData;
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[icount].bData);
				csData . MakeLower() ;
				if ( csData. Find ( csSearchString , 0 ) != -1 )
				{
					//csRunDataPath is integrating  Path where The entry found
					SendScanStatusToUI ( Special_RegVal, ulSpywareName , hHive,csArrLocations [ i ], vecRegValues[icount].strValue ,vecRegValues[icount].Type_Of_Data , vecRegValues[icount].bData , vecRegValues[icount].iSizeOfData) ;					
					bReturnValue = true;
				}
			}
		}
		return bReturnValue ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::SearchStringInRunKeyData, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckIfCodecFolder
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check if given folder is Codec spyware folder
	Author			: Anand
	Description		: check files in all the enumerated %PFDIR% folders and decide
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckIfCodecFolder ( CString csFolderName )
{
	try
	{
		CFileVersionInfo oFileVersionInfo;
	
		if ( !_taccess_s ( csFolderName + _T("\\isaddon.dll") , 0 ) && !_taccess_s ( csFolderName + _T("\\iesplugin.dll") , 0 ) &&
			 !_taccess_s ( csFolderName + _T("\\isamonitor.exe") , 0 ) )
		{
			
			// now check if the dlls dont have a version tab
			if ( oFileVersionInfo.DoTheVersionJob ( csFolderName + _T("\\isaddon.dll") , false ) ||
				 oFileVersionInfo.DoTheVersionJob ( csFolderName + _T("\\iesplugin.dll") , false ))
			{
				return true;
			}
		}
		// check if all the files are present
		if ( !_taccess_s ( csFolderName + _T("\\pmsnrr.exe") , 0 ) && !_taccess_s ( csFolderName + _T("\\pmmnt.exe") , 0 ) &&
			 !_taccess_s ( csFolderName + _T("\\isamini.exe") , 0 ))
		{
			// now check if the dlls dont have a version tab
			if ( oFileVersionInfo . DoTheVersionJob ( csFolderName + _T("\\isamini.exe") , false ) ||
				 oFileVersionInfo . DoTheVersionJob ( csFolderName + _T("\\pmmnt.exe") , false ) ||
				 oFileVersionInfo . DoTheVersionJob ( csFolderName + _T("\\pmsnrr.exe") , false ) )
			{
				return true;
			}
		}

		//Search for Codec folder
		//Version			: 2.5.0.18
		if ( IsCodecFolder ( csFolderName ) )
		{
			return true ;
		}

		return false;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckIfCodecFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: IsCodecFolder
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: check if given folder is Codec spyware folder
	Author			: Shweta
	Description		: check files has un.exe or un.dll in the file and the file must not 
					  have version tab
	Version			: 2.5.0.18
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: IsCodecFolder ( CString csFolderName )
{
	try
	{
		CFileFind objFF ;
		CString csFolderPath , csFileName ;
		BOOL bFFresult = TRUE ; 
		int icounter = 0 ;
		CFileVersionInfo objFV ;
		CArray<CStringA,CStringA> csArrCodecStrings ;

		csFolderPath = csFolderName + _T("\\*.*") ;
		bFFresult = objFF . FindFile ( csFolderPath  ) ;
		if ( !bFFresult )
			return ( false ) ;

		// prepare string array for codec strings
		csArrCodecStrings . Add ( "VideoA" ) ;

		while ( bFFresult )
		{
			bFFresult =  objFF . FindNextFile() ;

			if ( objFF . IsDirectory() || objFF . IsDots() )
				continue ;

			csFileName = objFF . GetFileName();
			
			//The file should have un.exe or un.dll
			if ( ( csFileName . Find ( _T("un.exe") , 0 ) == -1 ) && ( csFileName.Find ( _T("un.dll") , 0 ) == -1 ) )
				continue ;

			if ( ! objFV . DoTheVersionJob ( objFF . GetFilePath() , false ) )
				continue ;

			//Search for codec string
			if ( SearchStringsInFile ( objFF . GetFilePath() , csArrCodecStrings ) )
				icounter++ ;
		}

		objFF.Close();

		if ( icounter >= 2 )
			return ( true ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::IsCodecFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: SearchPathInCLSID
	In Parameters	: CString , CString , CString
	Out Parameters	: bool
	Purpose			: checks if this clsid points to the path sent
	Author			: Anand
	Description		: reads the dll name from the CLSID
					  and cheks if the path is present in it
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::SearchPathInCLSID ( CString csClassID , CString csPath , ULONG ulSpywareName )
{
	try
	{
		bool bFound = false ;
		csClassID.MakeLower();
		csClassID.Replace(_T("b{"),_T("{"));
		CStringArray csArrLocations ;

		csArrLocations . Add ( CLSID_KEY ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid")) ) ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			CString csData ;
			CString csFullKey = csArrLocations [ i ] + csClassID + CString(BACK_SLASH) + INPROCSERVER32 ;
			CPathExpander objExpander ;

			m_objReg.Get( csFullKey , BLANKSTRING , csData , HKEY_LOCAL_MACHINE ) ;
			if ( csData.IsEmpty() )
				return ( bFound ) ;

            objExpander.Expand( csData ) ;

			bFound = !_tcsnicmp ( csData , csPath , _tcslen ( csPath ) ) ;

			if ( bFound )
				EnumAndReportCOMKeys ( ulSpywareName , csArrLocations [ i ] + csClassID , HKEY_LOCAL_MACHINE ) ;
		}

		return ( bFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::SearchPathInCLSID, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ChangePermission
	In Parameters	: CString csRegKey  : Registry Key
					: HKEY hKey : Hive
	Out Parameters	: bool
	Purpose			: Change the permission of registry key
	Author			: Dipali
	Description		: deny the permission to registry key so that noone can access that key
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: ChangePermission(CString csRegKey, HKEY hKey)
{
	try
	{
		DWORD dwRes;
		PSID pEveryoneSID = NULL, pAdminSID = NULL;
		PACL pACL = NULL;
		PSECURITY_DESCRIPTOR pSD = NULL;
		EXPLICIT_ACCESS ea[2];
		SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
		SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
		SECURITY_ATTRIBUTES sa;
		HKEY hkSub = NULL;

		// Create a well-known SID for the Everyone group.
		if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
						 SECURITY_WORLD_RID,
						 0, 0, 0, 0, 0, 0, 0,
						 &pEveryoneSID))
		{
			goto Cleanup;
		}

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow Everyone read access to the key.
		ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
		ea[0].grfAccessMode = DENY_ACCESS;
		ea[0].grfInheritance= NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName  = (LPTSTR) pEveryoneSID;

		// Create a SID for the BUILTIN\Administrators group.
		if(! AllocateAndInitializeSid(&SIDAuthNT, 2,
						 SECURITY_BUILTIN_DOMAIN_RID,
						 DOMAIN_ALIAS_RID_ADMINS,
						 0, 0, 0, 0, 0, 0,
						 &pAdminSID)) 
		{
			goto Cleanup; 
		}

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow the Administrators group full access to the key.
		ea[1].grfAccessPermissions = KEY_ALL_ACCESS ;
		ea[1].grfAccessMode = DENY_ACCESS;
		ea[1].grfInheritance= NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[1].Trustee.ptstrName  = (LPTSTR) pAdminSID;

		// Create a new ACL that contains the new ACEs.
		dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
		if (ERROR_SUCCESS != dwRes) 
		{
			goto Cleanup;
		}

		// Initialize a security descriptor.  
		pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, 
								 SECURITY_DESCRIPTOR_MIN_LENGTH); 
		if (NULL == pSD) 
		{ 
			goto Cleanup; 
		} 
	 
		if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) 
		{  
			goto Cleanup; 
		} 
	 
		// Add the ACL to the security descriptor. 
		if (!SetSecurityDescriptorDacl(pSD, 
				TRUE,     // bDaclPresent flag   
				pACL, 
				FALSE))   // not a default DACL 
		{  
			goto Cleanup; 
		} 

		// Initialize a security attributes structure.
		sa.nLength = sizeof (SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = pSD;
		sa.bInheritHandle = FALSE;

		//// Use the security attributes to set the security descriptor 
		//// when you create a key.
		HKEY hRetKey;
		if(RegOpenKey(hKey,csRegKey,&hRetKey) == ERROR_SUCCESS)
		{
			RegSetKeySecurity(hRetKey,DACL_SECURITY_INFORMATION,pSD);
			RegCloseKey(hRetKey);
		}

	Cleanup:

		if (pEveryoneSID) 
			FreeSid(pEveryoneSID);
		if (pAdminSID) 
			FreeSid(pAdminSID);
		if (pACL) 
			LocalFree(pACL);
		if (pSD) 
			LocalFree(pSD);
		if (hkSub) 
			RegCloseKey(hkSub);
		return true;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::ChangePermission, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: FixLSP
	In Parameters	: 
	Out Parameters	: 
	Purpose			: fix lsp entries
	Author			: 
	Description		: overwrite default entries for lsp
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FixLSP ( void )
{
	try
	{
		if(CSystemInfo::m_bAdminRight)
		{
			HINSTANCE hinstDLL = NULL ;
			GETACTIVEXPROC OptionTabAction = NULL ;

			hinstDLL = ::LoadLibrary((LPCTSTR)_T("Option.dll"));
			if ( hinstDLL == NULL )
				return false;
			//Sandip
			//Description:Set the default parameter and also change in declartion
			//Date:12-June-2008
			OptionTabAction = (GETACTIVEXPROC)GetProcAddress(hinstDLL, "OptionTabAction");
			if(NULL == OptionTabAction)
			{
				::FreeLibrary ( hinstDLL ) ;
				return false;
			}

			OptionTabAction ( ENUM_OA_FIXLSP , CSystemInfo::m_strOS , NULL , L"" ,false) ;

			OptionTabAction = NULL ;
			::FreeLibrary ( hinstDLL ) ;
			return true;
		}
		else
		{
			WritePrivateProfileString(_T("LSP"),_T("Fix"),_T("1"),CSystemInfo::m_strAppPath + SVCQUARANTINEINI);
			return true;
		}
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::FixLSP, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSubFoldersForVariant
	In Parameters	: CString , CString , CStringArray
	Out Parameters	: bool
	Purpose			: check sub folders of a given folder for a known spyware variant
	Author			: Anand
	Description		: search for exe with folder name in the sub folders of the given folder,
					  and look for the set of keywords in the exe,
					  if the keywords list is found in the exe,
					  the exe sub folder contaning exe is spyware variant
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckSubFoldersForVariant ( ULONG ulSpywareName, CString csMainFolder, CArray<CStringA,CStringA>& csArrKeywordsList )
{
	try
	{
        if(IsStopScanningSignaled())
			return ( false ) ;

		CFileFind objFile;

		bool	bVariantFound = false ;
		BOOL	bMoreFiles	=	FALSE;
		
		CString csFileName = _T("") ;
		
		bMoreFiles = objFile.FindFile( csMainFolder + _T("\\*.*") ) ;
		while ( bMoreFiles )
		{
			bMoreFiles = objFile.FindNextFile() ;
			if ( objFile.IsDots() || !objFile.IsDirectory() )
				continue ;

			if(IsStopScanningSignaled())
				break ;

			csFileName = objFile.GetFilePath() + CString(BACK_SLASH) + objFile.GetFileName() + _T(".exe") ;
			
			//Version: 19.0.0.039
			//Resource:Avinash
			//getPattern - ***virus burst***changed again to normal string search as function is called in quick scan 
			if ( SearchStringsInFile ( csFileName, csArrKeywordsList))
			{
				RemoveFolders ( objFile.GetFilePath() , ulSpywareName , false ) ;
			}
		}
		objFile.Close() ;
		return	bVariantFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckSubFoldersForVariant, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsRandomSpywareFolder
	In Parameters	: const CString&, const CString&, const CString&
	Out Parameters	: 
	Purpose			: determine if the given folder is SmokingGun random folder
	Author			: Anand
	Description		: looks for a pattern and also the data in smoking gun main file
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: IsRandomSpywareFolder ( const CString& csFolderName , const CString& csSearchString , ULONG ulSpywareName )
{
	try
	{
		CString csRandomNumber ;
		CString csFullFileName ;
		int iDashIndex = 0 ;
		CFileFind objFF;
		BOOL bFound;
		CString csOnlyFolderName ;
		CArray<CStringA,CStringA> csArrStrings ;
		bool bSuspiciousFolder = false ;

		// a sample folder for which this function must return true
		//eg: c:\program files\PCS-375\SmokingGun.Net 2.4.0\PCSmokingGun375.exe
		iDashIndex = csFolderName . Find ( _T('-') ) ;
		if ( iDashIndex == -1 )
			return ( false ) ;

		csArrStrings . Add ( (CStringA)csSearchString ) ;
		csRandomNumber = csFolderName . Right ( csFolderName . GetLength() - ( iDashIndex + 1 ) ) ;

		// check all the characters must be digits
		for ( int i = 0 ; i < csRandomNumber . GetLength() ; i++ )
			if ( !isdigit ( csRandomNumber [ i ] ) )
				return ( false ) ;

		bFound = objFF . FindFile ( csFolderName + L"\\*" ) ;
		while ( bFound )
		{
			bFound = objFF.FindNextFile();
			if ( objFF.IsDots() || !objFF.IsDirectory() )
				continue ;

			csOnlyFolderName = objFF . GetFileName() . MakeLower() ;

			if ( csOnlyFolderName . Find ( csSearchString ) == -1 )
				continue ;

			csFullFileName.Format(_T("%s\\PC%s%s.exe"),
									static_cast<LPCTSTR>(objFF.GetFilePath()),
									static_cast<LPCTSTR>(csSearchString), 
									static_cast<LPCTSTR>(csRandomNumber));
			
			if ( _taccess_s ( csFullFileName , 0 ) )
				continue ;

			if ( !SearchStringsInFile ( csFullFileName , csArrStrings ) )
				continue ;

			csFullFileName.Format(_T("%s\\pcmn%s.ini"), 
									static_cast<LPCTSTR>(CSystemInfo::m_strWinDir), 
									static_cast<LPCTSTR>(csRandomNumber));
			if ( !_taccess_s ( csFullFileName , 0 ) )
				SendScanStatusToUI ( Special_File, ulSpywareName , csFullFileName  ) ;

			bSuspiciousFolder = true ;
			break ;
		}

		objFF.Close();
		return ( bSuspiciousFolder ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::IsRandomSpywareFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsEntryInMultiStringReg
	In Parameters	: HKEY , CString , CString , CString , bool 
	Out Parameters	: 
	Purpose			: Check entry in registry
	Author			: 
	Description		: checks for entry in registry
--------------------------------------------------------------------------------------*/
//REVISIT this function
bool CSplSpyScan::IsEntryInMultiStringReg(HKEY hHive, CString csKey, CString csValue, CString csCompareWith, bool bRemoveIt)
{
	try
	{
		HKEY hKey = NULL ;
		LONG lRetValue = 0 ;
		DWORD dwType = 0 , dwDataSize = 0 ;
		TCHAR * Data = NULL , * DuplicateData = NULL ;
		bool bMatchFound = false ;
		BYTE Hold [ 2 ] = { 0 } ;

		LPCTSTR	Ptr = NULL ;
		TCHAR * DupPtr = NULL ;

		lRetValue = RegCreateKey ( hHive , csKey , &hKey ) ;
		if ( ERROR_SUCCESS != lRetValue )
			return ( false ) ;

		RegQueryValueEx ( hKey , csValue , 0 , &dwType , 0 , &dwDataSize ) ;
		//Should be implemented in Bytes
        Data = new TCHAR [ dwDataSize ] ;
		if ( !Data )
		{
			RegCloseKey ( hKey ) ;
			return ( false ) ;
		}
    
		memset ( Data , 0 , dwDataSize * sizeof ( TCHAR ) ) ;
		lRetValue = RegQueryValueEx ( hKey , csValue , 0 , &dwType , (BYTE*)Data , &dwDataSize ) ;
		if ( ERROR_SUCCESS != lRetValue )
		{
			RegCloseKey ( hKey ) ;
			delete [] Data;
			return ( false ) ;
		}

		if ( bRemoveIt )
		{
			DuplicateData = new TCHAR [ dwDataSize ] ;
			if ( !DuplicateData )
			{
				RegCloseKey ( hKey ) ;
				delete [] Data;
				return ( false ) ;
			}

			memset ( DuplicateData , 0 , dwDataSize *sizeof(TCHAR)) ;
			DupPtr = DuplicateData ;
			Ptr = Data ;
			while ( *Ptr )
			{
				bMatchFound = false ;
				if ( 0 == _tcsicmp ( Ptr , csCompareWith ) )
					bMatchFound = true ;

				// skip to next string
				while ( *Ptr )
				{
					if ( false == bMatchFound )
						*DupPtr++ = *Ptr ;

					Ptr++ ;
				}
				
				if ( false == bMatchFound )
					*DupPtr++ = *Ptr ;

				Ptr++ ;
			}

			if ( DupPtr - DuplicateData >= 1 )
				*DupPtr++ = 0 ;

			RegSetValueEx ( hKey , csValue , 0 , dwType , Hold , 2 ) ;
			RegSetValueEx ( hKey , csValue , 0 , dwType , (BYTE*)DuplicateData , (DWORD) ( DupPtr - DuplicateData ) * sizeof ( TCHAR ) ) ;

			delete [] DuplicateData;
		}
		else
		{
			Ptr = Data ;
			while ( *Ptr )
			{
				if ( 0 == _tcsicmp ( Ptr , csCompareWith ) )
				{
					bMatchFound = true ;
					break ;
				}

				// skip to next string
				while ( *Ptr )Ptr++ ;
				Ptr++ ;
			}
		}

		RegCloseKey ( hKey ) ;
		delete [] Data;
		return ( bMatchFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::IsEntryInMultiStringReg, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ListFolders
	In Parameters	: WCHAR * , bool
	Out Parameters	: 
	Purpose			: list all folder using wide chars
	Author			: Anand
	Description		: check for pattern and delete folder
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: ListFolders ( WCHAR * wSearchPath , bool bToDelete )
{
	try
	{
		WCHAR wFullFileName [ _MAX_PATH ] = { 0 } ;
		WCHAR wSearchString [ _MAX_PATH ] = { 0 } ;
		WIN32_FIND_DATAW wFindData = { 0 } ;
		HANDLE hSearch = INVALID_HANDLE_VALUE;

		if ( _tcscpy_s ( wSearchString , _countof ( wSearchString ) , wSearchPath ) )
			return ( false ) ;

		if ( _tcscat_s ( wSearchString , _countof ( wSearchString ) , _T("\\*") ) )
			return ( false ) ;

		hSearch = FindFirstFileW ( wSearchString , &wFindData ) ;
		if ( INVALID_HANDLE_VALUE == hSearch )
			return ( false ) ;

		do
		{
			if ( _tcscpy_s ( wFullFileName , _countof ( wFullFileName ) , wSearchPath ) )
				break ;

			if ( _tcscat_s ( wFullFileName , _countof ( wFullFileName ) , _T("\\") ) )
				break ;

			if ( _tcscat_s ( wFullFileName , _countof ( wFullFileName ) , wFindData . cFileName ) )
				break ;

			if ( _tcscat_s ( wFullFileName , _countof ( wFullFileName ) , _T("\\fast.exe") ) )
				break ;

			if ( !_waccess ( wFullFileName , 0 ) )
			{
				if ( _tcscpy_s ( wFullFileName , _countof ( wFullFileName ) , wSearchPath ) )
					break ;

				if ( _tcscat_s ( wFullFileName , _countof ( wFullFileName ) , _T("\\") ) )
					break ;

				if ( _tcscat_s ( wFullFileName , _countof ( wFullFileName ) , wFindData . cFileName ) )
					break ;

				// check and delete purity scan files which are in Wide Char
				CheckAndDeleteWideCharFilenames ( wFullFileName , bToDelete , 5108 ) ;
				memset ( wFullFileName , 0 , sizeof ( wFullFileName ) ) ;
			}

		}while ( FindNextFileW ( hSearch , &wFindData ) ) ;

		FindClose ( hSearch ) ;
		return ( true ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::ListFolders, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndDeleteWideCharFilenames
	In Parameters	: WCHAR * , bool , CString 
	Out Parameters	: 
	Purpose			: check and remove wide char filename
	Author			: Anand
	Description		: delete folder using wide char filenames
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckAndDeleteWideCharFilenames ( WCHAR * wSearchPath , bool bToDelete , ULONG ulSpywareName )
{
	try
	{
		WCHAR wFullFileName [ _MAX_PATH ] = { 0 } ;
		WCHAR wSearchString [ _MAX_PATH ] = { 0 } ;
		WIN32_FIND_DATAW wFindData = { 0 } ;
		HANDLE hSearch = INVALID_HANDLE_VALUE;

		if ( _tcscpy_s ( wSearchString , _countof ( wSearchString ) , wSearchPath ) )
			return ( false ) ;

		if ( _tcscat_s ( wSearchString , _countof ( wSearchString ) , _T("\\*") ) )
			return ( false ) ;

		hSearch = FindFirstFileW ( wSearchString , &wFindData ) ;
		if ( INVALID_HANDLE_VALUE == hSearch )
			return ( false ) ;

		do
		{
			if ( _tcscpy_s ( wFullFileName , _countof ( wSearchString ) , wSearchPath ) )
				break ;

			if ( _tcscat_s ( wFullFileName , _countof ( wSearchString ) , _T("\\") ) )
				break ;

			if ( _tcscat_s ( wFullFileName , _countof ( wSearchString ) , wFindData . cFileName ) )
				break ;

			if ( ( wFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) != FILE_ATTRIBUTE_DIRECTORY )
			{
				WCHAR String [ _MAX_PATH ] = { 0 } ;
				int i = 0 ;

				if ( _tcslen ( wFullFileName ) < _countof ( String ) )
				{
                    //TODO:
					while ( String [ i ] = (char)wFullFileName [ i++ ] ) ;
					if (m_objEnumProcess.IsProcessRunning(String, true))
						SendScanStatusToUI (Special_Process, ulSpywareName , String  ) ;
					SendScanStatusToUI ( Special_File, ulSpywareName , String ) ;
				}
			}
			else
			{
				m_bSplSpyFound = true ;
				if ( _tcscmp ( wFindData . cFileName , _T(".") ) && _tcscmp ( wFindData . cFileName , _T("..") ) )
					CheckAndDeleteWideCharFilenames ( wFullFileName , bToDelete , ulSpywareName ) ;
			}

			memset ( wFullFileName , 0 , sizeof ( wFullFileName ) ) ;
		}while ( FindNextFileW ( hSearch , &wFindData ) ) ;

		FindClose ( hSearch ) ;
		SendScanStatusToUI ( Special_Folder, ulSpywareName , wSearchPath) ;
		return ( true ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckAndDeleteWideCharFilenames, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetIllegitimateFileNames
	In Parameters	: char *
	Out Parameters	: CStringArray&
	Purpose			: get entries which are new and spyware
	Author			: Anand
	Description		: get entries which are new and spyware in 'csFileNames'
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetIllegitimateFileNames ( TCHAR * RegData , CStringArray& csFileNames )
{
	try
	{
		TCHAR*	Ptr = NULL ;
		size_t  len = 0 ;
		TCHAR	SysPath [ MAX_PATH ] = { 0 } ;
		CString csUserinitExe	=	 m_objSysInfo.m_strSysDir + _T("\\userinit.exe") ;
		TCHAR * lpContex = NULL ;
		CString csOtherUserinitExe = m_csOtherSysDir + _T("\\userinit.exe") ;

		Ptr = _tcstok_s ( RegData , _T(",") , &lpContex ) ;
		while ( Ptr )
		{
			len = _tcslen ( Ptr ) ;

			for ( ; *Ptr == ' ' ; Ptr++ , len-- ) ; // remove spaces before 'Ptr'
			for ( ; len > 1 && Ptr [ len - 1 ] == ' ' ; Ptr [ --len ] = '\0' ) ; // remove spaces after 'Ptr'

			if ( _tcsicmp ( Ptr , _T("Explorer.exe") ) && _tcsicmp ( Ptr , csUserinitExe ) && *Ptr )
			{
				if ( _tcschr ( Ptr , _T('\\') ) )
					csFileNames.Add(Ptr);
				else
				{
					CString csFullFileName ( SysPath ) ;
					csFullFileName += Ptr ;
					csFileNames.Add(m_objSysInfo.m_strSysDir + CString(BACK_SLASH) + Ptr );
				}
			}

			Ptr = _tcstok_s ( NULL , _T(",") , &lpContex ) ;
		}
		return true;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::GetIllegitimateFileNames, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumKeynSubKey
	In Parameters	: CString ,CString
	Out Parameters	: void
	Purpose			: check for Common Name Random Keys
	Author			: Shweta
	Description		: Enumerate Keys and SubKeys
--------------------------------------------------------------------------------------*/
void CSplSpyScan :: EnumKeynSubKey ( CString csKeyToEnumerate , ULONG ulSpywareName , bool bAddInRestart)
{
	try
	{
		CString csKey , csHive;
		CStringArray csKeyArr ;
		//CStringArray csValArr , csDataArr ;
		HKEY hhive;

		csKey = csKeyToEnumerate.Right(csKeyToEnumerate.GetLength() - csKeyToEnumerate.Find(CString(BACK_SLASH),0)-1);
		csHive = csKeyToEnumerate.Left ( csKeyToEnumerate.Find(CString(BACK_SLASH),0) ); 
		csHive.MakeUpper();

		if ( csHive == HKLM ) 
			hhive = HKEY_LOCAL_MACHINE ;
		else 
		{
			if ( csHive == HKU )
				hhive = HKEY_USERS ;
			else
				return ;
		}

		m_objReg.EnumSubKeys ( csKey,csKeyArr,hhive );
		for ( int  ikeycnt = 0 ; ikeycnt < csKeyArr.GetCount() ; ikeycnt++)
		{
			EnumKeynSubKey(csKeyToEnumerate + CString(BACK_SLASH) + csKeyArr.GetAt(ikeycnt),ulSpywareName);
		}

		SendScanStatusToUI(Special_RegKey, ulSpywareName ,hhive, csKey , 0,0,0,0);
		if (bAddInRestart )
		{
			AddToCompulsoryDeleteOnRestartList ( RD_KEY , ulSpywareName , csHive + BACK_SLASH + csKey ) ;
		}

         vector<REG_VALUE_DATA> vecRegValues;
         m_objReg.EnumValues(csKey, vecRegValues, hhive);
        //m_objReg.QueryDataValue(csKey , csValArr , csDataArr ,hhive,ptrDataTypes, iDataTypeSize);
        int iCount = (int)vecRegValues.size();
		for ( int ivalcnt = 0 ; ivalcnt < iCount ; ivalcnt++)
		{
            CString csValue = vecRegValues[ivalcnt].strValue;
            SendScanStatusToUI( Special_RegVal, ulSpywareName , hhive, csKey ,csValue,vecRegValues[ivalcnt].Type_Of_Data , vecRegValues[ivalcnt].bData ,vecRegValues[ivalcnt].iSizeOfData);				
			if (bAddInRestart )
				AddInRestartDeleteList(RD_VALUE, m_ulSpyName, csKeyToEnumerate + REG_SEPERATOR + CString(vecRegValues[ivalcnt].bData));
		}
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::EnumKeynSubKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: FixINIFile
	In Parameters	: const char*, const char*, const char*, const char*
	Out Parameters	: 
	Purpose			: Fix the infected entries in ini file
	Author			: 
	Description		: Searches in the ini file for given entry, replaces it with blank if found
					  Returns true if found and fixed any such entry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FixINIFile ( LPCTSTR sIniFile , LPCTSTR sAppName , LPCTSTR sValue , LPCTSTR sInfectedStr )
{
	try
	{
		TCHAR strData [ MAX_PATH ] = { 0 } ;

		GetPrivateProfileString(sAppName, sValue, _T(""), strData, MAX_PATH, sIniFile);
		if(StrStrI(strData, sInfectedStr))
		{
			WritePrivateProfileString(sAppName, sValue, _T(""), sIniFile);
			return true;
		}

		return false;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::FixINIFile, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: FindExeAndRemove
	In Parameters	: CString , CString , CString , bool
	Out Parameters	: 
	Purpose			: check and fixes random spywares files
	Author			: 
	Description		: implements wildcard search for the given file in given folder
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindExeAndRemove(ULONG ulSpyName, CString csPath, CString csWildcard, bool bRemoveit)
{
	try
	{
		bool bRetVal = false;

		CFileFind	objFile;
		CString strWildcard(csPath);
		strWildcard += _T("\\") + csWildcard;
		BOOL bFound = objFile.FindFile(strWildcard);

		while(bFound)
		{  
			if( IsStopScanningSignaled())
				break;

			bFound = objFile.FindNextFile();
			if (objFile.IsDots())
				continue;

			bRetVal = true;
			CString csFilePath = objFile.GetFilePath();
			
			FindKillReportProcess ( csFilePath , ulSpyName , bRemoveit ) ;
		}
		
		objFile.Close();
		return bRetVal;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::FindExeAndRemove, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: FindExeAndRemove
	In Parameters	: CString , CString , CString , bool , CString 
	Out Parameters	: bool * 
	Purpose			: cleans an exe file
	Author			: 
	Description		: deletes exe files and kills if their process is running
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindExeAndRemove(ULONG ulSpyName, CString csPath, CString csWildcard, bool bRemoveit, CStringArray & sIgnoreList)
{
	try
	{
		if(IsStopScanningSignaled())
			return false;
		
		bool bRetVal = false;
		CFileFind	objFile;
		CString strWildcard(csPath);
		strWildcard += CString(BACK_SLASH) + csWildcard;
		
		BOOL bFound = objFile.FindFile(strWildcard);
		while(bFound)
		{  
			if(IsStopScanningSignaled())
				break;

			bFound = objFile.FindNextFile();
			if (objFile.IsDots())
				continue;

			CString csFilePath = objFile.GetFilePath();
			bool bFoundFlag = false;
			csFilePath.MakeLower();
			// 2.5.0.49
			for ( int i = 0 ; i < sIgnoreList.GetCount() ; i++)
			{
				if(csFilePath.Find(sIgnoreList.GetAt(i)) != -1)
				{
					bFoundFlag = true;
				}
			}
			if (!bFoundFlag )
			{
				bRetVal = true;
				FindKillReportProcess ( csFilePath , ulSpyName , bRemoveit ) ;
			}
			
			if( IsStopScanningSignaled())
				return false;
		}

		objFile.Close();
		return bRetVal;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::FindExeAndRemove, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetGenuineFile
	In Parameters	: const char *
	Out Parameters	: char *
	Purpose			: look for clean file
	Author			: 
	Description		: finds a clean version of the file in any of the backup folder
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetGenuineFile(LPCTSTR sFileName, LPTSTR sGenuineFileName , DWORD cbGenuineFileName )
{
	try
	{
		if(CheckSystemFolder(_T("dllcache\\"), sFileName, sGenuineFileName))
			return true;
		if(CheckWindowsFolder(_T("$hf_mig$\\KB890923\\SP2QFE\\"), sFileName, sGenuineFileName , cbGenuineFileName ))
			return true;
		if(CheckWindowsFolder(_T("$hf_mig$\\KB867282\\SP2QFE\\"), sFileName, sGenuineFileName , cbGenuineFileName ))
			return true;
		if(CheckWindowsFolder(_T("$hf_mig$\\KB883939\\SP2QFE\\"), sFileName, sGenuineFileName , cbGenuineFileName ))
			return true;
		if(CheckWindowsFolder(_T("ServicePackFiles\\i386\\"), sFileName, sGenuineFileName , cbGenuineFileName ))
			return true;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::GetGenuineFile, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSystemFolder
	In Parameters	: const char * , const char *
	Out Parameters	: char *
	Purpose			: search file in system32 folder
	Author			: 
	Description		: searchs the file in system32 folder and returns the path
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckSystemFolder(LPCTSTR sFolderName, LPCTSTR sFileName, LPTSTR sGenuineFileName)
{
	CStringArray csArrLocations ;

	csArrLocations . Add ( CSystemInfo::m_strSysDir ) ;
	if ( m_bScanOtherLocations )
		csArrLocations . Add ( m_csOtherSysDir ) ;

	for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
	{
		_tcscpy_s ( sGenuineFileName , MAX_PATH , ( csArrLocations [ i ] + CString(BACK_SLASH) ) ) ;
		_tcscat_s ( sGenuineFileName , MAX_PATH , sFolderName ) ;
		_tcscat_s ( sGenuineFileName , MAX_PATH , sFileName ) ;
		

		CFileFind objFile;
		if(objFile.FindFile(sGenuineFileName))
			return true ;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckWindowsFolder
	In Parameters	: const char * , const char *
	Out Parameters	: char *
	Purpose			: gets the clean file
	Author			: 
	Description		: Searches for file in windows folder and returns the name in 'sGenuineFileName'
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckWindowsFolder(LPCTSTR sFolderName, LPCTSTR sFileName, LPTSTR sGenuineFileName, DWORD cbGenuineFileName )
{
	_tcscpy_s(sGenuineFileName, cbGenuineFileName , (CSystemInfo::m_strWinDir + CString(BACK_SLASH) ));
	_tcscat_s(sGenuineFileName, cbGenuineFileName , sFolderName);
	_tcscat_s(sGenuineFileName, cbGenuineFileName , sFileName);

	CFileFind objFile;
	if(objFile.FindFile(sGenuineFileName))
		return true;
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckReportDeleteRegKey
	In Parameters	: HKEY : hive
					  CString csKeyPath : Main Key.
					  CString csSubKey  : SubKey to be deleted
					  CString csSpyDBName : Spyware Name used in database for reporting.
					  bool isDelete      : Check for Scan or Quarantine.
	Out Parameters	: bool  isSpywareFound : True if found else False.
	Purpose			: Checks for Registry Key Existance. Reports to UI or Quarantines the key
					  based on isDelete Flag.
	Author			: Nupur Aggarwal 
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckReportDeleteRegKey( HKEY hive, CString csKeyPath, CString csSubKey, ULONG ulSpyDBName, bool isDelete )
{
	bool bIsSpyFound = false;
	if( m_objReg.KeyExists(csKeyPath + CString(BACK_SLASH) + csSubKey, hive))
	{
		bIsSpyFound = true;	
	
		CString csHiveName = m_objReg.RootKey2String(hive);
		CString csFullKeyPath = csHiveName + CString(BACK_SLASH) + csKeyPath + CString(BACK_SLASH) + csSubKey;

		if(isDelete)
		{
			if(!m_objReg.DeleteKey(csKeyPath , csSubKey , hive))
			{				
				if(!DelKeyLocalMachine(csKeyPath))
				{
					AddInRestartDeleteList(RD_KEY, m_ulSpyName, csFullKeyPath);
				}
			}
		}
		else
			SendScanStatusToUI(Special_RegKey, ulSpyDBName,hive, csKeyPath + CString(BACK_SLASH) + csSubKey,0,0,0,0);
	}
	else
		bIsSpyFound = false;

	return bIsSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindKillReportProcess
	In Parameters	: CString , CString ,bool , bool
	Out Parameters	: 
	Purpose			: find and report process entry
	Author			: 
	Description		: find and report process entry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindKillReportProcess(CString csFullFilePath, ULONG ulSpywareName, bool isDelete, bool bDeleteFile )
{
	bool bSpyFound = false;
	
	if ( _taccess_s ( csFullFilePath, 0 ) == 0 )
	{
		bSpyFound = true;
		if ( m_objEnumProcess.IsProcessRunning( csFullFilePath , false ) )
		{
			if (!isDelete)
				SendScanStatusToUI( Special_Process, ulSpywareName, csFullFilePath  );	
			else if ( bDeleteFile)
				DeleteFile(csFullFilePath);
		}
		if ( !isDelete )
			SendScanStatusToUI(Special_File, ulSpywareName, csFullFilePath);
	}
	else 
		bSpyFound = false;
	
	return bSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindKillReportDll
	In Parameters	: CString , CString ,CString , bool
	Out Parameters	: 
	Purpose			: find and report dll entry
	Author			: 
	Description		: find and report dll entry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindKillReportDll(CString csFullDllPath, ULONG ulSpywareName,CString csFullProcPath, bool isDelete )
{
	bool bSpyFound = false;
	if ( _taccess_s ( csFullDllPath, 0 ) == 0 )
	{
		bSpyFound = true;
		if(isDelete)
		{
			m_objEnumProcess.IsProcessRunning( csFullProcPath , isDelete );
		}
		else
			SendScanStatusToUI( Special_Process, ulSpywareName, csFullDllPath );
	}
	else 
		bSpyFound = false;

	return bSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindKillReportService
	In Parameters	: CString , CString , CString , bool
	Out Parameters	: 
	Purpose			: find and report service entry
	Author			: 
	Description		: find and report service entry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindKillReportService(CString csFullFileName, CString csServiceName, ULONG ulSpywareName, bool isDelete )
{
	bool bSpyFound = false;
	
	CFileFind			fFind;
	CFileOperation		objFileOperation;

	bool bIsFileExists = false;
	if(csFullFileName.IsEmpty())
		bIsFileExists = true;
	else if( _taccess_s(csFullFileName, 0)== 0)
		bIsFileExists = true;

	if(bIsFileExists)
	{
		CString csServiceFileName;
		if ( isDelete )
		{
			CRemoteService objRemService ;
			if( objRemService.StopRemoteService( csServiceName , true , csServiceFileName ) )
			{		
				bSpyFound = true;
				objFileOperation . DeleteThisFile(csServiceFileName) ;
			}
		}
		else
		{
			if(!csFullFileName.IsEmpty())
			{
				bSpyFound = true;
				SendScanStatusToUI( Special_File, ulSpywareName , csFullFileName  ) ;
			}
		}
	}
	else 
		bSpyFound = false;

	return bSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindReportKillServiceOnRestart
	In Parameters	: CString ,CString ,CString , CString ,bool 
	Out Parameters	: 
	Purpose			: report the service entry
	Author			: 
	Description		: report the service entry and kill on restart
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindReportKillServiceOnRestart(CString csServiceName,ULONG ulSpywareName,
												 CString &csServiceFileName, CString &csServiceFolderName,
												 bool isDelete )
{
	bool isSpyFound = false;

	SC_HANDLE hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS); // Open Service Manager
	if ( hSCM != NULL )
	{
		SC_HANDLE hService = OpenService( hSCM , csServiceName , SERVICE_ALL_ACCESS ) ;
		if ( hService != NULL )
		{
			isSpyFound = true ;
			
			// get service names form service database managers
			GetServiceFileName ( hService , csServiceFileName , csServiceFolderName ) ;

			if ( isDelete )
			{
				// 4 is sent for disabling the service
				ChangeServiceConfig ( hService , SERVICE_NO_CHANGE , 4 , SERVICE_NO_CHANGE , NULL , 
									  NULL , NULL , NULL , NULL , NULL , NULL ) ;
				AddInRestartDeleteList(RD_KEY, m_ulSpyName, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + csServiceName);
			}
			else
			{
				if ( !csServiceFileName.IsEmpty () )
					SendScanStatusToUI ( Special_Process, ulSpywareName , csServiceFileName  ) ;
			}
			CloseServiceHandle ( hService ) ;
		}
		CloseServiceHandle ( hSCM ) ;
	}
	else
		isSpyFound = false;

	return isSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindReportRegKey
	In Parameters	: CString, CString, CString, HKEY, bool, bool
	Out Parameters	: 
	Purpose			: report the registry entry
	Author			: 
	Description		: report the registry entry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindReportRegKey(CString csKeyPath, ULONG ulSpyName,  HKEY hive, bool isDelete, bool enumFullKey)
{
	bool isSpyFound = false;

	CString csHive =  m_objReg.RootKey2String(hive);
	if(m_objReg.KeyExists(csKeyPath, hive))
	{
		isSpyFound = true;
		CString csFullKeyPath(csHive + CString(BACK_SLASH) + csKeyPath);

		if ( !isDelete )
		{
			SendScanStatusToUI(Special_RegKey , ulSpyName, hive, csKeyPath,0,0,0,0);
			if(enumFullKey)
			{
				EnumAndReportCOMKeys ( ulSpyName , csKeyPath , hive , false ) ;
			}
		}
		else
			m_objReg.DeleteKey(csKeyPath,BLANKSTRING, hive);
	}
	else
		isSpyFound = false;

	return	isSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindReportRegValue
	In Parameters	: CString, CString, CString, HKEY, bool, bool
	Out Parameters	: 
	Purpose			: report the registry entry
	Author			: 
	Description		: report the registry entry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindReportRegValue(CString csKeyPath, CString csValue, ULONG ulSpyName,  HKEY hive, bool isDelete, bool reportData)
{
	bool isSpyFound = false;

	CString csHive =  m_objReg.RootKey2String(hive);
	if(m_objReg.ValueExists( csKeyPath, csValue, hive))
	{
		isSpyFound = true;
		CString csFullKeyPath(csHive + CString(BACK_SLASH) + csKeyPath + REG_SEPERATOR + csValue );

		if ( !isDelete )
		{
            if( reportData )
			{
				CString csData;
                DWORD dwRegType;
				m_objReg.Get( csKeyPath , csKeyPath , csData , HKEY_LOCAL_MACHINE,&dwRegType);				
                SendScanStatusToUI(Special_RegVal, ulSpyName, HKEY_LOCAL_MACHINE, csKeyPath , csValue, dwRegType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
			}
		}
	}
	else
		isSpyFound = false;

	return	isSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FindReportKillOnRestart
	In Parameters	: CString, CString, bool, bool
	Out Parameters	: 
	Purpose			: report and kill entry on restart
	Author			: 
	Description		: kill the entry on restart
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::FindReportKillOnRestart( CString csFullFilePath, ULONG ulSpyName, bool isDelete, bool isDeleteOnRestart)
{
	bool isSpyFound = false;
	if( _taccess_s( csFullFilePath, 0) == 0)
	{
		isSpyFound = true;
		if(isDelete)
		{
            if ( true == isDeleteOnRestart )
			{
				AddInRestartDeleteList(RD_FILE_DELETE, ulSpyName, csFullFilePath);
			}
			else
				DeleteFile(csFullFilePath);
		}
		else
			SendScanStatusToUI(Special_File, ulSpyName, csFullFilePath);
	}
	else
		isSpyFound = false;

	return isSpyFound;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckCompanyName
	In Parameters	: CString , CString
	Out Parameters	: 
	Purpose			: Checks Company Name
	Author			: 
	Description		: Checks Company Name and returns true if found
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckCompanyName ( CString csFullFileName , CString csCompanyName )
{
	try
	{
		CFileVersionInfo  m_oFileVersionInfo;
		CString sCompName;
		if(m_oFileVersionInfo.GetCompanyName(csFullFileName, sCompName.GetBuffer(MAX_PATH)))
		{
			sCompName.ReleaseBuffer();
			sCompName.MakeLower(); csCompanyName.MakeLower();
			if(sCompName.Find(csCompanyName) != -1)
				return true;
		}
		else
		{
			sCompName.ReleaseBuffer();
		}
		return false;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckCompanyName, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: HandleUninstaller
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: handle the message boxes appearing while running uninstaller
	Author			: 
	Description		: clicks appropriate buttons on message boxes appearing
					  and also removes some winfixer entries from registry
--------------------------------------------------------------------------------------*/
void CSplSpyScan ::HandleUninstaller ( ULONG ulSpywareName )
{
	try
	{
		bool bStop = false ;
		time_t Start = time(0) , TimeOut = 1 * 60 ;	// 1 stands for one minute

		while ( TimeOut > time(0) - Start )
		{
			if ( !EnumWindows ( EnumWindowsProc , NULL ) )
				break ;
			DoEvents();
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::HandleUninstaller, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: EnumWindowsProc
	In Parameters	: HWND , LPARAM 
	Out Parameters	: 
	Purpose			: Callback function for uninstall handler
	Author			: 
	Description		: closes windows appearing during uninstallation
--------------------------------------------------------------------------------------*/
BOOL CALLBACK EnumWindowsProc ( HWND hwnd , LPARAM lParam )
{
	TCHAR Title [ 500 ] = { 0 } ;
	TCHAR * TitleList [] = 
	{
		_T("WinFixer ") ,
		_T("SpyFalcon") ,
		_T("WinAntiSpyware ") ,
		_T("Product Supporter") ,
		_T("WinAntiVirus Pro 2005 - ") ,
		_T("SpywareQuake") ,
		_T("AntiVirusGolden") ,
		_T("AntiVirus-Golden") ,		//Version: 19.0.0.17 , Resource: Anand
		_T("VirusBurst") ,
		_T("VB") ,						//Version: 18.9.0.003 , Resource: Anand
		_T("Virus-Burst") ,				//Version: 18.9.0.001 , Resource: Anand
		_T("Virus-Busters"),			//Version: 19.0.0.030  , Resource: Shweta
		NULL
	} ;

	if ( GetWindowText ( hwnd , Title , _countof ( Title ) ) )
	{
		for ( int i = 0 ; TitleList [ i ] ; i++ )
		{
			if ( StrNIStr ( (BYTE*)Title , _tcslen ( Title )*sizeof(TCHAR) , (BYTE*)TitleList [ i ] , _tcslen ( TitleList [ i ] ) ) )
			{
				bool bAVGolden = false ;
				bool bAV_Golden = false ;
	
				// Spyware Golden is behaving weird, hence multiple methods used for killing its window
				bAVGolden = !!StrNIStr ( (BYTE*)Title , _tcslen ( Title ) * 2 , (BYTE*)_T("AntiVirusGolden") , 15 * 2 ) ;
				bAV_Golden = !!StrNIStr ( (BYTE*)Title , _tcslen ( Title ) * 2 , (BYTE*)_T("AntiVirus-Golden") , 16 * 2 ) ;
				if ( bAVGolden || bAV_Golden )
				{
					HWND hBtn = GetDlgItem ( hwnd , IDCANCEL ) ;
					if ( hBtn )
					{
						SendMessage ( hwnd , WM_COMMAND , MAKEWPARAM ( IDCANCEL , BN_CLICKED ) , ( LPARAM ) hBtn ) ;
					}
					else
					{
						hBtn = GetDlgItem ( hwnd , IDOK ) ;
						if ( hBtn )
						{
							SendMessage ( hwnd , WM_COMMAND , MAKEWPARAM ( IDOK , BN_CLICKED ) , ( LPARAM ) hBtn ) ;
						}
					}

					PostMessage ( hwnd, WM_SYSCOMMAND, SC_CLOSE, 0 ) ;
					SendMessage ( hwnd, WM_ACTIVATE, FALSE, 0L ); 
					SendMessage ( hwnd, WM_CLOSE, FALSE, 0L ) ;
				}
				else
				{
					PostMessage ( hwnd, WM_SYSCOMMAND, SC_CLOSE, 0 ) ;
				}

				return ( FALSE ) ;
			}
		}
	}
	return ( TRUE ) ;

}

void CSplSpyScan::DoEvents()
{
	MSG msg;
	while (::PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) 
	{
		if (msg.message == WM_QUIT)            
		{
			::PostQuitMessage(static_cast<int>(msg.wParam));               
			break;            
		}
		if (!AfxGetApp()->PreTranslateMessage(&msg))
		{
			::TranslateMessage(&msg);               
			::DispatchMessage(&msg);
		}         
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRegKey
	In Parameters	: CString , CString , HKEY , CString
	Out Parameters	: bool * 
	Purpose			: Checks subkeys for given string
	Author			: 
	Description		: enumerates all keys and looks for strings in it and returns in 'strSubKey'
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckRegKey ( CString csMainKey, CString csCompare, HKEY hHiveKey, CString &strSubKey)
{
	try
	{
		bool bFound = false;
	
		CString csSubKey;
		CStringArray csSubKeyArr ;
		m_objReg.EnumSubKeys( csMainKey , csSubKeyArr , hHiveKey ) ;
		
		for ( long i = 0 ; i < csSubKeyArr . GetCount ( ) ; i ++ )
		{
			csSubKey = csSubKeyArr.GetAt(i);
			csSubKey.MakeLower();
			int iRet = csSubKey.Replace(_T("b{"),_T("{"));
			if ( csSubKey.Find( csCompare.MakeLower()) != -1)
			{
				if(iRet == 0)			
					strSubKey = csSubKey;
				else
					strSubKey = _T("b")+csSubKey;
				bFound = true;
				break ;
			}		
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckRegKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumAndReportCOMKeys
	In Parameters	: const CString& CString , const CString& CString 
	Out Parameters	: bool
	Purpose			: Checks subkeys for given string
	Author			: 
	Description		: enumerates all keys, values, data ( for files ) and report to UI
--------------------------------------------------------------------------------------*/
void CSplSpyScan :: EnumAndReportCOMKeys ( ULONG ulSpywareName, const CString& csKey, HKEY hKeyHive , const bool bCheckFiles )
{
	try
	{
		// variable declarations
		int i = 0 , iTotalCount = 0 ;
		BOOL bRetValue = false ;
		CString csWorm , csHive ;
		CStringArray csArrSubKeys ;
		//CStringArray csArrValues , csArrData ;

		bRetValue = m_objReg . KeyExists ( csKey , hKeyHive ) ;
		if ( !bRetValue )
			return ;
		SendScanStatusToUI ( Special_RegKey, ulSpywareName,hKeyHive, csKey, 0, 0, 0,0) ;		

		if ( bCheckFiles )
		{
			// check if the key was com file location and has a valid filename
			int iSlashIndex = 0 ;
			CString csOnlyKeyName ;

			iSlashIndex = csKey . ReverseFind ( '\\' ) ;
			if ( -1 != iSlashIndex )
				csOnlyKeyName = csKey . Right ( csKey.GetLength() - iSlashIndex - 1 ) ;

			if ( csOnlyKeyName . GetLength() > 0 )
			{
				if ( ( 0 == csOnlyKeyName . CompareNoCase ( _T("InprocServer32") ) ) ||
					 ( 0 == csOnlyKeyName . CompareNoCase ( _T("LocalServer32") ) ) ||
					 ( 0 == csOnlyKeyName . CompareNoCase ( _T("LocalServer") ) ) ||
					 ( 0 == csOnlyKeyName . CompareNoCase ( _T("InprocServer") ) ) )
				{
					CString csValue ;
					TCHAR szFilename [ MAX_PATH ] = { 0 } ;
					CFileVersionInfo objFileVersionInfo;

					m_objReg . Get ( csKey , BLANKSTRING , csValue , hKeyHive ) ;
					_tsearchenv_s ( csValue , _T("path") , szFilename , _countof ( szFilename ) ) ;

					if ( objFileVersionInfo . DoTheVersionJob ( szFilename , false ) )
					{
						SendScanStatusToUI ( Special_File, ulSpywareName , szFilename  ) ;
					}
				}
			}
		}

		// enumerate all keys inside this key
		bRetValue = m_objReg . EnumSubKeys ( csKey , csArrSubKeys , hKeyHive ) ;

		iTotalCount = (int)csArrSubKeys . GetCount() ;
		if ( iTotalCount > 0 )
		{
			for ( i = 0 ; i < iTotalCount ; i++ )
				EnumAndReportCOMKeys ( ulSpywareName , csKey + L"\\" + csArrSubKeys [ i ] , hKeyHive , bCheckFiles ) ;
		}

		// enumerate all values and data inside this key
        vector<REG_VALUE_DATA> vecRegValues;
	    m_objReg.EnumValues(csKey, vecRegValues, hKeyHive);        
		//bRetValue = m_objReg . QueryDataValue ( csKey , csArrValues , csArrData , hKeyHive,ptrDataTypes,iDataTypeSize) ;

		iTotalCount = (int)vecRegValues.size();
		for ( i = 0 ; i < iTotalCount ; i++ )
		{	
			SendScanStatusToUI (Special_RegVal, ulSpywareName ,hKeyHive, csKey ,  vecRegValues [ i ].strValue  ,vecRegValues [ i ].Type_Of_Data ,vecRegValues [ i ].bData,vecRegValues [ i ].iSizeOfData ) ;			
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::EnumAndReportCOMKeys, Error : %d and %s ") ,GetLastError(), static_cast < LPCTSTR > ( csKey ) );
		AddLogEntry(csErr,0,0) ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: IsStopScanningSignaled
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: Get stop scanning status
	Author			: Anand
	Description		: forward the call to scanner wrapper and get the stop scanning status
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: IsStopScanningSignaled()
{
	if ( m_pSplSpyWrapper )
		return m_pSplSpyWrapper -> IsStopScanningSignaled() ;
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: AddToCompulsoryDeleteOnRestartList
	In Parameters	: int, ULONG,CString
	Out Parameters	: bool
	Purpose			: Compulsory add in delet list
	Author			: Anand
	Description		: Compulsory add in delet list
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: AddToCompulsoryDeleteOnRestartList(int iVal, ULONG m_ulSpyName, const CString& csEntry)
{
	if ( m_pSplSpyWrapper )
		return m_pSplSpyWrapper -> AddToCompulsoryDeleteOnRestartList( iVal, m_ulSpyName, csEntry) ;
	return ( true ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckToCheckOtherLocations
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: Check if other locations available
	Author			: Anand
	Description		: Check and set path for other sys,pfdir and reg node values
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckToScanOtherLocations()
{
	m_bScanOtherLocations = (CSystemInfo::m_bIsOSX64 == FALSE ? false : true); //checking for 64-bit OS

#ifdef WIN64
	m_bScanOtherLocations = true;
#endif
	

	if ( m_bScanOtherLocations )
	{
		if ( m_pSplSpyWrapper )
			m_pSplSpyWrapper -> DisableFileSystemRedirection() ;

		//Version: 2.5.0.35
		//Description: deleted unwanted code of calling APIs
		//Resource: Anand
		m_csOtherSysDir = CSystemInfo::m_strSysWow64Dir ;
		m_csOtherPFDir = CSystemInfo::m_strProgramFilesDirX64 ;
	}

	return true;
}

void CSplSpyScan::CreateWormstoDeleteINI(CString strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Rename", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Replace", L"WormCnt", L"0", strINIPath);
	}
}

BOOL CSplSpyScan::AddInRestartDeleteList(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue)
{
	BOOL bRet = false;
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	WCHAR strCount[50] = {0};
	WCHAR strValue[MAX_PATH*4] = {0};
	LPTSTR lpszSection = NULL;
	WCHAR *szSection[8] = {L"File_Delete", L"File_Backup", L"Folder", L"RegistryKey",
							L"RegistryValue",L"RegistryData", L"File_Rename", L"File_Replace"};

	if(eRD_Type == RD_FILE_DELETE)
		lpszSection = szSection[0];
	else if ( eRD_Type == RD_FILE_BACKUP)
		lpszSection = szSection[1];
	else if ( eRD_Type == RD_FOLDER )
		lpszSection = szSection[2];
	else if ( eRD_Type == RD_KEY )
		lpszSection = szSection[3];
	else if ( eRD_Type == RD_VALUE )
		lpszSection = szSection[4];
	else if ( eRD_Type == RD_DATA)
		lpszSection = szSection[5];
	else if ( eRD_Type == RD_FILE_RENAME)
		lpszSection = szSection[6];
	else if ( eRD_Type == RD_FILE_REPLACE)
		lpszSection = szSection[7];

	if(lpszSection == NULL)
		return FALSE;

	CreateWormstoDeleteINI(strINIPath);

	UINT ulWormCnt = GetPrivateProfileIntW(lpszSection, L"WormCnt", 0, strINIPath);
	wsprintf(strCount, L"%d", ++ulWormCnt);
	WritePrivateProfileStringW(lpszSection, L"WormCnt", strCount, strINIPath);

	wsprintf(strValue, L"%ld^%s", ulSpyNameID, szValue);
	WritePrivateProfileStringW(lpszSection, strCount, strValue, strINIPath);
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: QuarantineFile
In Parameters	: CString csSpywareName - Spyware name
				  CString csSpyValue - Spyware value
Out Parameters	: bool
Purpose			: Nullify given file 
Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: QuarantineFile ( ULONG ulSpywareName , const CString& csSpyValue )
{
	AddInRestartDeleteList(RD_FILE_DELETE, ulSpywareName, csSpyValue);
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForKeyLoggerKeys
	In Parameters	: CString , CString
	Out Parameters	: 
	Purpose			: Check and fix random key Spyware
	Author			: Ritesh
	Description		: checks and remove random key entry from registry
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckForKeyLoggerKeys ( CString csRandomNumber , CString csFileName , ULONG ulSpywareName , CString csSpyToSearch )
{
	try
	{
		bool bFlag = false ;

		if ( csRandomNumber.IsEmpty() )
			return false ;

		//Create Key Path 
		CStringArray csSubKeys ;
		CRegistry objReg ;
		CString csData = L"" ;
		CString csFullKey = CString(APP_PATH) + CString(_T("\\")) + csFileName + csRandomNumber + CString(_T(".exe}")) ;

		//Check Existence Of Key
		if ( objReg.KeyExists( csFullKey , HKEY_LOCAL_MACHINE ) )
		{
			//report to UI
			EnumKeynSubKey ( CString(HKLM) + CString(_T("\\")) + csFullKey , ulSpywareName ) ;
			bFlag = true ;
		}
		
		for ( int i = 0 ; ; i++ )
		{
			csFullKey . Empty() ;
			csSubKeys . RemoveAll() ;

			if ( i == 0 )
				csFullKey . Format ( L"SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application" ) ;
			else
				csFullKey . Format ( L"SYSTEM\\ControlSet%03i\\Services\\Eventlog\\Application" , i ) ;

			if ( !m_objReg . KeyExists ( csFullKey , HKEY_LOCAL_MACHINE ) )
				break ;

			if ( !m_objReg . EnumSubKeys ( csFullKey , csSubKeys , HKEY_LOCAL_MACHINE ) )
				break ;
			
			for ( int j = 0 , count = (int) csSubKeys . GetCount() ; j < count ; j++ )
			{
				if ( csSubKeys.GetAt( j ).Find ( L"RdLst") == -1 )
					continue ;

				CString csFullKeyToCheck ;

				csFullKeyToCheck = csFullKey + L"\\" + csSubKeys [ j ] ;
				m_objReg . Get ( csFullKeyToCheck , L"EventMessageFile" , csData , HKEY_LOCAL_MACHINE ) ;

				if ( csData.GetLength() > 1 )
				{
					if ( StrStrI ( csData , csSpyToSearch ) )
					{
						//report to UI
						EnumKeynSubKey ( CString(HKLM) + CString(_T("\\")) + csFullKeyToCheck , ulSpywareName ) ;
						bFlag = true ;
						break ;
					}
				}
			}
		}

		return ( bFlag ) ;
	}

	catch(...)
	{
		AddLogEntry ( L"Exception caught in CSplSpyScan::CheckForKeyLoggerKeys" , 0 , 0 );
	}

	return false ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForKeyLoggerFiles
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: check and fix random files Spyware
	Author			: Ritesh
	Description		: checks and removes random .ini entry from windows directory
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckForKeyLoggerFiles ( const CString & csRandomNumber , ULONG ulSpywareName , const CString & csSubFolderName ,const CString & csRandomVersion , const CString & csSpy)
{
	try
	{
		bool bFlag = false ; 

		if ( csRandomNumber.IsEmpty() )
			return false ;

		//Create File Path 
		CString csPcmnFilePath , csPclnFilePath , csStartMenuFile ,csDesktopFile;
		TCHAR szPath [ MAX_PATH ] = { 0 } ;
		
		csPcmnFilePath = CSystemInfo::m_strWinDir + L"\\" + L"pcmn" + csRandomNumber + L".ini" ;
		csPclnFilePath = CSystemInfo::m_strWinDir + L"\\" + L"pcln" + csRandomNumber + L".ini" ;

		//Check Existence Of File
		if ( ! _taccess_s ( csPcmnFilePath , 00 ) )
		{
			SendScanStatusToUI ( Special_File, ulSpywareName , csPcmnFilePath );	
			bFlag = true ;
		}

		//Report to UI if file Exist
		if ( ! _taccess_s ( csPclnFilePath , 00 ) )
		{
			SendScanStatusToUI ( Special_File, ulSpywareName , csPclnFilePath  );
			bFlag = true ;
		}

		if ( SUCCEEDED( SHGetFolderPath ( 0, CSIDL_PROGRAMS ,0 , 0, szPath) ) )
		{
			csStartMenuFile = szPath ; 
			csStartMenuFile = csStartMenuFile + CString(BACK_SLASH) + csSubFolderName ;
			if ( !_taccess_s ( csStartMenuFile ,0))
			{
				RemoveFolders( csStartMenuFile , ulSpywareName , false );
			}
		}

		if ( SUCCEEDED( SHGetFolderPath ( 0, CSIDL_DESKTOPDIRECTORY  , 0 , 0, szPath )))
		{
			csDesktopFile = szPath ; 
			csDesktopFile = csDesktopFile + CString(BACK_SLASH) + csSpy + _T(" ") + csRandomVersion + _T(".lnk") ;
			if ( !_taccess_s ( csDesktopFile ,0))
			{
				SendScanStatusToUI ( Special_File, ulSpywareName , csDesktopFile  );
				bFlag = true ;
			}
		}

		return bFlag ;
	}

	catch(...)
	{
		AddLogEntry ( L"Exception caught in CSplSpyScan::CheckForKeyLoggerKeys" , 0 , 0 ) ;
	}

	return false ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRandomEntry
	In Parameters	: CString, CString, CString, CString, CStringArray, CString
	Out Parameters	: bool
	Purpose			: check and fix random key of spyware
	Author			: Ritesh
	Description		: checks and scan random registry key entry of spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckRandomEntry ( CString csSpyentry , CString csRandomNumber , CString csRandomVersion , ULONG ulSpywareName , CStringArray &csArrServiceKeys , CString csSubFolderName )
{
	try
	{
		bool bFlag = false ; 

		if ( csRandomNumber.IsEmpty() || csRandomVersion .IsEmpty () )
			return false ;

		//Create Key Path 
		CRegistry objReg ;
		CString csRandomNumberFullKey = SERVICES_MAIN_KEY + csSpyentry + csRandomNumber ;
		CString csRandomVersionKey1 = _T("Software\\pcs-") + csRandomVersion ;
		CString csRandomVersionKey2 = CString(CURRENTVERSION_PATH) + CString(_T("Uninstall\\")) + csSubFolderName ;
		CString csSid;
		CExecuteProcess objExecProc;

		csSid = objExecProc.GetCurrentUserSid();

		//Check Existence Of Key		
		if ( objReg.KeyExists( csRandomVersionKey1 , HKEY_LOCAL_MACHINE ) )
		{
			EnumKeynSubKey ( CString(HKLM) + CString(_T("\\")) + csRandomVersionKey1 , ulSpywareName ) ; 
			bFlag = true ;
		}

		if ( objReg.KeyExists( csSid + CString(BACK_SLASH) + csRandomVersionKey1 , HKEY_USERS ) )
		{
			EnumKeynSubKey ( CString(HKU) + CString(_T("\\")) + csSid + CString(BACK_SLASH) + csRandomVersionKey1 , ulSpywareName ) ; 
			bFlag = true ;
		}

		if ( objReg.KeyExists( csRandomVersionKey2 , HKEY_LOCAL_MACHINE ) )
		{
			EnumKeynSubKey ( CString(HKLM) + CString(_T("\\")) + csRandomVersionKey2 , ulSpywareName ) ; 
			bFlag = true ;
		}

		if ( objReg.KeyExists( csRandomNumberFullKey , HKEY_LOCAL_MACHINE ) )
		{
			CheckAndRemoveDriver ( ulSpywareName , csSpyentry + csRandomNumber , csRandomNumberFullKey , csArrServiceKeys , false ) ;
			bFlag = true ;
		}

		return ( bFlag ) ;
	}

	catch(...)
	{
		AddLogEntry ( L"Exception caught in CSplSpyScan::CheckRandomEntry" , 0 , 0 );
	}

	return false ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckforUninstallKey
	In Parameters	: CString, CString, CString, CString
	Out Parameters	: bool
	Purpose			: check and fix random key of spyware in App Path
	Author			: Shwetam
	Description		: checks and scan random registry key entry of spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckForUninstallKey ( const CString& csRandomNumber , ULONG  ulSpywareName , const CString& csMainFolder)
{
	try
	{
		CString csAppPath ;
		
		csAppPath = UNINSTALL_PATH + CString(BACK_SLASH) + csMainFolder + _T(" ") + csRandomNumber ;
		
		if ( m_objReg.KeyExists ( csAppPath , HKEY_LOCAL_MACHINE ) )
		{
			EnumKeynSubKey ( HKLM + CString(BACK_SLASH) + csAppPath , ulSpywareName ) ;
			return true;
		}
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSplSpyScan::CheckforAppPath, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: RandomVersion
	In Parameters	: CString , CString & , CString & 
	Out Parameters	: bool
	Purpose			: get random number 
	Author			: Ritesh
	Description		: get random number from spyware folder
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: RandomVersion (const CString & csFolderName , CString & csRandomVersion , CString & csSubFolderName , CString & csRandomVersionWithDot ,const CString & csKeyName)
{
	CFileFind	objFile ;
	BOOL	bMoreFiles = FALSE ;
	CString csRandomNumber = _T("") ;
	csRandomVersion = _T("") ;
	csSubFolderName = _T("") ;

	bMoreFiles = objFile.FindFile( csFolderName + _T("\\*.*") ) ;
	
	while( bMoreFiles)
	{
		bMoreFiles = objFile.FindNextFile();
		if ( objFile.IsDots() || ! objFile.IsDirectory() )
			continue ;
	
		if ( StrStrI ( objFile . GetFilePath() , csKeyName) )
		{		
			csSubFolderName = objFile . GetFileName() ;

			csRandomNumber = csSubFolderName .Right ( csSubFolderName .GetLength() - csSubFolderName .Find( _T(" ") , 0 ) - 1 ) ;
			csRandomNumber . Trim ( _T(" ") ) ;
			csRandomVersionWithDot = csRandomNumber ;
			csRandomNumber .Replace ( _T(".") , _T("") ) ;
			csRandomVersion = csRandomNumber  ;	
			objFile.Close();
			return true ;
			
		}
	}
	objFile.Close();
	return false ;
}

/*--------------------------------------------------------------------------------------
Function       : CSplSpyScan::PrepareMD5String
In Parameters  : CString &csSignature, LPBYTE MD5Signature
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 26 Jan, 2010.
--------------------------------------------------------------------------------------*/
void CSplSpyScan::PrepareMD5String(CString &csSignature, LPBYTE MD5Signature)
{
	csSignature.Format(L"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
						MD5Signature[0], MD5Signature[1], MD5Signature[2], MD5Signature[3],
						MD5Signature[4], MD5Signature[5], MD5Signature[6], MD5Signature[7],
						MD5Signature[8], MD5Signature[9], MD5Signature[10], MD5Signature[11],
						MD5Signature[12], MD5Signature[13], MD5Signature[14], MD5Signature[15]);
	csSignature.MakeUpper();
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	Function		: CheckForFileMD5
	In Parameters	: HKEY , CString & , CStringArray & , CStringArray & , CString & , CString  & , bool , bool , CFileSignatureDb *, bool 
	Out Parameters	: Bool
	Purpose			: To Compare MD5 values ,File Path and File name . with respect to given registry value. 
	Author			: Nitin Shekokar
	Description		: Calculate MD5 value of given registry value and matches with Black MD5 Value array
					  It also Compare black file path value with given registry value. 
				   	  NOTE : Only and only spyware in full scan can call this function.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckForFileMD5 ( HKEY hHive, CString & csRegKey , CStringArray & csArrRegValue ,CStringArray & csArrBlackMD5, CString & csBlackFilePath, CString  & csBlackFilename, bool bReportFullKey, bool bReportValue, CFileSignatureDb *pFileSigMan, bool bToDelete)
{
	m_pFileSigMan = pFileSigMan;
	CString csData;
	CString csSignature;
	CString csOnlyFilename;
	bool bFlag = false;
	CString csTemp = _T("");
	CString csTemp1 = _T("");
	TCHAR szOnlyFilename [ MAX_PATH ] = { 0 } ;
	CString csHive =  m_objReg.RootKey2String(hHive);

	if ( !m_objReg . KeyExists ( csRegKey , hHive ) )
		return false;

	for(int iValue = 0 ; iValue < csArrRegValue.GetCount() ; iValue++)
	{
		m_objReg.Get(csRegKey,csArrRegValue.GetAt(iValue),csData,hHive);
		if (csData != _T(""))
		{
			if ( !csBlackFilename.IsEmpty() ) //2.5.0.59 //Fix  desktop issue
			{
				if( (_taccess_s ( csBlackFilename , 0 ) == 0))
				{
					csBlackFilename.MakeUpper();
					_tsplitpath_s ( csData , 0 , 0 , 0 , 0 , szOnlyFilename , 0 , 0 , 0 ) ;
					csOnlyFilename =szOnlyFilename;
					csOnlyFilename.MakeUpper();

					if (csOnlyFilename == csBlackFilename)
					{
						if(csData == csBlackFilePath)
						{
							bFlag = true;
						}
					}
				}
			}

			if ( csArrBlackMD5.GetCount() <= 0 )
				continue;
			
			if( (_taccess_s ( csData , 0 ) == 0))
			{
				CString csSignature;
				BYTE byMD5Sig[16] = {0};
				if(m_pFileSigMan->GetMD5Signature(csData, byMD5Sig))
				{
					PrepareMD5String(csSignature, byMD5Sig);
					for(int iCount = 0 ; iCount < csArrBlackMD5.GetCount() ; iCount++)
					{
						csTemp = csArrBlackMD5.GetAt(iCount);
						csTemp.MakeUpper();
						if( csTemp == csSignature )
						{
							bFlag = true;
						}
					}
				}
			}
		}
		if ( bFlag  && !bToDelete )
		{
			SendScanStatusToUI ( Special_File, m_ulSpyName, csData  ) ;
            //TODO:Add regFix Scanner
			//SendScanStatusToUI ( Special_RegDataFix_Scanner, m_ulSpyName , csHive + csRegKey + CString(BACK_SLASH) + csArrRegValue.GetAt(iValue) + CString(BACK_SLASH) + csData  ) ;
			if (bReportFullKey)
			{
				SendScanStatusToUI ( Special_RegKey , m_ulSpyName ,hHive , csRegKey + CString(BACK_SLASH) + csArrRegValue.GetAt(iValue),0,0,0,0  ) ;
			}
			if (bReportValue)
			{
				SendScanStatusToUI ( Special_RegVal, m_ulSpyName , hHive, csRegKey ,  csArrRegValue.GetAt(iValue) , 0 ,0,0 ) ;
			}
		}
		else if ( bFlag )
		{
			m_objReg.Set(csRegKey,csArrRegValue.GetAt(iValue),csTemp1,hHive);
		}

	} //End of for loop
	
	if(bFlag)
	{
		return (true);
	}
	return (false);
}
/*-------------------------------------------------------------------------------------
	Function		: RegfixData
	In Parameters	: HKEY hHive, CString csKey, CString csValue, CString csData, CString csNewData, CString csSpywareName )
	Out Parameters	: bool
	Purpose			: Regfix the entry of Virus Alert
	Author			: Shweta Mulay
	Description		: To check for the regfix entry and if found send it to UI 
	version			: 2.5.0.57
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: RegfixData ( HKEY hHive, const CString& csKey, const CString& csValue, CString csData, const CString& csNewData, ULONG ulSpywareName )
{
	CString csRetrivedData ;

	if (! m_objReg.Get(csKey ,  csValue , csRetrivedData , hHive ) )
		return ( false ) ;

	csRetrivedData.MakeLower(); csData.MakeLower();

	if ( csRetrivedData != csData ) 
		return ( false ) ;
	
	CString csWorm;
	if ( hHive == HKEY_USERS  ) 
		csWorm = HKU + CString(BACK_SLASH) + csKey + REG_SEPERATOR  + csValue + REG_SEPERATOR  + csData + _T(" | ") + csNewData ;
	else if ( hHive == HKEY_LOCAL_MACHINE ) 
		csWorm = HKLM + CString(BACK_SLASH) + csKey + REG_SEPERATOR  + csValue + REG_SEPERATOR + csData + _T(" | ") + csNewData ;

     //TODO:Add regFix Scanner
	//SendScanStatusToUI ( ulSpywareName , csWorm , Special_RegDataFix_Scanner );
	return ( true ) ;

}
/*-------------------------------------------------------------------------------------
	Function		: EnumFolder
	In Parameters	: CString , CStringArrar ,CString, int , bool
	Out Parameters	: bool
	Purpose			: Enumerate
	Author			: Shweta Mulay
	Description		: To check for the regfix entry and if found send it to UI 
	version			: 2.5.0.70
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: EnumFolder ( const CString & csFolder , CStringArray &csArrFolder , ULONG ulSpywareName, int iDepth , bool bReprtToUI )
{
	bool bFound = false;

	try
	{
		CFileFind objFileFind ; 
		int icurrentDepth = 0;

		if ( iDepth == -1 )
			return false;
		
		bFound = (objFileFind.FindFile(csFolder + _T("\\*.*")) == FALSE ? false : true);
		
		if ( !bFound )
		{
			objFileFind.Close();
			return false;
		}
		
		while ( bFound )
		{
			bFound = (objFileFind.FindNextFile() == FALSE ? false : true);

			if ( objFileFind.IsDots() )
				continue;

			if ( objFileFind.IsDirectory() )
			{
				EnumFolder ( objFileFind.GetFilePath() , csArrFolder , ulSpywareName , iDepth -1 );
				if ( bReprtToUI )
					SendScanStatusToUI ( Special_Folder , ulSpywareName , objFileFind.GetFilePath());
			}	
			else
			{
				csArrFolder.Add ( objFileFind.GetFilePath() );
				if ( bReprtToUI )
					SendScanStatusToUI ( Special_File, ulSpywareName , objFileFind.GetFilePath() );
			}
		}
		objFileFind.Close() ;
		return true;
	}
	catch(...)
	{
		
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckIfValidExtension
	In Parameters	: CString , CString
	Out Parameters	: bool
	Purpose			: Check if valis extension is there
	Author			: Shweta Mulay
	Description		: To check if the file has valid extension.
	version			: 2.5.0.70
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckIfValidExtension ( const CString & csFileName , const CString &csExt ) 
{
	try
	{
		//Always must be in the firmat " .exe , .db or .dll and in lowercase.
		int ipos;
		csExt.GetLength();
		ipos = csFileName.Find ( csExt );
		if ( ipos == -1 )
			return false;
		else if ( ipos == ( csFileName.GetLength() - csExt.GetLength() ) )
			return true ;
		else
			return false;
	}
	catch(...)
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in  CSplSpyScan :: CheckIfValidExtension, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckVersionInfo
	In Parameters	: CString , int ,CString
	Out Parameters	: bool
	Purpose			: Check if valis extension is there
	Author			: Shweta Mulay
	Description		: To check if the file version info matches spyware info.
						Version Info As
						1 = CompanyName
						2 = Internal File name
						3 = Description
	version			: 2.5.0.70
--------------------------------------------------------------------------------------*/
bool CSplSpyScan :: CheckVersionInfo ( const CString &csFileName , int iVersionOption , const CString &csActualVersionInforequired )
{
	bool bFoundFlag = false;

	try
	{
		CFileVersionInfo objFVerInfo;
		TCHAR csCompanyName[MAX_PATH] , csInterName[MAX_PATH] , csDescription[MAX_PATH] ;

		switch ( iVersionOption )
		{
		case 1: 
			objFVerInfo.GetCompanyName ( csFileName , csCompanyName );
			if ( csCompanyName == csActualVersionInforequired )
				bFoundFlag = true ;
			break;
		case 2:
			objFVerInfo.GetInternalNameofFile( csFileName , csInterName );
			if ( csInterName == csActualVersionInforequired )
				bFoundFlag = true ;
			break;
		case 3:
			objFVerInfo.GetFileDescription ( csFileName , csDescription );
			if ( csInterName == csActualVersionInforequired )
				bFoundFlag = true ;
			break;
		default:
			ASSERT(0 && "Unhandled VersionOption in CSplSpyScan :: CheckVersionInfo(...)");
		}
		//if ( bFoundFlag )
		//	return true;
		//else
		//	return false;
	}
	catch(...)
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in  CSplSpyScan :: CheckVersionInfo, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}

	return bFoundFlag;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDrivesToScan
	In Parameters	: CString&
	Out Parameters	: void
	Purpose			: get the drives to scan
	Author			: Anand Srivastava
	Description		: get the drives to scan
	version			: 2.5.0.76
--------------------------------------------------------------------------------------*/
void CSplSpyScan :: GetDrivesToScan ( CString & csDrivesToScan )
{
	csDrivesToScan = m_pSplSpyWrapper -> m_csDrivesToScan ;
}

void CSplSpyScan::LoadAvailableUsers()
{
	HKEY hMainkey = NULL;
	CString csMainKey(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, csMainKey, 0, KEY_READ, &hMainkey) != ERROR_SUCCESS)
		return;

	DWORD LengthOfLongestSubkeyName = 0;
	DWORD dwSubKeyCount = 0;			// number of subkeys 

	//To detemine MAX length
	if(RegQueryInfoKey(hMainkey, NULL, NULL, NULL, &dwSubKeyCount, &LengthOfLongestSubkeyName, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
	{
		RegCloseKey( hMainkey);
		return;
	}

	DWORD  LengthOfKeyName = LengthOfLongestSubkeyName;
	LPWSTR lpKeyName = NULL;

	lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR));
	if ( NULL == lpKeyName )
	{
		RegCloseKey( hMainkey);
		return;
	}

	DWORD idxKey = 0, NTr = 0;

	csMainKey += L"\\";
	for(idxKey = 0; idxKey < dwSubKeyCount ;idxKey++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		LengthOfKeyName = LengthOfLongestSubkeyName + 1;
		SecureZeroMemory(lpKeyName, (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR));
		NTr = RegEnumKeyEx(hMainkey, idxKey, (LPWSTR)lpKeyName, &LengthOfKeyName, NULL, NULL, NULL, NULL);
		
		if(NTr == ERROR_NO_MORE_ITEMS)
			break;
		// ignore entry which could not be retrieved as the buffer provided was small
		else if(NTr == ERROR_MORE_DATA) 
			continue;
		else if(NTr != ERROR_SUCCESS)
			break;
		else if(NTr == ERROR_SUCCESS)
		{
			if(LengthOfKeyName == 0)
				continue;

			if(LengthOfKeyName > MAX_PATH)
			{
				CString csOut;
				csOut.Format(L"Skipping long key with len: %d, Key: %s", LengthOfKeyName, csMainKey);
				OutputDebugString(csOut);
			}

			WCHAR wchData[MAX_PATH] = {0};
			DWORD dwSizeBuffer = MAX_PATH * sizeof(TCHAR);
			DWORD dwTypeOfData = REG_SZ;

			QueryRegData(csMainKey + lpKeyName, L"ProfileImagePath", dwTypeOfData, (LPBYTE)wchData, dwSizeBuffer, HKEY_LOCAL_MACHINE);
			if(wcslen(wchData) > 0)
			{
				CString csProfilePath(wchData);
				csProfilePath = m_oDBPathExpander.ExpandSystemPath(csProfilePath);
				m_objAvailableUsers.AppendItem(lpKeyName, csProfilePath);

				HKEY hUserKey = NULL;
				if(RegOpenKeyEx(HKEY_USERS, lpKeyName, 0, KEY_READ, &hUserKey) == ERROR_SUCCESS)
				{
					RegCloseKey(hUserKey);
				}
				else
				{
					m_oRegistry.LoadKey(HKEY_USERS, lpKeyName, csProfilePath + L"\\NTUser.dat");
				}
			}
		}
	}

	GlobalFree(lpKeyName);
	RegCloseKey(hMainkey);

	m_objAvailableUsers.AppendItem(L".default", m_oDBPathExpander.GetDefaultUserPath());
	m_objAvailableUsers.AppendItem(L"All Users", m_oDBPathExpander.GetAllUsersPath());
}

bool CSplSpyScan::QueryRegData(LPCWSTR strKeyPath, LPCWSTR strValueName, DWORD &dwDataType, LPBYTE lpbData, DWORD &dwBuffSize, HKEY HiveRoot)
{
    DWORD dwSize = MAX_PATH;
    HKEY hKey = NULL;
    DWORD dwType = REG_SZ;

    if(::RegOpenKeyEx(HiveRoot, strKeyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) 
        return false;

    LONG lReturn = RegQueryValueEx(hKey, strValueName, NULL, &dwType, NULL, &dwSize);
    if(lReturn != ERROR_SUCCESS)
    {
        ::RegCloseKey(hKey);
        return false;
    }

    if(((dwType != REG_SZ) && (dwType != REG_EXPAND_SZ) && (dwType != REG_MULTI_SZ) && (dwType != REG_DWORD)) || (dwSize == 0))
    {
        ::RegCloseKey(hKey);
        return false;
    }

    LPBYTE pData = new BYTE[dwSize];
    memset(pData, 0, dwSize);
    lReturn = RegQueryValueEx(hKey, strValueName, NULL, &dwType, pData, &dwSize);
    if(lReturn != ERROR_SUCCESS)
    {
        ::RegCloseKey(hKey);
        return false;
    }
    ::RegCloseKey(hKey);

	dwDataType = dwType;
	if(dwBuffSize > dwSize)
	{
		memcpy_s(lpbData, dwBuffSize, pData, dwSize); 	//the size of pData is in BYTE's
		dwBuffSize = dwSize;
	}
	else
	{
		CString csOut;
		csOut.Format(L"Skipping long value data with len: %d, Key: %s, Value: %s", dwSize, strKeyPath, strValueName);
		OutputDebugString(csOut);
		dwBuffSize = 0;
	}

	delete [] pData;
    pData = NULL;
    return true;
}
void CSplSpyScan::CallToStatusBarFucn()
{
	CRegistry objReg;
	DWORD dwStatusbar;

	dwStatusbar = 0;
	objReg.Get(CSystemInfo::m_csProductName, _T("StatusBar"),dwStatusbar, HKEY_LOCAL_MACHINE); 			
    if(dwStatusbar)
	    m_bStatusbar = true;

}

/*-------------------------------------------------------------------------------------
Function		: GetFilePathFromRegData
In Parameters	: LPCTSTR szRegData, CString& csFilePath
Out Parameters	: bool
Purpose			: get file path from given reg data read from run registry values
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetFilePathFromRegData(LPCTSTR szRegData, CString& csFilePath)
{
	bool bFilePathFound = false;
	TCHAR szFilePath[MAX_PATH] = {0};
	LPCTSTR Ptr = NULL, StartPtr = NULL, EndPtr = NULL;

	if(Ptr = _tcsstr(szRegData, _T("rundll32.exe\"")))
	{
		Ptr += _tcslen(_T("rundll32.exe\""));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32.exe")))
	{
		Ptr += _tcslen(_T("rundll32.exe"));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32\"")))
	{
		Ptr += _tcslen(_T("rundll32\""));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32")))
	{
		Ptr += _tcslen(_T("rundll32"));
	}
	else
	{
		Ptr = szRegData;
	}

	for(; Ptr && *Ptr; Ptr++)
	{
		if(NULL == StartPtr)
		{
			if((_T(' ') != *Ptr) && (_T('"') != *Ptr))
			{
				StartPtr = Ptr;
			}
		}
		else
		{
			if(_T('"') == *Ptr)
			{
				EndPtr = Ptr;
				break;
			}
			else if(!_tcsnicmp(Ptr, _T(".exe"),4)||!_tcsnicmp(Ptr, _T(".com"),4)||!_tcsnicmp(Ptr, _T(".scr"),4))
			{
				EndPtr = Ptr + 4;
				break;
			}
		}
	}

	if(!StartPtr || !EndPtr || StartPtr >= EndPtr)
	{
		return bFilePathFound;
	}

	if(EndPtr - StartPtr >= _countof(szFilePath))
	{
		return bFilePathFound;
	}

	_tcsncpy_s(szFilePath, _countof(szFilePath), StartPtr, EndPtr - StartPtr);

	if(_tcsrchr(szFilePath, _T('.')))
	{
		LPTSTR DotPtr = _tcsrchr(szFilePath, _T('.'));
		if(!_tcsnicmp(DotPtr, _T(".exe"), 4))
		{
			DotPtr [ 4 ] = 0;
		}
	}

	if((!_tcschr(szFilePath, _T('\\'))) && (!_tcschr(szFilePath, _T('/'))))
	{
		TCHAR szNewFilePath[MAX_PATH] = {0};
		_tsearchenv_s(szFilePath, _T("PATH"), szNewFilePath, _countof(szNewFilePath));
		if(0 != szNewFilePath[0])
		{
			_tcscpy_s(szFilePath, _countof(szFilePath), szNewFilePath);
		}
	}

	csFilePath = szFilePath;
	bFilePathFound = true;
	return bFilePathFound;
}

/*-------------------------------------------------------------------------------------
Function		: SearchStringsInFileU
In Parameters	: LPCTSTR szFilePath, CStringArray csArrStrList
Out Parameters	: bool
Purpose			: search the file for list of strings
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::SearchStringsInFileU(LPCTSTR szFilePath, const CStringArray& csArrStrList)
{
	int hFile = -1 ;
	int i = 1 , iStrFound = 0 ;
	bool bStringFound = false ;
	bool bAllEntriesFound = true ;
	char * pHold = NULL ;

	_tsopen_s ( &hFile , szFilePath , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
	if ( hFile == -1 )
	{
		return ( false ) ;
	}

	for ( i = 0 ; i < csArrStrList.GetCount() && bAllEntriesFound ; i++ )
	{
		bStringFound = false ;
		if ( !SearchString ( hFile , (LPBYTE)(LPCTSTR)csArrStrList[i],
							(csArrStrList[i].GetLength() * sizeof(TCHAR)), &bStringFound ) )
		{
			_close ( hFile ) ;
			return false;
		}

		bAllEntriesFound = bStringFound ? bAllEntriesFound : false ;
		if(IsStopScanningSignaled())
		{
			_close ( hFile ) ;
			return ( false ) ;
		}
	}

	_close ( hFile ) ;
	return ( bAllEntriesFound ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfSectionsPresent
	In Parameters	: LPCTSTR szFilePath, LPBYTE bySections, DWORD cbSections
	Out Parameters	: bool
	Purpose			: Check if file has the given sections
	Author			: Anand Srivastava
	Description		: return true if all sections are present
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::CheckIfSectionsPresent(LPCTSTR szFilePath, LPBYTE bySections, DWORD cbSections,
										 PIMAGE_DOS_HEADER_MSS pDosHeader, PIMAGE_NT_HEADERS_MSS pNtHeader,
										 PIMAGE_SECTION_HEADER_MSS pSecHdr, DWORD * pdwCount)
{
	bool bAllSectionsPresent = true, bFound = true;
	HANDLE hFile = 0;
	IMAGE_DOS_HEADER_MSS DosHeader = {0};
	IMAGE_NT_HEADERS_MSS NtHeader = {0};
	IMAGE_SECTION_HEADER_MSS SectionHeader[100] = {0};
	DWORD dwBytesRead = 0, dwBytesToRead = 0;

	hFile =	CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	ReadFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);
	if(dwBytesRead != sizeof(IMAGE_DOS_HEADER))
	{
		CloseHandle(hFile);
		return false;
	}

	if(pDosHeader)
	{
		memcpy(pDosHeader, &DosHeader, sizeof(DosHeader));
	}

	if(DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		CloseHandle(hFile);
		return false;
	}

	if(SetFilePointer(hFile, DosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return false;
	}

	ReadFile(hFile, &NtHeader, sizeof(IMAGE_NT_HEADERS), &dwBytesRead, NULL);
	if(dwBytesRead != sizeof(IMAGE_NT_HEADERS))
	{
		CloseHandle(hFile);
		return false;
	}

	if(pNtHeader)
	{
		memcpy(pNtHeader, &NtHeader, sizeof(NtHeader));
	}

	if(NtHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hFile);
		return false;
	}

	if(NtHeader.FileHeader.NumberOfSections > _countof(SectionHeader))
	{
		dwBytesToRead = _countof(SectionHeader) * sizeof(SectionHeader[0]);
	}
	else
	{
		dwBytesToRead = NtHeader.FileHeader.NumberOfSections * sizeof(SectionHeader[0]);
	}

	ReadFile(hFile, SectionHeader, dwBytesToRead, &dwBytesRead, 0);
	if(dwBytesToRead != dwBytesRead)
	{
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);
	if(pSecHdr && pdwCount)
	{
		DWORD i = 0;

		for(i = 0; i < *pdwCount && i < NtHeader.FileHeader.NumberOfSections; i++)
		{
			memcpy(pSecHdr + i, &SectionHeader[i], sizeof(SectionHeader[i]));
		}

		*pdwCount = i;
	}

	if(NULL == bySections || 0 == cbSections)
	{
		return false;
	}

	for(int i = 0, iTotal = cbSections / sizeof(SectionHeader->Name); i < iTotal; i++)
	{
		bFound = false;
		for(DWORD dwIndex = 0; dwIndex < NtHeader.FileHeader.NumberOfSections; dwIndex++)
		{
			if(0 == _memicmp(SectionHeader[dwIndex].Name, &bySections[i * sizeof(SectionHeader->Name)], sizeof(SectionHeader[dwIndex].Name)))
			{
				bFound = true;
				break;
			}
		}

		if(!bFound)
		{
			bAllSectionsPresent = false;
			break;
		}
	}

	return bAllSectionsPresent;
}

/*-------------------------------------------------------------------------------------
Function		: GetCurUserStartupPath
In Parameters	: CString& csStartupPath, bool bAllUser
Out Parameters	: bool
Purpose			: get 'C:\Documents and Settings\Currently Logged In User\Start Menu\Programs\Startup'
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetCurUserStartupPath(CString& csStartupPath, bool bAllUser)
{
	CExecuteProcess objExecProc;
	CString csCurUser, csData;

	if(bAllUser)
	{
		if(!m_objReg.Get(REG_SHELL_FOLDER, _T("Common Startup"), csStartupPath, HKEY_LOCAL_MACHINE))
		{
			return false;
		}
	}
	else
	{
		csCurUser = objExecProc.GetCurrentUserSid();
		if(BLANKSTRING == csCurUser)
		{
			return false;
		}

		if(!m_objReg.Get(csCurUser + BACK_SLASH + REG_SHELL_FOLDER, _T("Startup"), csStartupPath, HKEY_USERS))
		{
			return false;
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: GetCurUserStartMenuProgs
In Parameters	: CString& csStartMenuProgsPath, bool bAllUser
Out Parameters	: bool
Purpose			: get 'C:\Documents and Settings\Cur logged In User\Start Menu\Programs'
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetCurUserStartMenuProgs(CString& csStartMenuProgsPath, bool bAllUser)
{
	CExecuteProcess objExecProc;
	CString csCurUser, csData;

	if(bAllUser)
	{
		if(!m_objReg.Get(REG_SHELL_FOLDER, _T("Common Programs"), csStartMenuProgsPath, HKEY_LOCAL_MACHINE))
		{
			return false;
		}
	}
	else
	{
		csCurUser = objExecProc.GetCurrentUserSid();
		if(BLANKSTRING == csCurUser)
		{
			return false;
		}

		if(!m_objReg.Get(csCurUser + BACK_SLASH + REG_SHELL_FOLDER, _T("Programs"), csStartMenuProgsPath, HKEY_USERS))
		{
			return false;
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: GetCurUserDesktopPath
In Parameters	: CString& csCurUserDesktopPath, bool bAllUser
Out Parameters	: bool
Purpose			: get 'C:\Documents and Settings\Cur User\Desktop'
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSplSpyScan::GetCurUserDesktopPath(CString& csCurUserDesktopPath, bool bAllUser)
{
	CExecuteProcess objExecProc;
	CString csCurUser, csData;

	if(bAllUser)
	{
		if(!m_objReg.Get(REG_SHELL_FOLDER, _T("Common Desktop"), csCurUserDesktopPath, HKEY_LOCAL_MACHINE))
		{
			return false;
		}
	}
	else
	{
		csCurUser = objExecProc.GetCurrentUserSid();
		if(BLANKSTRING == csCurUser)
		{
			return false;
		}

		if(!m_objReg.Get(csCurUser + BACK_SLASH + REG_SHELL_FOLDER, _T("Desktop"), csCurUserDesktopPath, HKEY_USERS))
		{
			return false;
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: SetRestartFlag
In Parameters	: bool bSet
Out Parameters	: 
Purpose			: Set restart flag
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSplSpyScan::SetRestartFlag(bool bSet)
{
	if(m_pSplSpyWrapper)
	{
		m_pSplSpyWrapper->m_bRestartMachineAfterQuarantine = bSet;
	}
}
