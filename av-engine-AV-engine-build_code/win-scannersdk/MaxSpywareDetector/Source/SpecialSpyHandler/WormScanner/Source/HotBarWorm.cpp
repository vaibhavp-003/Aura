/*====================================================================================
   FILE				: HotBarWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware HotBar
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
					version: 2.5.0.32
					Resource : Shweta
					Description: Changed _CheckHotBarRandomEntries for function call CheckReportKeyValueData
========================================================================================*/

#include "pch.h"
#include <io.h>
#include <fcntl.h>
#include <sys\stat.h>
#include "HotBarWorm.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforHotBar
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Removes Run Entries
	Author			: 
	Description		: Removes registry entries under HKLM and HKCU of Software\HbTools
					  and searches strings entries in Run files
--------------------------------------------------------------------------------------*/
bool CHotBarWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return m_bSplSpyFound;

		CStringArray csRegLocations ;

		csRegLocations . Add ( _T("Software\\HBtools") ) ;
		if ( m_bScanOtherLocations )
			csRegLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("HBtools")) ) ;

		for ( int i = 0 ; i < csRegLocations . GetCount() ; i++ )
		{
			if( FindReportRegKey ( csRegLocations [ i ] , m_ulSpyName , HKEY_LOCAL_MACHINE, bToDelete ))
				m_bSplSpyFound = true;
		}

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;

			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			if(FindReportRegKey(csUserKey + _T("\\Software\\HBtools"), m_ulSpyName , HKEY_USERS, bToDelete))
				m_bSplSpyFound = true;
		}
 		
		CString			csData, csValue;
		CStringArray	csArrRegRunLocations ;

		csArrRegRunLocations . Add ( RUN_REG_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrRegRunLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;

		for ( int i = 0 ; i < csArrRegRunLocations . GetCount() ; i++ )
		{            
            vector<REG_VALUE_DATA> vecRegValues;
	        m_objReg.EnumValues(csArrRegRunLocations [ i ], vecRegValues, HKEY_LOCAL_MACHINE);

            for(size_t iCount=0; iCount < vecRegValues.size(); iCount++)
			{
                csValue = vecRegValues[iCount].strValue;
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[iCount].bData);

				CString csExt = csData.Right(3);
				if(csExt.MakeLower()==_T("exe"))
				{
					BYTE bMD5Signature[16] = {0};
					const BYTE MD5_HOTBAR[16] = {0xC3,0x36,0xD5,0xA8,0x93,0x3B,0xCC,0x3C,0xC6,0x5A,0x64,0xC3,0xA6,0xDF,0x87,0x72};
					if(m_pFileSigMan->GetMD5Signature(csData, bMD5Signature))
					{
						if(!memcmp(bMD5Signature, MD5_HOTBAR, 16))
						{
							if ( !bToDelete )
							{
								if ( m_objEnumProcess.IsProcessRunning ( csData , false ) )
									SendScanStatusToUI ( Special_Process ,  m_ulSpyName , csData  ) ;
								
								SendScanStatusToUI ( Special_File ,  m_ulSpyName, csData ) ;							
								SendScanStatusToUI ( Special_RegVal,m_ulSpyName, HKEY_LOCAL_MACHINE,csArrRegRunLocations [ i ], vecRegValues[iCount].strValue , vecRegValues[iCount].Type_Of_Data,vecRegValues[iCount].bData,vecRegValues[iCount].iSizeOfData);
							}
							m_bSplSpyFound = true;
							continue;
						}
					}
				}
			}
			if(IsStopScanningSignaled())
				return m_bSplSpyFound;

			bool bTempFound = false;
			// look for some strings in the file and decide if its a hotbar file
			_CheckIfHotBarFile ( csData.GetBuffer(csData.GetLength()), &bTempFound ) ;
			csData.ReleaseBuffer(); 

			if ( bTempFound && !bToDelete )
			{
				m_bSplSpyFound = true;
				if ( m_objEnumProcess . IsProcessRunning ( csData , false ) )
					SendScanStatusToUI ( Special_Process ,  m_ulSpyName , csData  ) ;
				
				SendScanStatusToUI ( Special_File ,  m_ulSpyName , csData );								                
                SendScanStatusToUI ( Special_RegVal,m_ulSpyName, HKEY_LOCAL_MACHINE,csArrRegRunLocations [ i ], csValue,  REG_SZ , (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
			}
		}


			//Version 19.0.0.10
			//Resource : Shweta
			//Description : Checking for random entries of registry and files for hotbar
			if ( m_bSplSpyFound && !bToDelete )
				_CheckHotBarRandomEntries() ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHotBarWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckIfHotBarFile
	In Parameters	: char *
	Out Parameters	: bool * 
	Purpose			: Checks if the file is a hotbar file
	Author			: Anand
	Description		: Searches for all the keyword list and returns true in 'bFound'
					  if all of them were found
--------------------------------------------------------------------------------------*/
bool CHotBarWorm::_CheckIfHotBarFile(TCHAR * FileName, bool * bFound)
{
	try
	{
		if(IsStopScanningSignaled())
			return false;
	
		int hFile = -1 ;
		bool flag = false ;
		DWORD i = 0 ;
		char * Strings [] =
		{
			"HbTools" ,
			"December" ,
			"November" ,
			"October" ,
			"September" ,
			"August" ,
			"July" ,
			"June" ,
			"April" ,
			"March" ,
			"February" ,
			"January" ,
			"Saturday" ,
			"Friday" ,
			"Thursday" ,
			"Wednesday" ,
			"Tuesday" ,
			"Monday" ,
			"Sunday" ,
			"0123456789" ,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ" ,
			"abcdefghijklmnopqrstuvwxyz" ,
			"SunMonTueWedThuFriSat" ,
			"JanFebMarAprMayJunJulAugSepOctNovDec" ,
			"Release_HbTools" ,
			"AVexception" ,
			"AVlogic_error" ,
			"AVlength_error" ,
			"AVout_of_range" ,
			"AVbad_alloc" ,
			"AVtype_info" ,
			NULL
		} ;

		int iRetValue = _tsopen_s ( &hFile , FileName , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
		if ( 0 != iRetValue || hFile == -1 )
			return ( false ) ;

		for (i = 0; Strings[i]; i++)
		{
			flag = false ;
			if (!SearchString(hFile ,Strings[i] ,&flag) )
			{
				_close ( hFile ) ;
				return(false) ;
			}

			if ( false == flag )
			{
				*bFound = false ;
				_close ( hFile ) ;
				return(true) ;
			}

			if(IsStopScanningSignaled())
			{
				_close ( hFile ) ;
				return *bFound;
			}
		}

		*bFound = flag ;
		_close ( hFile ) ;
		return(true) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHotBarWorm::_CheckIfHotBarFile, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
Function		: _CheckHotBarRandomEntries
In Parameters	: void
Out Parameters	: void
Purpose			: Checks for random files and keys
Author			: Shweta
Description		: Check for the Random Hotbar Entries
--------------------------------------------------------------------------------------*/
void CHotBarWorm::_CheckHotBarRandomEntries ( void )
{
	try
	{
		CString csSearchFolder ;
		CArray<CStringA,CStringA> csArrKeyWords2 ;
		CStringArray csArrPFDirLocations ;

		csArrKeyWords2.Add ( "Hotbar.com" ) ;

		if( IsStopScanningSignaled())
			return ;

		csArrPFDirLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrPFDirLocations . Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < csArrPFDirLocations . GetCount() ; i++ )
		{
			csSearchFolder = csArrPFDirLocations [ i ] + _T("\\Common Files\\Microsoft Shared\\Stationery") ;
			_CheckForHotbarRandomFilesInPath ( csSearchFolder , _T("\\*.htm?") , 0 , csArrKeyWords2 ) ;
		}

		//Added Spyware Name parameter
		CheckReportKeyValueData ( m_ulSpyName , SOFTWARE , HKEY_LOCAL_MACHINE);
		if ( m_bScanOtherLocations )
			CheckReportKeyValueData ( m_ulSpyName , WOW6432NODE_REG_PATH , HKEY_LOCAL_MACHINE);
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHotBarWorm::_CheckHotBarRandomEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}

/*-------------------------------------------------------------------------------------
Function		: _CheckForHotbarRandomFilesInPath
In Parameters	: CString , CString , int , CStringArray  
Out Parameters	: bool
Purpose			: Checks for random files in given folder
Author			: Shweta
Description		: Enumerate folders for checking fils against a keywords with file size specification
--------------------------------------------------------------------------------------*/
bool CHotBarWorm :: _CheckForHotbarRandomFilesInPath ( CString csSearchFolder , CString csWildCard , int iMinSize , CArray<CStringA,CStringA> & csArrKeywords )
{
	try
	{
		CFileFind	objFile;
		BOOL bFileFlag = FALSE ;
		bool bFound = false ;
		
		bFileFlag = objFile.FindFile ( csSearchFolder + csWildCard ) ;
		while ( bFileFlag )
		{
			bFileFlag = objFile.FindNextFile();
			if ( objFile.IsDots() || objFile.IsDirectory() )
				continue;

			if ( iMinSize != 0 && objFile.GetLength() < iMinSize )
				continue ;

			if(IsStopScanningSignaled())
				break ;

			if ( SearchStringsInFile ( objFile.GetFilePath() , csArrKeywords ) )
			{
				SendScanStatusToUI ( Special_File ,  m_ulSpyName , objFile.GetFilePath()  ) ;
			}
		}
		objFile.Close() ;
		return true;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHotBarWorm::_CheckForHotbarRandomFilesInPath, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
