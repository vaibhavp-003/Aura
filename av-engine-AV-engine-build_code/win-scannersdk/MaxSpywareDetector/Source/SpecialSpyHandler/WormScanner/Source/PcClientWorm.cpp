/*======================================================================================
   FILE				: PcClientWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Backdoor PcClientWorm
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Shweta Mulay
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 17/09/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.52
					Resource : Shweta
					Description: created this class to fix PcClientWorm

					version:  2.5.1.03
					Resource : Vaibhav Desai
					Description: Add the code for scan random reg entries and files

					version:  2.5.1.14
					Resource : Shweta Mulay
					Description: Add the code for scan legacy entries

========================================================================================*/

#include "pch.h"
#include "PcClientWorm.h"
#include "PathExpander.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove CPcClientWorm
	Author			: Shweta M
	Description		: This function checks for random service dll
--------------------------------------------------------------------------------------*/
bool CPcClientWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		ScanRegEntryAndFiles ( bToDelete ) ;
		ScanRegEntryBySysFiles ( bToDelete ) ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CXPProWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanRegEntryBySysFiles
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove CPcClientWorm
	Author			: Vaibhav Desai
	Description		: This function checks for random Reg Entryes
--------------------------------------------------------------------------------------*/
void CPcClientWorm :: ScanRegEntryBySysFiles ( bool bToDelete )
{
	CStringArray cskeys;
	CString csData ;
	CFileVersionInfo objFileVer;
	CArray<CStringA,CStringA> csArrFile ;
	CString csSubKey;
	CPathExpander objExpander ;

	csArrFile.Add ("h.data");
	csArrFile.Add ("RSDS");
	csArrFile.Add ("j9Y3");

	if(IsStopScanningSignaled())
		return ;

	m_objReg.EnumSubKeys(SERVICES_MAIN_KEY, cskeys, HKEY_LOCAL_MACHINE );
	
	for ( int iCnt = 0 , iTotalCount = (int)cskeys.GetCount() ; iCnt < iTotalCount ; iCnt++ )
	{
		if(IsStopScanningSignaled())
			break;
		csSubKey = SERVICES_MAIN_KEY +  cskeys . GetAt ( iCnt ) ;
        vector<REG_VALUE_DATA> vecRegValues;
        m_objReg.EnumValues( csSubKey, vecRegValues, HKEY_LOCAL_MACHINE);

		//get the display name
		csData = "" ;
		if ( !m_objReg . Get ( (CString)SERVICES_MAIN_KEY + cskeys . GetAt ( iCnt ) , _T("DisplayName") , csData , HKEY_LOCAL_MACHINE ) )
			continue ;

		if ( _tcsicmp ( csData , cskeys . GetAt ( iCnt ) ) != 0 )
			continue ;

		//Get the imagepath if key present
		csData = "" ;
		if ( !m_objReg . Get ( (CString)SERVICES_MAIN_KEY + cskeys . GetAt ( iCnt ) , _T("ImagePath") , csData , HKEY_LOCAL_MACHINE ) )
			continue;

		if ( csData . Find ( _T ( "\\??\\" ) ) == -1 || csData . Find ( _T ( "\\drivers" ) ) == -1 )
			continue ;

		csData = csData.Mid( 4 );
		csData.MakeLower();

		if ( !objExpander . ExpandSystemTags ( csData ) )
			continue;

		if ( !objFileVer . DoTheVersionJob ( csData , bToDelete ) )
			continue;

		if ( !CheckSignature ( csData ) )
			continue ;

		if ( !SearchStringsInFile ( csData , csArrFile ) )
			continue ;

		m_bSplSpyFound = true;
		SendScanStatusToUI ( Special_File , m_ulSpyName , csData ) ;
		EnumKeynSubKey ( CString ( HKLM ) + BACK_SLASH + SERVICES_MAIN_KEY + cskeys . GetAt ( iCnt ) , m_ulSpyName ) ;
	}

	return ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanRegEntryAndFiles
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove CPcClientWorm
	Author			: Vaibhav Desai
	Description		: This function checks for random Reg Entryes and files
--------------------------------------------------------------------------------------*/

void CPcClientWorm  :: ScanRegEntryAndFiles(bool bToDelete)
{
	    CStringArray csArrLoc;
		CString csData ;
		CFileVersionInfo objFileVer;
		CArray<CStringA,CStringA> csArrFile ;

		//csArrFile.Add ( "SOFTWaRe\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost");
		//csArrFile.Add ( "SYSTEM\\ControlSet001\\Services\\");
		csArrFile.Add ( "d.exe");

		if(IsStopScanningSignaled())
			return ;

		//64 bit 
		csArrLoc.Add ( SVCHOST_MAIN_KEY ) ;
		if ( m_bScanOtherLocations )
			csArrLoc.Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_SVCHOST_MAIN_KEY) );

		for ( int iLocCnt = 0 ; iLocCnt < csArrLoc.GetCount() ; iLocCnt++ )
		{
            //Get the list of value and data from Svchost path
            vector<REG_VALUE_DATA> vecRegValues;
	        m_objReg.EnumValues( csArrLoc.GetAt(iLocCnt), vecRegValues, HKEY_LOCAL_MACHINE);
			            
			if(IsStopScanningSignaled())
				break;
			            
            for ( size_t iregcnt = 0 ; iregcnt < vecRegValues.size() ; iregcnt++ )
			{
				if(IsStopScanningSignaled())
					break;

				//Check if the key with the value is present in services 
                if ( !m_objReg.KeyExists ( (CString)SERVICES_MAIN_KEY + (CString)vecRegValues[iregcnt].strValue ,HKEY_LOCAL_MACHINE ) )
					continue;
				
				csData = "" ;
				//Get the imagepath if key present
                if ( !m_objReg . Get ( (CString)SERVICES_MAIN_KEY + (CString)vecRegValues[iregcnt].strValue , _T("ImagePath") ,csData , HKEY_LOCAL_MACHINE ) )
					continue;

				//Check if the image path has "svchost.exe -k " in data part
				csData.MakeLower();
                CString csKeyname = vecRegValues[iregcnt].strValue;
				csKeyname.MakeLower();
				if ( csData . Find ( _T("svchost") ) == -1 || csData . Find ( csKeyname ) == -1 || csData . Find ( _T("-k") ) == -1 )
					continue ;

				csData = "" ;
				//Check and Get the the Servicedll data part
                if ( !m_objReg.Get ( (CString)SERVICES_MAIN_KEY + (CString)vecRegValues[iregcnt].strValue + BACK_SLASH + _T("Parameters"), _T("ServiceDll") ,csData , HKEY_LOCAL_MACHINE ) )
					continue;

				csData.MakeLower();
				if(-1 != csData.Find(_T("netsession_win_dbc0250.dll")))
				{
					continue;
				}

				CPathExpander objExpander ;
				if ( !objExpander . ExpandSystemTags ( csData ) )
					continue;

				if(IsStopScanningSignaled())
					break;

				//Check if file exist at the path
				if ( !_taccess_s ( csData , 0 ) )
				{
					//get extension of file
					CString csFileExt = csData.Right(4);

					//Check for version tab
					if ( objFileVer . DoTheVersionJob ( csData , bToDelete ) )
					{
						//Search Strings in the file
						if (!SearchStringsInFile ( csData , csArrFile ) )
							continue ;
					}
					else if( csFileExt == _T(".kll") )						
					{
						//check to .k file exit
						CString csKFile;
						csKFile = csData.Left ( csData.ReverseFind ( _T('.')));
						csKFile = csKFile + _T(".k");

						if ( ! _taccess_s ( csKFile ,0 ))
						SendScanStatusToUI ( Special_File , m_ulSpyName , csKFile );
					}
					else
					{
						continue;
					}

					m_bSplSpyFound = true;
					SendScanStatusToUI ( Special_File , m_ulSpyName , csData );
					SendScanStatusToUI ( Special_RegVal , m_ulSpyName  ,HKEY_LOCAL_MACHINE,
                        csArrLoc.GetAt(iLocCnt)  ,  vecRegValues[iregcnt].strValue,vecRegValues[iregcnt].Type_Of_Data,vecRegValues[iregcnt].bData,vecRegValues[iregcnt].iSizeOfData );
					EnumKeynSubKey ( CString(HKLM) + CString(BACK_SLASH) + CString(SERVICES_MAIN_KEY) 
                        + vecRegValues[iregcnt].strValue, m_ulSpyName );

					CString csValue = vecRegValues[iregcnt].strValue ;
					if ( m_objReg.KeyExists ( SERVICES_LEGACY_KEY +  csValue , HKEY_LOCAL_MACHINE	) )
					{
						EnumKeynSubKey ( CString(HKLM) + CString(BACK_SLASH) + CString(SERVICES_LEGACY_KEY) 
									+ vecRegValues[iregcnt].strValue, m_ulSpyName );
					}

					//Check for .key file present
					CString csKeyFile;
					csKeyFile = csData.Left ( csData.ReverseFind ( _T('.')));
					csKeyFile = csKeyFile + _T(".key");

					if ( ! _taccess_s ( csKeyFile ,0 ))
						SendScanStatusToUI ( Special_File , m_ulSpyName , csKeyFile );
				}
			}
		}

}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: Check PE Signature for pcclientworm
	Author			: Vaibhav Desai
	Description		: This function checks PE Signature for Pcclientworm
--------------------------------------------------------------------------------------*/
bool CPcClientWorm  :: CheckSignature ( const CString csFilePath )
{
	DWORD dwBytesRead = 0 ;
	HANDLE hFile = NULL ;
	IMAGE_NT_HEADERS NTFileHeader = { 0 } ;
	IMAGE_DOS_HEADER DosHeader = { 0 } ;
	IMAGE_SECTION_HEADER SectionHeader [ 10 ] = { 0 } ;
	BYTE bySig[ 12 ] ={ 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x18, 0x02, 0x00, 0x00, 0x56, 0x57, 0xBE };
	BYTE ReadBuffer[ 12 ] = { 0 };

	if(IsStopScanningSignaled())
		return false;

	hFile = CreateFile ( csFilePath , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( ! ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( DosHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x5A4D != DosHeader . e_magic  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}
	
	SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
	
	if (!ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( sizeof ( NTFileHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x00004550 != NTFileHeader.Signature  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.FileHeader.NumberOfSections != 0x5 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.OptionalHeader.AddressOfEntryPoint < 0x300 || NTFileHeader.OptionalHeader.AddressOfEntryPoint > 0x1000 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( !ReadFile ( hFile , &SectionHeader , sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( SectionHeader [ 0 ] . PointerToRawData != 0x300 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	SetFilePointer ( hFile , NTFileHeader . OptionalHeader . AddressOfEntryPoint , 0 , FILE_BEGIN ) ;

	if (!ReadFile ( hFile , ReadBuffer , 12 , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( dwBytesRead != 12 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	if ( memcmp ( bySig , ReadBuffer , 12 ) )
		return ( false ) ;

	return true;

}