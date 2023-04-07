/*======================================================================================
   FILE				: CommonNameWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Common Name
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
========================================================================================*/

#include "pch.h"
#include <io.h>
#include <fcntl.h>
#include <sys\stat.h>
#include "CommonNameWorm.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForCommonName
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove common name
	Author			: Anand
	Description		: this function checks if the driver registry key is present
					  it first tries to delete that and only if this successfully done
					  rest of the removal is initiated, which includes
					  removal of legacy key, random folder and run entries, driver file
--------------------------------------------------------------------------------------*/
bool CCommonNameWorm::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		bool bCheckRandomFolder = false ;
		if ( !bToDelete )
		{
			if ( m_objReg.KeyExists ( SYSTEM_WINIK , HKEY_LOCAL_MACHINE ) ) // check if the driver key exists
			{
				if ( EnablePrivilegesToHandleReg()) 	// enable privileges to handle this key
				{
					if ( m_objReg.AdjustPermissions ( HKEY_LOCAL_MACHINE , SYSTEM_WINIK ) ) // get required perissions on the key
					{
						// delete all the values in this key, so that driver is not loaded next time
						if ( DeleteAllTheValues ( HKEY_LOCAL_MACHINE , SYSTEM_WINIK ) )
						{							
							bCheckRandomFolder = true ; // set the flag to check rest of the infection

							// delete if this is present as its leftover of the above function (DeleteAllTheValues)
							// as the driver is active it wont allow us to delete it right here
							AddInRestartDeleteList(RD_KEY, m_ulSpyName, CString(HKLM) + CString(BACK_SLASH) + CString(SYSTEM_WINIK) + CString(_T("Dummy")));

							SendScanStatusToUI ( Special_RegKey, m_ulSpyName , HKEY_LOCAL_MACHINE ,  CString(SERVICES_LEGACY_KEY) + CString(_T("WINIK")),0,0,0,0 ) ;
							SendScanStatusToUI ( Special_RegKey, m_ulSpyName , HKEY_LOCAL_MACHINE, CString(SYSTEM_WINIK) , 0,0,0,0 ) ;
                            

							// send to UI both the keys
							RemoveRegistryKey ( CString(SERVICES_LEGACY_KEY) + CString(_T("WINIK")) , HKEY_LOCAL_MACHINE ,  m_ulSpyName ) ;
							RemoveRegistryKey ( SYSTEM_WINIK , HKEY_LOCAL_MACHINE , m_ulSpyName ) ;

							// send to UI the driver also
							CString csDriver = m_objSysInfo . m_strSysDir + _T("\\Drivers\\Winik.sys") ;
							if ( !_taccess_s ( csDriver , 0 ) )
								SendScanStatusToUI ( Special_File ,  m_ulSpyName , csDriver ) ;

							if ( m_bScanOtherLocations )
							{
								csDriver = m_csOtherSysDir + _T("\\Drivers\\Winik.sys") ;
								if ( !_taccess_s ( csDriver , 0 ) )
									SendScanStatusToUI ( Special_File ,  m_ulSpyName , csDriver  ) ;
							}
						}
					}
				}
			}
			else
			{
				bCheckRandomFolder = true ;
			}

			if ( bCheckRandomFolder )
			{
				// check the random folder and run entries
				CheckForRandomCommonNameFolder() ;
			}
		}

		// check for main commonName folder
		CStringArray csLocations ;

		csLocations . Add ( m_objSysInfo.m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csLocations.Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < (int)csLocations.GetCount() ; i++ )
		{
			CString csCmnNameFolder = csLocations [ i ] + _T("\\CommonName") ;
			if ( !_taccess_s ( csCmnNameFolder , 0 ) )
			{
				m_bSplSpyFound = true ;
				if ( bToDelete )
					FixLSP() ;
				else
					SendScanStatusToUI ( Special_Folder , m_ulSpyName , csCmnNameFolder ) ;
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CCommonNameWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForRandomCommonNameFolder
	In Parameters	: 
	Out Parameters	: 
	Purpose			: check random folder of common name
	Author			: Anand
	Description		: this function enumerates alll the folders under prog files
					  and checks for a dll with www.commonname.com in all the folders in Prog Files
					  or a pattern of files like cnml.exe and cnbabe.dat or babe.dat
--------------------------------------------------------------------------------------*/
bool CCommonNameWorm :: CheckForRandomCommonNameFolder ( void )
{
	BOOL bFileFlag = FALSE ;
	CStringArray csLocations ;
	CString csSearchPath ;

	csLocations . Add ( m_objSysInfo.m_strProgramFilesDir ) ;
	if ( m_bScanOtherLocations )
		csLocations.Add ( m_csOtherPFDir ) ;

	for ( int i = 0 ; i < (int)csLocations.GetCount() ; i++ )
	{
		csSearchPath = csLocations [ i ] + _T("\\*") ;

		CFileFind objFile;
		bFileFlag = objFile.FindFile( csSearchPath ) ;
		while ( bFileFlag )
		{
			if(IsStopScanningSignaled())
			{
				objFile.Close();
				return false;
			}

			bFileFlag = objFile.FindNextFile();
			if(objFile.IsDots()|| !objFile.IsDirectory())
				continue;

			// determine if its a commonname random folder
			if ( IsRandomCommonNameFolder( objFile.GetFilePath() ) )
			{
				//Version :19.0.0.29
				//Resource :Shweta
				CheckForRandomCommonNameRegKey(objFile.GetFileName());

				// make all the entries in the UI
				RemoveFolders ( objFile.GetFilePath() , m_ulSpyName , false ) ;

				// make tmp file with common name random folder
				FILE * fp = NULL;
				int iRetValue = _tfopen_s ( &fp , m_objSysInfo.m_strAppPath + _T("cmn.tmp") , _T("a") ) ;
				if ( !iRetValue && fp )
				{
					if ( fp ) _fputts ( objFile.GetFileName() + _T("\r\n") , fp ) ;
					if ( fp ) fclose ( fp ) ;
				}
			}
		}

		objFile.Close() ;
	}

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
Function		: CheckForRandomCommonNameRegKey
In Parameters	: CString 
Out Parameters	: void
Purpose			: check for Common Name Random Keys
Author			: Shweta
Description		: Find the Random Keys for Common Name
--------------------------------------------------------------------------------------*/
void CCommonNameWorm :: CheckForRandomCommonNameRegKey ( CString csFolderName )
{
	CString csRegKey = SOFTWARE_PATH;
	csRegKey = csRegKey + _T("\\") + csFolderName ;

	if ( m_objReg . KeyExists ( csRegKey.Right(csRegKey.GetLength() - csRegKey.Find(_T("\\"),0) - 1) , HKEY_LOCAL_MACHINE ) )
	{
		SendScanStatusToUI ( Special_RegKey, m_ulSpyName, HKEY_LOCAL_MACHINE , csRegKey ,0,0,0,0 );
		EnumKeynSubKey ( csRegKey , m_ulSpyName ) ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: IsRandomCommonNameFolder 
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: Checks if the file is a hotbar file
	Author			: Anand
	Description		: this function checks for a dll with www.commonname.com in all the folders in Prog Files
					  or a pattern of files like cnml.exe and cnbabe.dat or babe.dat
--------------------------------------------------------------------------------------*/
bool CCommonNameWorm :: IsRandomCommonNameFolder ( CString csPath )
{
	bool bFound = false ;
	BOOL bFileFlag = FALSE ;
	CString csSearchPath = csPath + _T("\\*.dll") ;
	CFileFind FileFinder ;

	bFileFlag = FileFinder . FindFile ( csSearchPath ) ;
	while ( bFileFlag && !bFound )
	{
		if(IsStopScanningSignaled())
		{
			FileFinder.Close();
			return false ;
		}

		bFileFlag = FileFinder . FindNextFile();
		if(FileFinder.IsDots() || FileFinder.IsDirectory())
			continue;

		// look for the text in file
		if ( IsCommonNameFile( FileFinder.GetFilePath() ) )
		{
			bFound = true ;
		}
	}
	
	FileFinder.Close() ;
	if ( bFound )
		return ( bFound ) ;

	// if the text was not found above, look for pattern
	if ( ( !_taccess_s ( csPath + _T("\\cnml.exe") , 0 ) ) && 
		 ( !_taccess_s ( csPath + _T("\\babe.dat") , 0 ) ) || 
		 ( !_taccess_s ( csPath + _T("\\cnbabe.dat") , 0 ) ) )
	{
		int hFile = -1 ;
		char * const string = "CommonName Agent" ;

		int iRetValue = _tsopen_s ( &hFile , csPath + _T("\\cnml.exe") , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
		if ( 0 == iRetValue && hFile != -1  )
		{
			SearchString ( hFile , string , &bFound ) ;
			_close ( hFile ) ;
		}
	}

	return ( bFound ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsCommonNameFile
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: detremines common name file
	Author			: Anand
	Description		: this function checks for a text with www.commonname.com and
					  file must not have a version tab
--------------------------------------------------------------------------------------*/
bool CCommonNameWorm :: IsCommonNameFile ( CString csFileName )
{
	CFileVersionInfo oFileVersionInfo;

	bool bFound = false ;
	char * const search = "www.commonname.com" ;
	int hFile = -1 ;

	int iRetValue = _tsopen_s ( &hFile , csFileName , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
	if ( 0 == iRetValue && hFile != -1 )
	{
		SearchString ( hFile , search , &bFound ) ;
		_close ( hFile ) ;
	}
	bFound = bFound ? oFileVersionInfo.DoTheVersionJob ( csFileName , false ) : false ;
	return ( bFound ) ;
}
