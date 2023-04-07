/*======================================================================================
   FILE				: BustedWorm.Cpp
   ABSTRACT			: Scans for PCBusted.Net spyware
   DOCUMENTS		: Refer The Design Folder (SpecialSpyHandler_DesignDoc.doc)
   AUTHOR			: Avinash B
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 30/07/2007
   NOTES			:
   Version History	:
				Version: 2.5.0.9
				Resource: Avinash B
				Description: Created the file and added random files and folder scanning fix

				version: 2.5.0.23
				Resource : Anand
				Description: Ported to VS2005 with Unicode and X64 bit Compatability					

				version: 2.5.0.31
				Resource : Shweta
				Description: Add function call for random entries.
======================================================================================*/

#include "pch.h"
#include "bustedworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete: if spyware is to be deleted 
	Out Parameters	: 
	Purpose			: check and fix PCBusted.Net spyware
	Author			: Avinash B
	Description		: checks and removes Busted random folder in pfdir
--------------------------------------------------------------------------------------*/
bool CBustedWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
				return false;

		CFileFind	objFile;
		BOOL	bMoreFiles = FALSE ;
		CStringArray csArrLocations ;

		csArrLocations.Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations.Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
		{
			bMoreFiles = objFile.FindFile( csArrLocations [ i ] + _T("\\*.*") );
			if ( !bMoreFiles )
				continue ;

			while( bMoreFiles)
			{
				bMoreFiles = objFile.FindNextFile();
				if ( objFile.IsDots() || !objFile.IsDirectory() )
					continue ;

				if ( IsRandomSpywareFolder ( objFile.GetFilePath() , _T("busted") , m_ulSpyName ) )
				{
					RemoveFolders ( objFile.GetFilePath(), m_ulSpyName , false ) ;

					//checking for registry keys.
					CheckForRegKeys(objFile.GetFilePath());
				}
			}

			objFile.Close();
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CBustedWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForRegKeys
	In Parameters	: CString&
	Out Parameters	: 
	Purpose			: check and fix Busted spyware
	Author			: Avinash B
	Description		: checks and removes Busted random folder in pfdir
--------------------------------------------------------------------------------------*/
void CBustedWorm ::CheckForRegKeys(CString& csFolderName)
{
	try
	{
		CString csRandomNumber, csRandomVersion , csRandomVersionWithDot;
		int iDashIndex = 0 ;
		CString csSubFolderName;

		// a sample folder for which this function must return true
		//eg: c:\program files\PCS-375\Busted.Net 2.4.0\PCBusted375.exe

		iDashIndex = csFolderName . Find ( '-' ) ;
		if ( iDashIndex == -1 )
			return  ;

		csRandomNumber = csFolderName . Right ( csFolderName . GetLength() - ( iDashIndex + 1 ) ) ;
		if ( csRandomNumber.IsEmpty() )
			return ;

		CheckForKeyLoggerKeys ( csRandomNumber ,L"PCBusted" , m_ulSpyName , L"Busted" );
		if ( RandomVersion ( csFolderName , csRandomVersion ,csSubFolderName , csRandomVersionWithDot, L"Busted.Net") )
		{
			CheckForKeyLoggerFiles ( csRandomNumber , m_ulSpyName , csSubFolderName ,csRandomVersion ,  L"Busted.Net");
		}

		//enumerating keys.
		CRegistry objReg;
		CStringArray arrSubKeys ;

		objReg.EnumSubKeys(_T("SYSTEM"),arrSubKeys,HKEY_LOCAL_MACHINE);
		for(int nIndex = 0 ; nIndex < arrSubKeys.GetCount() ; nIndex++)
		{
			//checking for control set key.
			CString csStr = arrSubKeys.GetAt(nIndex) ;
			if(_tcsstr(csStr.MakeLower(),_T("controlset")) == NULL)
				continue ;

			//checking for HKLM\SYSTEM\CurrentControlSet\Services\SnLtxxx
			CString csKeyPath , csWorm ;
			csKeyPath.Format(_T("SYSTEM\\%s\\Services\\SnLt%s"), static_cast<LPCTSTR>(arrSubKeys[nIndex]), static_cast<LPCTSTR>(csRandomNumber));
			if(objReg.KeyExists(csKeyPath,HKEY_LOCAL_MACHINE))
			{
				CString csData ;
				//check for Image path value.
				objReg.Get(csKeyPath,_T("ImagePath"),csData,HKEY_LOCAL_MACHINE);
				if(_tcsstr(csData,csFolderName) != NULL)
				{
					//report to UI			
					csWorm.Format(_T("\\%s"), static_cast<LPCTSTR>(csKeyPath));
                    SendScanStatusToUI(Special_RegKey, m_ulSpyName,HKEY_LOCAL_MACHINE,csKeyPath , 0,0,0,0);
				}
				
			}

			csKeyPath.Empty();
			csKeyPath.Format(_T("SYSTEM\\%s\\Enum\\Root\\LEGACY_SNLT%s"), static_cast<LPCTSTR>(arrSubKeys[nIndex]), static_cast<LPCTSTR>(csRandomNumber));
			if(objReg.KeyExists(csKeyPath,HKEY_LOCAL_MACHINE))
			{
                SendScanStatusToUI(Special_RegKey, m_ulSpyName,HKEY_LOCAL_MACHINE,csKeyPath , 0,0,0,0);
			}

			csKeyPath.Empty();
			csKeyPath.Format(_T("SYSTEM\\%s\\Services\\Eventlog\\Application\\SnLt%s"), static_cast<LPCTSTR>(arrSubKeys[nIndex]), static_cast<LPCTSTR>(csRandomNumber));
			if(objReg.KeyExists(csKeyPath,HKEY_LOCAL_MACHINE))
			{
				SendScanStatusToUI(Special_RegKey, m_ulSpyName,HKEY_LOCAL_MACHINE,csKeyPath , 0,0,0,0);
			}
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CBustedWorm::CheckForRegKeys, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}
