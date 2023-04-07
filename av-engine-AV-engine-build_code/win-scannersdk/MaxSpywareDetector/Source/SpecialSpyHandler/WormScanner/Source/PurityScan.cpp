/*====================================================================================
   FILE				: PurityScan.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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
#include "purityscan.h"
//#include <shfolder.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForPurityScan
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove purity scan
	Author			: Anand
	Description		: wide char names searching for folder
--------------------------------------------------------------------------------------*/
bool CPurityScan :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		TCHAR	wSearchPath [_MAX_PATH ] =  { 0 } ;
		TCHAR	sPath [_MAX_PATH ]		 =	{ 0 } ;
		size_t	len = 0,	i = 0 ;

		SHGetFolderPath (0, CSIDL_APPDATA, 0, 0, sPath);

		len = _tcslen (sPath);
		if ( len >= _MAX_PATH )
			return ( false ) ;

		// convert char string to wide char string
		while ( wSearchPath[i] = sPath[i++]);

		ListFolders(wSearchPath, bToDelete);

		CStringArray csArrVal, csArrData;

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;

			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			m_objReg.QueryDataValue(csUserKey + BACK_SLASH + RUN_REG_PATH, csArrVal, csArrData, HKEY_USERS);
			int nValCount = (int)csArrVal.GetCount();
			for(int icount = 0; icount < nValCount; icount++)
			{
				if(IsStopScanningSignaled())
					break;
				if ( ValidatePurityScan( csArrData.GetAt( icount))) 
				{
					if( FindReportRegValue(csUserKey + BACK_SLASH + RUN_REG_PATH, csArrVal[icount], m_ulSpyName , HKEY_USERS, bToDelete, true))
						m_bSplSpyFound = true;
				}
			}
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CPurityScan::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ValidatePurityScan
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: Checks if the file is a hotbar file
	Author			: Shweta Mulay
	Description		: This function checks for the Data having _T("-vt") in 'csData'
					  and then checks for the version tab of the file if both conditions are satisfied 
					  returns true otherwise false
--------------------------------------------------------------------------------------*/
bool CPurityScan::ValidatePurityScan( CString csData )
{
	try
	{
		CFileVersionInfo m_oFileVersionInfo;
		
		csData.MakeLower() ;
		if ( csData.Find ( _T("-vt") , 0 ) != -1 )
		{
			csData = csData.Left ( csData.ReverseFind ( '-' ) -2 ) ;
			csData = csData.Right ( csData.GetLength() - 1 ) ;
			
			if ( m_oFileVersionInfo.DoTheVersionJob ( csData , false ) ) //check for version tab of the file present in regdata
			{
				if( FindKillReportProcess(csData, m_ulSpyName , false))
					m_bSplSpyFound = true;
				
				CString csFolderName;
				csFolderName = csData.Left(csData.ReverseFind('\\'));
				CheckPurityScanFolder(csFolderName);
				return true ;
			}
		}
		else
		{
			TCHAR		szFileDesc[MAX_PATH + 5] = { 0 } ;
			CString		csFileDescription;
			CString		csFileName;
			
			csFileName = csData ;
			if ( !m_oFileVersionInfo.DoTheVersionJob(csData , false))
			{
				m_oFileVersionInfo.GetFileDescription( csData, szFileDesc);
				csFileDescription.Format(_T("%s"), szFileDesc);
				csFileDescription.MakeLower();
				if ( csFileDescription.Find(_T("sear1")) != -1)
				{
					if( FindReportKillOnRestart(csFileName,  m_ulSpyName , false) )
					{
						return m_bSplSpyFound = true;
					}
				}
			}
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CPurityScan::ValidatePurityScan, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
Function		: CheckPurityScanFolder
In Parameters	: csFolderName
Out Parameters	: 
Purpose			: Check and report purity scan folder
Author			: Shweta
Description		: Confirming for Purity Scan
--------------------------------------------------------------------------------------*/
void CPurityScan::CheckPurityScanFolder(CString csFolderName)
{
	try
	{
		CString csPurityScanFolder;
		csPurityScanFolder = csFolderName + csFolderName.Right(csFolderName.GetLength() - csFolderName.ReverseFind('\\'));
		
		if (_taccess_s ( csPurityScanFolder, 0) == 0)
		{
            
			SendScanStatusToUI( Special_Folder , m_ulSpyName , csPurityScanFolder ) ;
			SendScanStatusToUI( Special_Folder , m_ulSpyName , csFolderName  ) ;
		}
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CPurityScan::CheckPurityScanFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}	
}
