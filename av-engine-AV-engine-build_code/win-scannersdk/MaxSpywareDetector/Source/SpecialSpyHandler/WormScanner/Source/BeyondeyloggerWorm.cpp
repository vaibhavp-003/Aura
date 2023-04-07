/*====================================================================================
   FILE				: BeyondkeyLogger.cpp
   ABSTRACT			: This class is used for scanning and qurantining Keylogger Beyond
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: 
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
#include "BeyondKeyloggerWorm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CheckForBeyondKeyLogger
In Parameters	: bool
Out Parameters	: 
Purpose			: Check and Keylogger.Beyond
Author			: Shweta
Description		: Check and removes Hidden folder and Files of Beyond Keylogger
--------------------------------------------------------------------------------------*/
bool CBeyondKeyloggerWorm::ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan)
{
	
	try
	{
		m_pFileSigMan = pFileSigMan;		
		CFileFind objFile;
		CString csFilePath , csFullFileName , csFileName;
		BOOL bFlag = false;
		bool bHomeFlag = false, bPurchaseFlag = false;
		CStringArray csArrofFiles;
		CArray<CStringA,CStringA> csArr ;
		csArr.Add( "http://www.supremtec.com/" );
		CStringArray csArrLocations ;

		csArrLocations .Add ( RUN_REG_PATH  ) ;
		if ( m_bScanOtherLocations )
			csArrLocations.Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;
		
		for ( int a = 0 ; a < csArrLocations.GetCount() ; a++ )
		{
            vector<REG_VALUE_DATA> vecRegValues;
	        m_objReg.EnumValues( csArrLocations [ a ] , vecRegValues, HKEY_LOCAL_MACHINE);            

            for ( size_t i = 0 ; i < vecRegValues.size() ; i++ )
			{
                CString csData;
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[i].bData);
				if ( csData.Find(_T("\\csrss.exe"))== -1 )
					continue;

				//Check for version tab and the Description               
				CFileVersionInfo oFileVersionInfo;
				if ( !oFileVersionInfo.DoTheVersionJob ( csData , false ))
				{
					TCHAR szFileDesc[MAX_PATH];
					CString csFileDescription;
					bool bDerscFlag = false;

					oFileVersionInfo.GetFileDescription(csData,szFileDesc);
					csFileDescription.Format(_T("%s"),szFileDesc);
					csFileDescription.MakeLower();
					if ( csFileDescription != _T("csrss helper file") )
						continue;
				}

				csFilePath = csData;
				csFilePath = csFilePath.Left(csFilePath.ReverseFind('\\'));

				if ( bToDelete )
				{
					if ( m_csFileName .IsEmpty() )
						return false;
					MoveFileEx ( m_csFileName , NULL , MOVEFILE_DELAY_UNTIL_REBOOT );
				}
				else
				{
					if ( _taccess ( csFilePath  , 0 ) != 0 )
						return false;

					bFlag = objFile.FindFile ( csFilePath + _T("\\*.* ") );
					if ( !bFlag )
						return false;

					m_bSplSpyFound = true; 

					while ( bFlag )
					{
						bFlag = objFile.FindNextFile() ;
						if ( objFile.IsDirectory() || objFile.IsDots() )
							continue ;

						csFileName = objFile.GetFilePath() ;
						if ( csFileName.IsEmpty() )
							continue ;

						csFullFileName = csFileName ;
						if (csFullFileName.Find(_T("Home.url"))!= -1 )
						{
							if ( SearchStringsInFile(csFullFileName,csArr) )
								bHomeFlag = true;
						}
						if ( csFullFileName.Find(_T("Purchase.url")) != -1 )
						{
							if ( SearchStringsInFile(csFullFileName,csArr) )
								bPurchaseFlag = true;
						}
						if ( csFullFileName .Find( _T(".exe") , 0)!= -1 )
							m_csFileName = csFullFileName ;

						csArrofFiles.Add(csFullFileName);
					}
					if (bHomeFlag && bPurchaseFlag )
					{
						for (int j =0 ;j < csArrofFiles.GetCount() ;j++)
						{
							SendScanStatusToUI ( Special_File, m_ulSpyName , csArrofFiles.GetAt(j) );
						}
						SendScanStatusToUI( Special_Folder, m_ulSpyName , csFilePath );
                        SendScanStatusToUI( Special_RegVal, m_ulSpyName , HKEY_LOCAL_MACHINE , CString(RUN_REG_PATH) , vecRegValues[i].strValue ,vecRegValues[i].Type_Of_Data ,vecRegValues[i].bData ,vecRegValues[i].iSizeOfData);
					}
				}
			}
		}
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		return m_bSplSpyFound;
		
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBeyondKeyloggerWorm"), 0, 0);
	}
	return false;
}