/*======================================================================================
   FILE				: Antivirus2009.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Antivirus 2009
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
   CREATION DATE	: 01/03/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.65
					Resource : Shweta
					Description: created this class to fix Antivirus 2009

					versio: 2.5.1.04
					Resource : Shweta
					Description: Added core for varient of similar spyware
========================================================================================*/

#include "pch.h"
#include "Antivirus2009.h"
#include "ExecuteProcess.h"
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
	Purpose			: Check and remove Antivirus 2009
	Author			: Shweta M
	Description		: This function checks for random files of Antivirus 2009
--------------------------------------------------------------------------------------*/
bool CAntivirus2009  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;
		
		CString csData , csFileName ;
		CArray<CStringA,CStringA> csArr , csArrnew , csArrnew1;
		csArr.Add("E s e t   H o o k s   D L L");
		csArrnew.Add("S o f t C o m p l e t e   D e v e l o p m e n t");
		csArrnew1.Add ("WINMM.dll");//2.5.1.07
		csArrnew1.Add ("CloseDriver");
		csArrnew1.Add ("OpenDriver");
		csArrnew1.Add ("PathRenameExtensionA");
		csArrnew1.Add ("PathRemoveArgsA");
		csArrnew1.Add ("PathFindNextComponentA");

		CString csSid;
		CExecuteProcess objExecProc;

		csSid = objExecProc.GetCurrentUserSid();


        vector<REG_VALUE_DATA> vecRegValues;
	    m_objReg.EnumValues( csSid + BACK_SLASH + RUN_REG_PATH, vecRegValues, HKEY_USERS);		
		{
            for ( size_t iruncnt = 0 ; iruncnt < vecRegValues.size(); iruncnt++ )
			{
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[iruncnt].bData);
				if ( CheckIfRandomEntry ( vecRegValues[iruncnt].strValue  , csData  , csSid ) )
				{
                    SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_USERS ,  csSid + CString(BACK_SLASH) + CString(RUN_REG_PATH) ,  vecRegValues[iruncnt].strValue  , vecRegValues[iruncnt].Type_Of_Data ,  vecRegValues[iruncnt].bData , vecRegValues[iruncnt].iSizeOfData);		
					
				}
			}
		}     
		CheckIfSpywareDesktop ( csSid );

        vector<REG_VALUE_DATA> vecRegValues1;            
	    m_objReg.EnumValues(RUN_REG_PATH, vecRegValues1, HKEY_LOCAL_MACHINE);        

        for ( size_t icnt = 0 ; icnt < vecRegValues1.size(); icnt++)
		{
            csData.Format(_T("%s") , (TCHAR*)vecRegValues1[icnt].bData);
			csData.MakeLower();
			if ( csData.Find ( _T("rundll32.exe") ) == -1 )
				continue ;

			if (( csData.GetLength() - csData.ReverseFind(',')) != 2 ) 
				continue;
			
			csFileName = csData.Right ( csData.GetLength() -  csData.Find ( _T("\"") ) );
			csFileName = csFileName.Left ( csFileName.Find ( _T("\",") ) );
			csFileName.Replace ( _T("\"") , _T("") );

			if ( csFileName == _T("") )
			{
				csFileName = csData.Right ( csData.GetLength() -  csData.Find ( _T(" ") ) );
				csFileName = csFileName.Left ( csFileName.Find ( _T(",") ) );
			}

			csFileName.Trim();
			if ( csFileName.Find ( m_objSysInfo.m_strSysDir.MakeLower() ) == -1 )
				continue ;

			CFileVersionInfo objFV;
			CString csCmpynm;
			if (!objFV.DoTheVersionJob ( csFileName , false ) )
			{
				TCHAR csCmpy[MAX_PATH] = { 0 } ;
				if ( objFV.GetCompanyName ( csFileName , csCmpy ) )
				{
					if ( _tcscmp ( csCmpy , L"eset" ) != 0 ) 
						if ( _tcscmp ( csCmpy , L"SoftComplete Development" ) != 0 ) 
							continue;
				}
			}
			else
			{
				if ( !SearchStringsInFile ( csFileName , csArr ) )
					if ( !SearchStringsInFile ( csFileName , csArrnew ) )
						if ( !SearchStringsInFile ( csFileName , csArrnew1 ) )//2.5.1.07
						continue;
			}

			if ( bToDelete )
			{
				//2.5.1.07
				AddToCompulsoryDeleteOnRestartList(RD_VALUE, m_ulSpyName, CString(HKLM) + BACK_SLASH + CString(RUN_REG_PATH) + BACK_SLASH + _T("\t#@#") + vecRegValues1[icnt].strValue);
			}
			else
			{
				m_bSplSpyFound = true ;
				SendScanStatusToUI ( Special_File, m_ulSpyName , csFileName  );
                SendScanStatusToUI ( Special_RegVal ,  m_ulSpyName , HKEY_LOCAL_MACHINE, CString(RUN_REG_PATH) , vecRegValues1[icnt].strValue ,  vecRegValues1[icnt].Type_Of_Data ,vecRegValues1[icnt].bData,vecRegValues1[icnt].iSizeOfData);				
			}
		}		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CAntivirus2009::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckifRandomEntry
	In Parameters	: csVal , csData , csSid
	Out Parameters	: bool
	Purpose			: check and report the random key
	Author			: Shwetam
	Description		: returns true random key found with datapart as AV2009.exe
--------------------------------------------------------------------------------------*/
bool CAntivirus2009 :: CheckIfRandomEntry ( const CString & csVal , CString csData , const CString &csSid )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( false ) ;

		CString csKey , csExtractedVal;

		for ( int i = 0 ; i < csVal .GetLength () ; i++ )
		{
			if ( !isdigit ( csVal [ i ] ) )
					return ( false ) ;
		}

		csData.MakeLower();
		if ( csData	.Find ( _T("antivirus 2009\\av2009.exe") ) == -1 )
			return false;

		csKey = csSid + BACK_SLASH + SOFTWARE + BACK_SLASH + csVal + BACK_SLASH + _T("Options") ;

		if (! m_objReg.KeyExists ( csKey , HKEY_USERS ) )
			return false;

		if ( !m_objReg.Get ( csKey , _T("pPath") , csExtractedVal , HKEY_USERS ) )
			return false;

		csExtractedVal.MakeLower();
		if ( csExtractedVal.Find ( _T("antivirus 2009\\av2009.exe")) == -1 )
			return false;
		
		if ( !m_objReg.Get ( csKey , _T("pName") , csExtractedVal , HKEY_USERS ) )
			return false;

		csExtractedVal.MakeLower();
		if ( csExtractedVal.Find ( _T("antivirus 2009")) == -1 )
			return false;

		EnumKeynSubKey ( CString(HKU) + CString(BACK_SLASH)  + csSid + CString(BACK_SLASH) + CString(SOFTWARE) + CString(BACK_SLASH) + csVal  , m_ulSpyName );
		return true;
	}
	catch(...)
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CAntivirus2009::CheckIfRandomEntry, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfSpywareDesktop
	In Parameters	: cSid
	Out Parameters	: bool
	Purpose			: check and report the random file of winAv2009
	Author			: Shwetam
	Description		: If the entry witht 
--------------------------------------------------------------------------------------*/
void CAntivirus2009 :: CheckIfSpywareDesktop ( const CString & csSid )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ;

		//%SystemRoot%\System32\ahtn.htm
		CPathExpander objPathExpander;
		CString csData , csFileName;
		CArray<CStringA,CStringA> csArr ;

		csArr.Add ( "WARNING!!!" );
		csArr.Add ( "check up the computer with a special software." );
		csArr.Add ( "Many viruses were found on your computer" );

		if ( !m_objReg.Get ( csSid + BACK_SLASH + DESKTOP_GENERAL_PATH , _T("Wallpaper") , csData ,  HKEY_USERS ) )
			return ;

		csFileName = csData ;
		if ( !objPathExpander.ExpandSystemTags ( csData )  )
			return ;
		csData.MakeLower () ;

		if ( csData.Find (_T(".htm") ,0 ) == -1 )
			return ;

		if (!SearchStringsInFile ( csData , csArr ) )
			return ;

		SendScanStatusToUI ( Special_File, m_ulSpyName , csData );	
        //TODO:regFixScanner
		//SendMessageToUI ( m_ulSpyName , CString(HKU) + CString(BACK_SLASH) + csSid + CString(BACK_SLASH) + CString(DESKTOP_GENERAL_PATH) + CString(REG_SEPERATOR) + CString(_T("Wallpaper")) + CString(REG_SEPERATOR) + csFileName + CString(_T(" | ")) + CString(_T("")) , Special_RegDataFix_Scanner );
	}
	catch(...)
	{
		CString csErr ;	
		csErr . Format ( _T("Exception caught in CAntivirus2009::CheckIfSpywareDesktop, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	return ;
}