/*====================================================================================
   FILE				: CoolWebSearchWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#include "pch.h"
#include "coolwebsearchworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForCoolWebSearch
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: checks for cool web search
	Author			: Anand
	Description		: check for cool web search dll which makes entry app init
	Version			: 18.7
--------------------------------------------------------------------------------------*/
bool CCoolWebSearchWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;
		
		if(IsStopScanningSignaled())
				return false;

		TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;
		
		if ( false == bToDelete )
		{
			m_csArrCWSFiles.RemoveAll() ;
			CString		csData ;
			CStringArray csArrLoc;

			csArrLoc.Add ( WNT_WINDOWS_PATH );
			if ( m_bScanOtherLocations )
				csArrLoc.Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_WNT_WINDOWS_PATH) );

			for ( int iLoc = 0 ; iLoc < csArrLoc.GetCount() ; iLoc++ )
			{
				// at scanning look for the files with CWS signatures
				m_objReg.Get( csArrLoc.GetAt ( iLoc ), APPINIT , csData, HKEY_LOCAL_MACHINE  ) ;

				csData += _T(";") ;
				int i = 0;
				while ( true )
				{
					if ( -1 == ( i = csData.FindOneOf( _T(",;") )))
						break ;

					if ( _tcslen ( csData.Left(i)) < _countof(szFullFileName) )
					{
						_tcscpy_s ( szFullFileName , _countof ( szFullFileName ) , (LPCTSTR)csData.Left(i));
						if ( IsFilePresentInSystem ( szFullFileName , _countof ( szFullFileName ) ) )
						{
							if ( !LookUpWhiteList ( szFullFileName , KEY_ID_APPINIT ) )
							{
								BYTE bMD5Signature[16] = {0};
								const BYTE MD5_COOLWEBSEARCH[16] = {0x9B,0xDA,0xA9,0x2C,0xEC,0x04,0x5F,0xD1,0x53,0x2E,0x8D,0x5E,0xF0,0x55,0x94,0xDC};
								if(m_pFileSigMan->GetMD5Signature(szFullFileName, bMD5Signature))
								{
									if(!memcmp(bMD5Signature, MD5_COOLWEBSEARCH, 16))
									{
										if( FindReportKillOnRestart(szFullFileName, m_ulSpyName , bToDelete))
											m_bSplSpyFound = true;

										if( FindReportRegValue(csArrLoc.GetAt(iLoc), APPINIT, m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, true))
											m_bSplSpyFound = true;
										
										m_csArrCWSFiles.Add( szFullFileName);
									}
								}
							}
						}

						memset ( szFullFileName , 0 , sizeof ( szFullFileName ) ) ;
					}

					i = csData.GetLength() - i - 1 ;
					csData = csData.Right( i ) ;
				}
			}
		}
		else
		{
			int nFiles = (int)m_csArrCWSFiles.GetCount();
			for ( int i = 0; i < nFiles; i++)
				MoveFileEx ( m_csArrCWSFiles[i], NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
			m_csArrCWSFiles.RemoveAll();
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CCoolWebSearchWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
