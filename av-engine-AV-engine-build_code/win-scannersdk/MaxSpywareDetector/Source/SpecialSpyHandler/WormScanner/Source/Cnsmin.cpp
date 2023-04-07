/*=============================================================================
   FILE				: Cnsmin.Cpp
   ABSTRACT			: Implementation of Special Spyware Zhelatin Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta Mulay
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 7/03/2007
   NOTES			:
   VERSION HISTORY	: 2.5.0.30		
=============================================================================*/

#include "pch.h"
#include "Cnsmin.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool , CFileSignatureListManager*
	Out Parameters	: bool
	Purpose			: Checks and removes Cnsmin driver entry.
	Author			: Shweta
	Description		: scans for Cnsmin random driver and quarantines it.
--------------------------------------------------------------------------------------*/
bool CCnsmin :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		CString csDrvname1,csDrvname2,csGroupData;
		CStringArray csServiceKeys;
		CStringArray csArrLoc;

		csArrLoc . Add ( m_objSysInfo.m_strSysDir );
		if ( m_bScanOtherLocations )
		{
			csArrLoc . Add ( m_objSysInfo . m_strSysWow64Dir ) ;
		}

		for (int iLocCnt = 0 ; iLocCnt < csArrLoc.GetCount() ; iLocCnt++ )
		{
			csDrvname1 = csArrLoc . GetAt ( iLocCnt ) + _T("\\drivers\\cnsminkp.sys") ;
			csDrvname2 = csArrLoc . GetAt ( iLocCnt ) + _T("\\drivers\\CnsStd.sys") ;

			if ( _taccess ( csDrvname1 , 0 ) && _taccess ( csDrvname2 ,0 ) )
			{
				continue;
			}
			m_bSplSpyFound = true ;

			//Enumerate registry services entry
			m_objReg . EnumSubKeys ( SERVICES_MAIN_KEY , csServiceKeys , HKEY_LOCAL_MACHINE ) ;

			for ( int i = 0 ; i < csServiceKeys.GetCount() ; i++ )
			{
				csGroupData = BLANKSTRING ;
				if ( !m_objReg.Get ( SERVICES_MAIN_KEY + csServiceKeys.GetAt(i) , _T("Group") , csGroupData , HKEY_LOCAL_MACHINE ) )
					continue;

				if ( csGroupData != _T("DMN") )
				{
					continue;
				}
				
				CString csImagePathData , csDisplayNameData;
				m_objReg.Get ( SERVICES_MAIN_KEY + csServiceKeys.GetAt(i) , _T("ImagePath") , csImagePathData , HKEY_LOCAL_MACHINE );
				m_objReg.Get ( SERVICES_MAIN_KEY + csServiceKeys.GetAt(i) , _T("DisplayName") , csDisplayNameData , HKEY_LOCAL_MACHINE );

				if ( ( csDisplayNameData == csServiceKeys.GetAt(i) ) && ( csImagePathData.Find( csServiceKeys.GetAt(i) != -1 )))
				{
					CString csFilenm;
					csFilenm = csArrLoc . GetAt ( iLocCnt ) + _T("\\drivers\\") + csServiceKeys.GetAt(i) + _T(".sys") ;
					if ( !_taccess ( csFilenm , 0 ) )
					{
						//m_bSplSpyFound = true;
						if ( bToDelete )
						{
							QuarantineFile ( m_ulSpyName , csFilenm ) ;
						}
						else
						{
							SendScanStatusToUI ( Special_File ,  m_ulSpyName , csFilenm  ) ;
							EnumKeynSubKey( CString(HKLM) + CString(BACK_SLASH) + CString(SERVICES_MAIN_KEY) + csServiceKeys.GetAt(i) , m_ulSpyName ) ;
						}
						
					}
				}			
			}
			if (m_bSplSpyFound)
			{
				if ( bToDelete )
				{
					QuarantineFile ( m_ulSpyName , csDrvname1 ) ;
					QuarantineFile ( m_ulSpyName , csDrvname2 ) ;
				}
				else
				{
                    SendScanStatusToUI ( Special_File, m_ulSpyName , csDrvname1  );
					SendScanStatusToUI ( Special_File, m_ulSpyName , csDrvname2  );
				}
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		return ( m_bSplSpyFound ) ;
	}

	catch (...)
	{
		CString csErr ;
		csErr.Format(_T("Exception caught in CCnsmin::ScanSplSpy(), Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}
