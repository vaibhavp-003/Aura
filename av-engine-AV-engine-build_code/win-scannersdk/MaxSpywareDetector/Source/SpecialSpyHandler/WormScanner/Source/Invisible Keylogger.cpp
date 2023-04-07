/*=============================================================================
   FILE				: Invisible Keylogger.Cpp
   ABSTRACT			: Implementation of Special Spyware InvisibleKeylogger Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 26/02/2008
   NOTES			:
   VERSION HISTORY	:
					version: 2.5.0.41
					Resource : shweta
					Description: Added function to set the Upperfilter Data without iks entry .  
									
=============================================================================*/
#include "pch.h"
#include "Invisible Keylogger.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete - delete flag
					  CFileSignatureDb *pFileSigMan - signature db
	Out Parameters	: bool : true / false
	Purpose			: Checks and remove Invisible kelogger keyboard entry
	Author			: Shweta
	Description		: remove iks entry from the registry
--------------------------------------------------------------------------------------*/
bool CInvisibleKeylogger::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false ;

		if ( bToDelete )
		{
			SetNonIKSData();
		}
		else
		{
			CStringArray csArrData ;

			if ( !m_objReg.KeyExists(KEYBORD_REG_PATH,HKEY_LOCAL_MACHINE))
				return ( false ) ;

			m_csArrModifiedData . RemoveAll();
			m_objReg . Get ( KEYBORD_REG_PATH , _T ( "UpperFilters" ) , csArrData , HKEY_LOCAL_MACHINE ) ;

			for ( int i = 0 ; i < csArrData . GetCount() ; i++ )
			{
				if ( csArrData . GetAt ( i ) == _T ( "iks" ) )
				{
					m_bSplSpyFound = true ;
                    SendScanStatusToUI ( Special_RegVal,  m_ulSpyName , HKEY_LOCAL_MACHINE,
						CString(KEYBORD_REG_PATH) , CString(_T ( "UpperFilters" ))
						, REG_MULTI_SZ , LPBYTE(L"iks"), 8);
				}
				else
				{
					m_csArrModifiedData . Add ( csArrData . GetAt ( i ) ) ;
				}
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
		csErr.Format(_T("Exception caught in CInvisibleKeylogger::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false ;
}

/*-------------------------------------------------------------------------------------
	Function		: SetNonIKSData
	In Parameters	: void
	Out Parameters	: bool 
	Purpose			: Sets clean data
	Author			: Shweta
	Description		: remove iks entry from the registry
--------------------------------------------------------------------------------------*/
bool CInvisibleKeylogger :: SetNonIKSData()
{
	try
	{
		m_objReg . Set ( KEYBORD_REG_PATH , _T ( "UpperFilters" ) , m_csArrModifiedData, HKEY_LOCAL_MACHINE ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CInvisibleKeylogger::SetNonIKSData, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( true ) ;
}
