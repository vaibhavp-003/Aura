/*======================================================================================
   FILE				: RemotelyAny.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware RemotelyAny
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
#include "remotelyany.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForRemotelyAnywhere
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove RemotelyAnywhere
	Author			: Anand
	Description		: this function checks for RAinit.dll which is in system32 folder
					  and is loaded from notify keys
--------------------------------------------------------------------------------------*/
bool CRemotelyAny :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;
		
		if ( !bToDelete )
		{
			CStringArray csNotifySubKey ; 
			TCHAR csData[MAX_PATH]  = {0};
			char cSubString[MAX_PATH] = {0};
			DWORD csDatalength = 0 ;
			CStringArray csArrLocations ;

			csArrLocations . Add ( REG_NOTIFY_ENTRY ) ;
			if ( m_bScanOtherLocations )
				csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_REG_NOTIFY_ENTRY) ) ;

			for ( int a = 0 ; a < csArrLocations . GetCount() ; a++ )
			{
				m_csArrRAFiles.RemoveAll();
				m_objReg.EnumSubKeys( csArrLocations [ a ] , csNotifySubKey, HKEY_LOCAL_MACHINE);

				for ( int i = 0; i < csNotifySubKey.GetCount(); i++)
				{
					CString csSubKey = csArrLocations [ a ] + BACK_SLASH + csNotifySubKey[i];
					csDatalength = sizeof ( csData ) ;
					m_objReg.Get( csSubKey , _T("DllName") , REG_SZ , (UCHAR*)csData, csDatalength , HKEY_LOCAL_MACHINE ) ;

					// Version: 18.1
					// Resource: Anand
					// Description: added ippspw.dll for ignoring
					if ( !StrStrI ( csData , _T("navlogon.dll") ) && !StrStrI ( csData , _T("ippspw.dll") ) )
					{
						if ( IsItRemotelyAnywhereFile(csData))
						{
							m_bSplSpyFound = true ;
							m_csArrRAFiles . Add ( csData ) ;
							SendScanStatusToUI(Special_File , m_ulSpyName , csData );
							SendScanStatusToUI(Special_RegKey , m_ulSpyName , HKEY_LOCAL_MACHINE,csSubKey ,0,0,0,0 ) ;
						}
					}
					memset ( csData , 0 , sizeof ( csData ) ) ;
 				}
			}
		}
		else
		{
			// enum m_csArrRAFiles files found array 
			for ( int i = 0 ; i < m_csArrRAFiles . GetCount() ; i++ )
			{
				// add all files in restart delete managed by system
				MoveFileEx ( m_csArrRAFiles [ i ] , NULL , MOVEFILE_DELAY_UNTIL_REBOOT ) ;
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
		csErr.Format( _T("Exception caught in CRemotelyAny::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsItRemotelyAnywhereFile
	In Parameters	: char *
	Out Parameters	: 
	Purpose			: determine if remotely anywhere file
	Author			: Anand
	Description		: check the signature and determine if its a remotely anywhere file
--------------------------------------------------------------------------------------*/
bool CRemotelyAny :: IsItRemotelyAnywhereFile ( LPCTSTR Filename)
{
	BYTE bMD5Signature[16] = {0};
	const BYTE MD5_REMOTELYANY[16] = {0x4C,0xB0,0x4A,0x31,0x3B,0x27,0x7F,0x27,0x4F,0x20,0xEA,0xC4,0x21,0x25,0xFC,0xAC};
	if(m_pFileSigMan->GetMD5Signature(Filename, bMD5Signature))
	{
		if(!memcmp(bMD5Signature, MD5_REMOTELYANY, 16))
			return true;
	}
	return false;
}