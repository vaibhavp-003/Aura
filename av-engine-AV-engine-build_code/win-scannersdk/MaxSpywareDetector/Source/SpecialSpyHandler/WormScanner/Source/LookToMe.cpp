/*=============================================================================
   FILE				: Lok2me.Cpp
   ABSTRACT			: Implementation of Special Spyware look2me Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta M
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 
   NOTES			:
   VERSION HISTORY	: 
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
=============================================================================*/

#include "pch.h"
#include "looktome.h"
#include <afxpriv.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForLook2Me
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove look2me
	Author			: Shweta M
	Description		: searches files and adds them to restart delete
--------------------------------------------------------------------------------------*/
bool CLookToMe :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( !bToDelete )
		{
			// reset the array used to store the Look to me files, on checking
			csArrL2MFiles.RemoveAll () ;
			csArrKeyToDelete.RemoveAll ();

			CheckNotifyKeys(bToDelete);
			if ( csArrL2MFiles.GetCount() )
			{
				CheckCLSIDforData( bToDelete );
				CheckforBHOEntry();//2.5.0.8
			}

			if ( csArrKeyToDelete.GetCount() )
				CheckRegistryforLook2Me( bToDelete );
		}
		else
		{
			//Version: 16.8
			//Resource: Anand
			// enum l2m files found array 
			for ( int i = 0 ; i < csArrL2MFiles . GetSize() ; i++ )
			{
				//Version: 17.2
				//Resource: Anand
				// adding one more method for delete at restart logging for both the functions return value

				MoveFileEx ( csArrL2MFiles [ i ] , NULL , MOVEFILE_DELAY_UNTIL_REBOOT ) ;
				CFileOperation::ReplaceFileOnRestart ( csArrL2MFiles [ i ] , NULL ) ;
			}

			for ( int i = 0 ; i < csArrKeyToDelete .GetSize () ; i++ )
			{
				AddInRestartDeleteList(RD_KEY, m_ulSpyName, csArrKeyToDelete.GetAt(i));
			}
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLookToMe::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}//End of function to check and delete look to me

/*-------------------------------------------------------------------------------------
	Function		: CheckCLSIDforData
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: checks look2me file entries in clsid
	Author			: Shweta M
	Description		: checks look2me file entries in clsid
--------------------------------------------------------------------------------------*/
bool CLookToMe :: CheckCLSIDforData (bool bToDelete )
{
	try
	{
		CStringArray csClsidArr ;
		CStringArray csArrVal , csArrData ;
		TCHAR csData [512]  = {0};
		DWORD csDatalength = 0 ;
		CStringArray csArrLocations ;

		csArrLocations . Add ( ACTIVEX_REGISTRY_INFO ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("Classes\\CLSID")) ) ;

		for ( int j = 0 ; j < csArrLocations .GetCount() ; j++ )
		{
			m_objReg . EnumSubKeys ( csArrLocations [ j ] , csClsidArr , HKEY_LOCAL_MACHINE ) ;

			for ( int i = 0 ; i < csClsidArr.GetCount() ; i++ )
			{
				CString csSubKey = csArrLocations [ j ] + BACK_SLASH + csClsidArr . GetAt ( i ) + _T("\\InprocServer32") ;

				if ( m_objReg.KeyExists ( csSubKey , HKEY_LOCAL_MACHINE ) )
				{
					csDatalength = sizeof(csData) ;                    
					m_objReg.Get ( csSubKey , BLANKSTRING , REG_SZ , (UCHAR*)csData, csDatalength, HKEY_LOCAL_MACHINE) ;
					
					for(int k = 0; k < static_cast<int>(csArrL2MFiles.GetCount()); k++)
					{
						if ( !StrCmpI ( csArrL2MFiles . GetAt( k ) , static_cast<LPCTSTR>(csData) ) )
						{
							csArrKeyToDelete.Add ( CString(HKLM) + CString(BACK_SLASH) + csArrLocations [ j ] 
							+ CString(BACK_SLASH) + csClsidArr . GetAt ( i ) );
							m_bSplSpyFound = true ;
                            SendScanStatusToUI (Special_RegKey , m_ulSpyName , HKEY_LOCAL_MACHINE , csArrLocations [ j ] + CString(BACK_SLASH) + csClsidArr . GetAt ( i ), 0, 0, 0, 0 );
							break;
						}
					}
				}
			}
		}

		return true;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLookToMe :: CheckCLSIDforData, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRegistryforLook2Me
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Make entry to UI
	Author			: Anand
	Description		: Make entry to UI
--------------------------------------------------------------------------------------*/
bool CLookToMe::CheckRegistryforLook2Me ( bool bDelete )
{	
	try
	{
		CStringArray csArrVal , csArrData ;
		TCHAR csData[512] ={0} ;
		DWORD csDataLength =0 ;
		CStringArray csArrLocations ;

		csArrLocations . Add ( CV_SHELL_EXT_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_CV_SHELL_EXT_PATH) ) ;

		csDataLength = sizeof(csData);
		for( int i=0 ; i < csArrKeyToDelete . GetCount() ; i++ )
		{
			for ( int j = 0 ; j < csArrLocations . GetCount() ; j++ )
			{
               
				m_objReg.Get ( csArrLocations [ j ] , csArrKeyToDelete.GetAt(i), REG_SZ , (UCHAR*)csData, csDataLength , HKEY_LOCAL_MACHINE) ;
				if ( _tcscmp ( csData , _T("") ) )
				{
					m_bSplSpyFound = true ;
                    SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_LOCAL_MACHINE , csArrLocations [ j ], csArrKeyToDelete.GetAt ( i ) ,REG_SZ ,(LPBYTE)csData, int(wcslen(csData)*sizeof(TCHAR)));                    
				}
				memset ( csData , 0 , sizeof ( csData ) ) ;
			}
		}
		
		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLookToMe::CheckRegistryforLook2Me, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckNotifyKeys
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check notify keys
	Author			: Shweta M
	Description		: check notify keys and check version tab for the dlls
--------------------------------------------------------------------------------------*/
bool CLookToMe :: CheckNotifyKeys (bool bToDelete)
{
	try
	{
		CStringArray	csNotifySubKey ; 
		TCHAR			csData[MAX_PATH]  = {0};
		char			cSubString [MAX_PATH] = {0};
		DWORD			csDatalength = 0 ;
		CFileVersionInfo	m_oFileVersionInfo;
		CStringArray	csArrLocations ;

		csArrLocations . Add ( REG_NOTIFY_ENTRY ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_REG_NOTIFY_ENTRY) ) ;

		for ( int j = 0 ; j < csArrLocations . GetCount() ; j++ )
		{
			m_objReg . EnumSubKeys ( csArrLocations [ j ] , csNotifySubKey , HKEY_LOCAL_MACHINE ) ;
			for ( int i = 0 ; i < csNotifySubKey . GetCount() ; i++ )
			{
				bool bSuccess = false ;
				CString		csSubKey  =	csArrLocations [ j ] + csNotifySubKey.GetAt(i);
				csDatalength = sizeof ( csData ) ;

				bSuccess = m_objReg . Get ( csSubKey , _T("DllName") , REG_SZ , (UCHAR*)csData, csDatalength , HKEY_LOCAL_MACHINE ) ;

				if ( bSuccess )
				{
					if ( IsFilePresentInSystem ( csData , _countof ( csData ) ) )
					{
						//Version:  19.0.0.15
						//Resource: Anand ( checking for navlogon.dll )
						CString csHoldName ( csData ) ;
						csHoldName.MakeLower() ;

						if ( ( -1 == csHoldName . Find ( _T("navlogon.dll") ) ) && !LookUpWhiteList ( csData , KEY_ID_NOTIFY ) )
						{
							if ( m_oFileVersionInfo . DoTheVersionJob ( csData , false ) )
							{
								m_bSplSpyFound = true ;
								csArrL2MFiles . Add ( csData ) ;
								SendScanStatusToUI ( Special_File , 7022 , csData   ) ;
								SendScanStatusToUI ( Special_RegKey , 7022 , HKEY_LOCAL_MACHINE, csSubKey , 0,0,0,0 ) ;
							}
						}
					}
				}
				memset ( csData , 0 , sizeof ( csData ) ) ;
 			}
		}

		return false ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLookToMe::CheckNotifyKeys, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckforBHOEntry
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check BHO keys for l2m infected files.
	Author			: Shweta M
	Description		: Scans BHO Key for the the Files found as look 2me files.
--------------------------------------------------------------------------------------*/
bool CLookToMe :: CheckforBHOEntry()
{
	try
	{
		CStringArray csArrBHOKeys;
		CRegistry m_objReg ;
		TCHAR chData [MAX_PATH]  = {0};
		DWORD iDatalength = MAX_PATH;
		CString csSubKey ;
		CStringArray	csArrLocations ;

		csArrLocations . Add ( BHO_REGISTRY_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_BHO_REGISTRY_PATH) ) ;

		for ( int j = 0 ; j < csArrLocations . GetCount() ; j++ )
		{
			m_objReg.EnumSubKeys ( csArrLocations [ j ] , csArrBHOKeys , HKEY_LOCAL_MACHINE ) ;

			for ( int i = 0 ; i < csArrBHOKeys . GetCount() ; i++ )
			{
				CStringArray	csArrCLSIDLocations ;

				csArrCLSIDLocations . Add ( CLSID_KEY ) ;
				if ( m_bScanOtherLocations )
					csArrCLSIDLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid")) ) ;

				for ( int k = 0 ; k < csArrCLSIDLocations . GetCount() ; k++ )
				{
					CString csKey = csArrCLSIDLocations [ k ] + csArrBHOKeys [ i ] + _T("\\InprocServer32") ;

					iDatalength = sizeof ( chData ) ;
					m_objReg . Get ( csKey , _T("") , REG_SZ , (UCHAR*)chData, iDatalength , HKEY_LOCAL_MACHINE ) ;
					if ( 0 == chData [ 0 ] )
						continue ;

					for (int l = 0 ; l < static_cast<int>(csArrL2MFiles.GetCount()) ; l++ )
					{
						if ( StrStrI ( csArrL2MFiles . GetAt ( l ) , chData ) )
						{
							csArrKeyToDelete . Add ( CString(HKLM) + CString(BACK_SLASH) 
								+ csArrLocations [ j ] + CString(BACK_SLASH) + csArrBHOKeys . GetAt(i) ) ;
							SendScanStatusToUI ( Special_RegKey, m_ulSpyName , HKEY_LOCAL_MACHINE ,  csArrLocations [ j ] + CString(BACK_SLASH) + csArrBHOKeys . GetAt ( i ) , 0,0,0,0) ;
						}
					}

					memset ( chData , 0 , sizeof ( chData ) ) ;
				}
			}
		}

		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CheckforBHOEntry::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}