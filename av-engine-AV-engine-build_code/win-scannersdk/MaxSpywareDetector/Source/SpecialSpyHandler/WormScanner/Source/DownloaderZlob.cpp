/*======================================================================================
   FILE				: DownloaderZlob.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware DownloaderZlob
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
   CREATION DATE	: 12/22/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.62	
					Resource : Shweta
					Description: created this class to fix DownloaderZlob
					version: 2.5.0.69
					Resource : Shweta
					Description: Added function for the registry keys
========================================================================================*/

#include "pch.h"
#include "DownloaderZlob.h"
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
	Purpose			: Check and remove DownloaderZlob
	Author			: Shweta M
	Description		: This function checks for hiddent entries of tdssserv.sys
--------------------------------------------------------------------------------------*/
bool CDownloaderZlob  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		CStringArray csKeys , csMainKeys;
		csKeys.Add(CString(SERVICES_MAIN_KEY) + CString(_T("h8srtd.sys\\modules")));
		csKeys.Add(CString(SERVICES_MAIN_KEY) + CString(_T("tdssserv.sys\\modules")));

		csMainKeys.Add (CString(SERVICES_MAIN_KEY) + CString(_T("h8srtd.sys")));
		csMainKeys.Add (CString(SERVICES_MAIN_KEY) + CString(_T("tdssserv.sys")));

		for ( int iKey = 0 , iKeycount = (int)csMainKeys.GetCount() ; iKey < iKeycount; iKey++ )
		{
			CString csKey = csKeys.GetAt(iKey);
			CString csMainKey =  csMainKeys.GetAt(iKey);
			CString csWorm , csWorm1 ;

			CheckAndAdjustPermission();

			if (!bToDelete)
			{
				if ( m_objReg.KeyExists( csMainKey , HKEY_LOCAL_MACHINE ) )
				{
					m_objReg.AdjustPermissions ( HKEY_LOCAL_MACHINE , csKey );
					m_objReg.AdjustPermissions ( HKEY_LOCAL_MACHINE , csMainKey ) ;
					EnumKeynSubKey ( CString(HKLM) + CString(BACK_SLASH) + csMainKey , m_ulSpyName );
				}
			}
	        
			vector<REG_VALUE_DATA> vecRegValues;
			m_objReg.EnumValues( csKey, vecRegValues, HKEY_LOCAL_MACHINE);
			for ( size_t i = 0 ; i <  vecRegValues.size() ; i++ )
			{
				AddLogEntry (  CString(HKLM) + CString(BACK_SLASH) + csKey );
				CString csData;
				csData.Format(_T("%s"),(TCHAR*)vecRegValues[i].bData);
				if (! Checkforthefile (csData , bToDelete ) )
					continue;

				csWorm = CString(HKLM) + CString(BACK_SLASH) + csKey + CString(REG_SEPERATOR) + vecRegValues[i].strValue ;
				csWorm1 = CString(HKLM) + CString(BACK_SLASH) + csKey + CString(REG_SEPERATOR) + vecRegValues[i].strValue + CString(REG_SEPERATOR) + csData;
				if ( bToDelete )
				{
					AddInRestartDeleteList(RD_VALUE, m_ulSpyName, csWorm);
				}
				else
				{				
					SendScanStatusToUI ( Special_RegVal, m_ulSpyName , HKEY_LOCAL_MACHINE , csKey , vecRegValues[i].strValue,vecRegValues[i].Type_Of_Data,vecRegValues[i].bData ,vecRegValues[i].iSizeOfData);
				}
			}
		}
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		csKeys.RemoveAll();
		csMainKeys.RemoveAll();
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CXPProWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: Checkforthefile
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove 
	Author			: Shweta M
	Description		: This function checks for random folder in PFDIR of XP Protector 2008
--------------------------------------------------------------------------------------*/
bool CDownloaderZlob :: Checkforthefile ( CString csFile ,  bool bToDelete)
{
	FILE *pFile = NULL;
	if ( csFile.Find ( _T("\\\\?\\globalroot\\systemroot\\")) != -1 )
		csFile.Replace ( _T("\\\\?\\globalroot\\systemroot") , m_objSysInfo.m_strWinDir ) ;
	else
		csFile.Replace ( L"\\systemroot" , m_objSysInfo.m_strWinDir ) ;
	pFile = _wfsopen ( csFile , _T("r") ,SH_DENYNO );

	if (pFile)
	{
		fclose(pFile);
		if (! bToDelete )
		{
			SendScanStatusToUI ( Special_File ,  m_ulSpyName , csFile );
			m_bSplSpyFound = true ;
		}
		else
		{
			AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csFile);
			pFile = _wfsopen ( csFile , _T("w") ,SH_DENYNO );
			if(pFile)
				fclose ( pFile );
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndAdjustPermission
	In Parameters	: void
	Out Parameters	: 
	Purpose			: Set permission for the specific keys
	Author			: Shweta M
	Description		: Check for the random tdssserv varient key in registry and Set the permission
--------------------------------------------------------------------------------------*/
void CDownloaderZlob :: CheckAndAdjustPermission()
{
	CStringArray csMainKey ;
	CStringArray csNewKey ;
	CString csCreatedKey ;
	CArray <CString,CString> csArrKeys;

	csNewKey.RemoveAll();
	csMainKey.RemoveAll();

	csMainKey.Add ( _T("tdssserv.sys") ) ;
	csMainKey.Add ( _T("msqpdxserv.sys" )) ;
	csMainKey.Add ( _T("gaopdxserv.sys" )) ;

	if ( !m_objReg.EnumSubKeys ( SYSTEM_SUB_KEY , csArrKeys , HKEY_LOCAL_MACHINE , true ) )
		return;

	for ( int iregcnt = 0 ; iregcnt < csMainKey.GetCount() ; iregcnt++)
	{
		for ( int ikeycnt = 0; ikeycnt < csArrKeys.GetCount(); ikeycnt++ )
		{
			csCreatedKey =  CString(SYSTEM_SUB_KEY) + CString(BACK_SLASH) + csArrKeys.GetAt(ikeycnt) + CString(BACK_SLASH) + CString(_T("Services")) + CString(BACK_SLASH) +csMainKey.GetAt ( iregcnt )  ;
			if ( m_objReg.KeyExists ( csCreatedKey , HKEY_LOCAL_MACHINE ) )
			{
				m_objReg.AdjustPermissions ( HKEY_LOCAL_MACHINE , csCreatedKey ) ;
				EnumKeynSubKey ( CString(HKLM) + CString(BACK_SLASH) + csCreatedKey , m_ulSpyName );
			}
		}
	}
	csNewKey.Add ( CString(CLSID_KEY) + _T("{285AB8C6-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(CLSID_KEY) + _T("{385AB8C4-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(CLSID_KEY) + _T("{385AB8C5-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(CLSID_KEY) + _T("{296AB1C6-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(INTERFACE_PATH) + _T("{285AB8C6-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(INTERFACE_PATH) + _T("{385AB8C4-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(INTERFACE_PATH) + _T("{385AB8C5-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(INTERFACE_PATH) + _T("{296AB1C6-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(TYPELIB_PATH) + _T("{285AB8C6-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(TYPELIB_PATH) + _T("{385AB8C4-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(TYPELIB_PATH) + _T("{385AB8C5-FB22-4D17-8834-064E2BA0A6F0}") );
	csNewKey.Add ( CString(TYPELIB_PATH) + _T("{296AB1C6-FB22-4D17-8834-064E2BA0A6F0}") );
	
	for ( INT_PTR i = 0 , itotal = csNewKey.GetCount() ; i< itotal ; i++)
	{
		if ( m_objReg.KeyExists ( csNewKey.GetAt(i) , HKEY_LOCAL_MACHINE ) )
		{
			m_objReg.AdjustPermissions ( HKEY_LOCAL_MACHINE , csNewKey.GetAt(i) ) ;
			EnumKeynSubKey ( CString(HKLM) + CString(BACK_SLASH) + csNewKey.GetAt(i) , 1295 );
		}
	}
}