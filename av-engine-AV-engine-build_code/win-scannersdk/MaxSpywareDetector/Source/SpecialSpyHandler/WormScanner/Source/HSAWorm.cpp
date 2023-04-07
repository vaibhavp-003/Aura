/*====================================================================================
   FILE				: HSAWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Home Search Assistant
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
#include "hsaworm.h"
#include "remoteservice.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforHSA
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: checks and cleans HomeSearchAssistant
	Author			: 
	Description		: Searches for all the keyword list and returns true in 'bFound'
					  if all of them were found
--------------------------------------------------------------------------------------*/
bool CHSAWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if ( IsStopScanningSignaled() )
			return false ;

		CString		csExePath ;				//File Path To Delete		
		if( _EnumKeysForHSA ( SERVICES_MONITOR_KEY, HKEY_LOCAL_MACHINE, bToDelete, csExePath ))
			m_bSplSpyFound = true;
		
		if ( m_bSplSpyFound )
		{			
			CString			csData, csValue, csKey;		 			
			CString			csClassID;
		
			if ( m_objReg.KeyExists( IE_URLSEARCH_HOOKS, HKEY_LOCAL_MACHINE ) )
			{				


                vector<REG_VALUE_DATA> vecRegValues;
	            m_objReg.EnumValues(IE_URLSEARCH_HOOKS, vecRegValues, HKEY_LOCAL_MACHINE);                
                int nUrlHooks = (int)vecRegValues.size();
				for ( int iCount = 0 ; iCount < nUrlHooks ; iCount++ )
				{
                    csValue = vecRegValues[iCount].strValue;
                    csData.Format(_T("%s") , (TCHAR*)vecRegValues[iCount].bData);
					if ( _CheckRegKey ( BHO_REGISTRY_PATH, csValue, HKEY_LOCAL_MACHINE, csKey ) )
					{
						_RemoveBHOForHSA ( csValue );
                        SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_LOCAL_MACHINE ,  CString(BHO_REGISTRY_PATH) ,csKey ,0,0,0);
						SendScanStatusToUI ( Special_RegVal, m_ulSpyName , HKEY_LOCAL_MACHINE ,
                            CString(IE_URLSEARCH_HOOKS) ,vecRegValues[iCount].strValue,vecRegValues[iCount].Type_Of_Data,vecRegValues[iCount].bData,vecRegValues[iCount].iSizeOfData);
					}//End Of if to check for BHO present or not in system
				}//End Of for to read all search hook keys
			}//End Of If to check if search hook keys exist or not
			
			_GetAllRunEntries();
	
			_EnumKeysForHSA ( BHO_REGISTRY_INFO, HKEY_LOCAL_MACHINE, bToDelete, csExePath, csClassID);
			_EnumKeysForHSA ( BHO_REGISTRY_INFO, HKEY_LOCAL_MACHINE, bToDelete, csExePath, csClassID);

			_QueryReportIEMainPageValues ( START_PAGE_KEY, m_ulSpyName , HKEY_LOCAL_MACHINE);

			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;
				CString csUserKey = m_arrAllUsers.GetAt(iCnt);
				_QueryReportIEMainPageValues(csUserKey + BACK_SLASH + START_PAGE_KEY, m_ulSpyName, HKEY_USERS);
			}

			return true;
		}//End Of if to check for Hsa Traces present		
	
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHSAWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumKeysForHSA
	In Parameters	: CString , HKEY , bool , CString 
	Out Parameters	: CString&
	Purpose			: getting infected class ID
	Author			: 
	Description		: returns infected subkey of ClassID
--------------------------------------------------------------------------------------*/
bool CHSAWorm :: _EnumKeysForHSA ( CString csMainKey , HKEY hHiveKey , bool bRemove , CString csExePath , CString& csDllClassID )
{
	try
	{
		long lVal = 0;    
		CStringArray	spyExes, csSubKeyArr ;
		CString			csSubKey;		
		CString			strSubKey;
		HKEY			hSubKey;

		m_objReg.EnumSubKeys ( csMainKey , csSubKeyArr , hHiveKey ) ;

		int nSubKeys = (int)csSubKeyArr.GetCount();
		for ( long i = 0; i < nSubKeys; i ++ )
		{
			csSubKey = csMainKey + BACK_SLASH + csSubKeyArr.GetAt( i );
			csSubKey.MakeLower () ;
			strSubKey = _T("");
			
			if( ( _CheckRegKey ( csSubKey , _T("localserver") , hHiveKey , strSubKey ) )	|| 
				  _CheckRegKey ( csSubKey , _T("localserver32") , hHiveKey , strSubKey )	|| 
				  _CheckRegKey ( csSubKey , _T("InprocServer32") , hHiveKey , strSubKey )  )
			{				
				csSubKey = csSubKey + BACK_SLASH + strSubKey ;				
				lVal = RegOpenKeyEx ( hHiveKey , csSubKey , 0 , KEY_READ | KEY_QUERY_VALUE , &hSubKey );
				if ( lVal != ERROR_SUCCESS )
				{
					RegCloseKey ( hSubKey );
					continue ;
				}

				CString csData;
				m_objReg.Get ( csSubKey , BLANKSTRING , csData , hHiveKey );

				if( csData == BLANKSTRING )
				{
					RegCloseKey ( hSubKey );
					continue ;
				}
                if ( ( csData.Find(_T(".dll")) != -1 ) )
				{
					if ( csData.MakeLower() == csExePath.MakeLower() )
					{
						csDllClassID = csSubKeyArr.GetAt ( i ) ;
						RegCloseKey ( hSubKey );						
						return true;
					}//End Of If To Check for the dll name
				}//end of if to check for the value of dll

				bool bFound = false;				
				CString sTemp;
				for ( int k = 0 ; k < m_csRunEntries.GetCount(); k ++ )
				{
					sTemp = m_csRunEntries.GetAt(k);
					if ( csData . MakeLower () == sTemp . MakeLower () )
					{
						bFound = true ; 
						spyExes.Add ( csData ) ;						
					}//End Of If To Make The ExePath LowerCase
				}//End Of For Loop To Check With Entries Caught And Add The ExePath To Remove it
				
				if( csData.MakeLower() == csExePath.MakeLower() )
					bFound = true;
                
				//Delete key in CLSID
				if( bFound )
				{
					csData = csSubKeyArr .GetAt ( i ) ;
                    SendScanStatusToUI ( Special_RegKey , m_ulSpyName , HKEY_LOCAL_MACHINE,csMainKey + CString(BACK_SLASH) + csData ,0,0,0,0 );
				}//End of if to check wether Required Key found

				RegCloseKey ( hSubKey ) ;
			}//End of if to Check csSubKey is LocalServer Or LocalServer32
		}//End Of For to traverse the clsid and find the exe
		
		//Now Kill all spy exes and delete run entries
		for ( int j=0 ; j < spyExes . GetCount ( ) ; j ++ )
		{
            strSubKey = spyExes . GetAt ( j );		
			//Remove spyware exe
			if ( m_objEnumProcess.IsProcessRunning ( strSubKey , false ) )
				SendScanStatusToUI (Special_Process ,  m_ulSpyName , strSubKey );  

			if ( strSubKey.GetLength () > 4 )
				SendScanStatusToUI ( Special_File , m_ulSpyName , strSubKey );

			csSubKey = strSubKey.Mid ( strSubKey.ReverseFind( '\\' )+1 , strSubKey.GetLength() );
			SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_LOCAL_MACHINE, CString(RUN_REG_PATH) 
                , csSubKey , REG_SZ, (LPBYTE)(LPCTSTR)strSubKey,strSubKey.GetLength()+sizeof(TCHAR));
		}//End of For Loop To Kill All Spy Exe
	}//End Of Try Block
	
	catch (...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHSAWorm::_EnumKeysForHSA, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}//End Of function EnumKeysForHSA

 
/*-------------------------------------------------------------------------------------
	Function		: EnumKeysForHSA
	In Parameters	: CString , HKEY , bool 
	Out Parameters	: CString& 
	Purpose			: Checks all SubKeys under given key
	Author			: 
	Description		: stops sevice and removes registry keys and sends them to UI
--------------------------------------------------------------------------------------*/
bool CHSAWorm :: _EnumKeysForHSA ( CString csMainKey , HKEY hHiveKey , bool bShouldDelete , CString& csExePath )
{	
	try 
	{
		if ( IsStopScanningSignaled() )
			return false;

		bool bFound = false ;
		CStringArray	csSubKeyArr ;
		CString			csSubKey ;
		m_objReg.EnumSubKeys ( csMainKey , csSubKeyArr , hHiveKey ) ;

		for ( long i = 0 ; i < csSubKeyArr . GetCount ( ) ; i ++ )
		{
			csSubKey = csSubKeyArr.GetAt( i );
			csSubKey.MakeUpper();
			csSubKey = csSubKey.Left( 4 );
			if ( csSubKey != _T(" 11F") )
				continue ;
			
			csSubKey = csSubKeyArr.GetAt ( i ) ;
			bFound = true ;
			CString csFileName;
			CRemoteService objRemService ;

			objRemService.StopRemoteService ( csSubKey , true , csFileName ) ;
			
			/*The Exe Of Home Search Assistant Appends /s at End Of Path At 11F Registory Key.*/
			csExePath = csFileName = csFileName.Left( csFileName.GetLength() - 3 );
			//The Path Cleared.

			if ( m_objEnumProcess . IsProcessRunning ( csExePath , false ) )
				SendScanStatusToUI (Special_Process ,  m_ulSpyName ,  csExePath );

			if ( csFileName.GetLength () > 4 )
				SendScanStatusToUI ( Special_File , m_ulSpyName , csExePath  );

			csSubKey = csMainKey + BACK_SLASH + csSubKeyArr . GetAt ( i ) ;
			SendScanStatusToUI ( Special_RegKey , m_ulSpyName , HKEY_LOCAL_MACHINE,  csSubKey,0,0,0,0) ;
			break ;
		}//End Of for to traverse the current controle set
		
		return bFound;

	}//End Of try block
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHSAWorm::_EnumKeysForHSA, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}//End of function EnumKeysForHSA


/*-------------------------------------------------------------------------------------
	Function		: CheckRegKey
	In Parameters	: CString , CString , HKEY , CString
	Out Parameters	: bool * 
	Purpose			: Checks subkeys for given string
	Author			: 
	Description		: enumerates all keys and looks for strings in it and returns in 'strSubKey'
--------------------------------------------------------------------------------------*/
bool CHSAWorm :: _CheckRegKey ( CString csMainKey , CString csCompare , HKEY hHiveKey , CString &strSubKey )
{	
	try
	{
		bool bFound = false;
		CString csSubKey;
		CStringArray csSubKeyArr ;

		m_objReg.EnumSubKeys ( csMainKey , csSubKeyArr , hHiveKey ) ;
		int nSubKeys = (int)csSubKeyArr.GetCount();

		for ( long i = 0; i < nSubKeys; i++ )
		{
			csSubKey = csSubKeyArr.GetAt( i );
			csSubKey.MakeLower();
			int iRet = csSubKey.Replace(_T("b{"),_T("{"));

			if ( csSubKey.Find( csCompare.MakeLower()) != -1)
			{
				if(iRet == 0)			
					strSubKey = csSubKey;
				else
					strSubKey = _T("b") + csSubKey;
				bFound = true;
				break ;
			}		
		}//End Of for loop to traverse the clsid loop
		return bFound;
	}//End Of try Block
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHSAWorm::_CheckRegKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}//End Of the Function to check reg key

/*-------------------------------------------------------------------------------------
	Function		: RemoveBHOForHSA
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: Remove the BHO
	Author			: 
	Description		: remove the given BHO
--------------------------------------------------------------------------------------*/
void CHSAWorm :: _RemoveBHOForHSA ( CString csCLSID )
{
   	try 
	{
		CStringArray csSubKeyArr ;
		CString csSubKey ;
		m_objReg.EnumSubKeys( BHO_REGISTRY_INFO, csSubKeyArr, HKEY_LOCAL_MACHINE);

		int nKeys = (int)csSubKeyArr.GetCount();
		for ( long i = 0 ; i < nKeys; i++ )
		{			
			csSubKey = csSubKeyArr.GetAt( i );
			if ( csSubKey.MakeLower() == csCLSID.MakeLower() )
			{
				CFileFind objFile;
				CString csKey = CString(BHO_REGISTRY_INFO) + CString(BACK_SLASH) 
					+ csSubKey + CString(_T("\\InprocServer32")) ;
				CString csData;
				m_objReg.Get( csKey , BLANKSTRING , csData, HKEY_LOCAL_MACHINE );
				csData.MakeLower();
				if( csData.Find( _T(".dll") ) != -1)
				{
					if( objFile.FindFile( csData ) )					
                        SendScanStatusToUI ( Special_File , m_ulSpyName , csData  );

                    SendScanStatusToUI (Special_RegKey,  m_ulSpyName , HKEY_LOCAL_MACHINE , CString(CLSID_KEY) + csSubKey , 0,0,0,0 ) ;
					return ;				
				}//End Of if to check if the file is a dll
			}//End Of if to check for in class id == required one
		}//End Of for loop to traverse all the sub keys under class ID
	}//End Of Try Block
	
	catch (...) 
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHSAWorm::_RemoveBHOForHSA, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}//End Of function Remove Bho For HSA

/*-------------------------------------------------------------------------------------
	Function		: _QueryReportIEMainPageValues
	In Parameters	: CString, CString, HKEY
	Out Parameters	: bool
	Purpose			: Remove the search infection
	Author			: 
	Description		: remove the search URLs
--------------------------------------------------------------------------------------*/
bool CHSAWorm::_QueryReportIEMainPageValues(CString csIEMainKey, ULONG ulSpyName, HKEY hive)
{
	CString			csClassID ;	
	CString			csValue, csData;
    
    vector<REG_VALUE_DATA> vecRegValues;
	m_objReg.EnumValues(csIEMainKey, vecRegValues, hive);
	
    int nValCount = (int)vecRegValues.size();
	for ( int iCount = 0; iCount < nValCount; iCount++ )
	{
        csValue		=	vecRegValues[iCount].strValue;
		csClassID	=	csValue ;
		csClassID.MakeLower();

		if ( ( !csClassID.Compare( _T("default_search_url") ) ) || ( !csClassID.Compare( _T("search bar") ) ) 
			|| (!csClassID.Compare( _T("search page") ) ) || ( !csClassID.Compare( _T("searchassistant") ) ) )
		{			
            SendScanStatusToUI ( Special_RegVal,ulSpyName, hive, csIEMainKey , vecRegValues[iCount].strValue,vecRegValues[iCount].Type_Of_Data,vecRegValues[iCount].bData,vecRegValues[iCount].iSizeOfData );
		}				
	}
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetAllRunEntries
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Getting all run entries
	Author			: Sandeep B.S.
	Description		: Getting all run entries with exe
--------------------------------------------------------------------------------------*/
void CHSAWorm::_GetAllRunEntries()
{
	try
	{
		CStringArray	csArrVal, csArrData;
		CString		csData , csValue;

		m_objReg.QueryDataValue ( RUN_REG_PATH , csArrVal, csArrData , HKEY_LOCAL_MACHINE );

		for ( int iCount = 0 ; iCount < csArrVal . GetCount() ; iCount++ )
		{
			csValue = csArrVal.GetAt(iCount);
			csData  = csArrData.GetAt(iCount);

			if ( csData . Find (_T(".exe")) != - 1)
				m_csRunEntries.Add( csData );			
		}
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHSAWorm::_GetAllRunEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}