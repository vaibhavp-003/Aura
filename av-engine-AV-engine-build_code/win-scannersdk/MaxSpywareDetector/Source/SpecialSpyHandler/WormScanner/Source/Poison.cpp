/*======================================================================================
   FILE				: Poison.cpp
   ABSTRACT			: This class is used for scanning  Backdoor Poison worm
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Vaibhav Desai
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 13/08/2009
   NOTE				:
   VERSION HISTORY	:
					version  : 2.5.1.03			
					Resource : vaibhav
					Description: created this class to fix Poison worm
========================================================================================*/

#include "pch.h"
#include "Poison.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check Poison worm
	Author			: Vaibhav Desai
	Description		: This function checks for Poison Registry entry's
--------------------------------------------------------------------------------------*/
bool CPoisonWorm ::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{				
		CString csSubKey;		
		CString csData ;
		CStringArray csSubKeyArr, csValueArr;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		m_objReg.EnumSubKeys(ACTIVESETUP_INSTALLCOMPONENTS, csSubKeyArr, HKEY_LOCAL_MACHINE );
		
		for(long i = 0; i < csSubKeyArr.GetCount(); i++ )
		{

			if(IsStopScanningSignaled())
				break ;

			csSubKey = (CString)ACTIVESETUP_INSTALLCOMPONENTS + BACK_SLASH + csSubKeyArr.GetAt(i);			

			vector<REG_VALUE_DATA> vecRegValues;			
			m_objReg.EnumValues( csSubKey, vecRegValues, HKEY_LOCAL_MACHINE );
			
			if( vecRegValues.size() > 2 )
			{
				continue;
			}			
			
			for( unsigned long i = 0 ; i < vecRegValues.size(); i++ )
			{

				if(IsStopScanningSignaled())
					break;

				if( ( _wcsicmp ( vecRegValues[i].strValue, _T( "StubPath" ) ) ) != 0  )
				{
					continue;
				}
			
				csData.Format( _T("%s"), (TCHAR *) vecRegValues[i].bData );		

				if(csData.IsEmpty())
				{
					continue;
				}
				if  (_taccess(csData , 0 ) != 0 )
					continue;

				CFileVersionInfo	oFileVersionInfo;				
				if( oFileVersionInfo.DoTheVersionJob ( csData, false ) )
				{
					SendScanStatusToUI ( Special_RegVal , 7567 , HKEY_LOCAL_MACHINE , csSubKey , vecRegValues[i].strValue ,vecRegValues[i].Type_Of_Data ,vecRegValues[i].bData , vecRegValues[i].iSizeOfData );
					SendScanStatusToUI ( Special_File , 7567 , csData );
				}
				else
				{
					TCHAR szCompanyName [ MAX_PATH ] = { _T("DummyData") } ;

					if ( oFileVersionInfo . GetCompanyName ( csData , szCompanyName ) )
					{
						if ( 0 == szCompanyName [ 0 ] )
						{
							SendScanStatusToUI ( Special_RegVal , 7567 , HKEY_LOCAL_MACHINE , csSubKey ,vecRegValues[i].strValue ,vecRegValues[i].Type_Of_Data ,vecRegValues[i].bData , vecRegValues[i].iSizeOfData );
						}
					}
				}
			}
		}

		return true;
	
	}//End of try block 	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CPoisonWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}