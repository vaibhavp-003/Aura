/*======================================================================================
   FILE				: RandomDrivers.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware RandomDrivers
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
   CREATION DATE	: 04/06/2008
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "RandomDrivers.h"
#include "PathExpander.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove Random Drivers
	Author			: Shweta
	Description		: This function checks for the random driver entries
--------------------------------------------------------------------------------------*/
bool CRandomDriversWorm  :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		CFileVersionInfo objFileVer;
		CStringArray csArrSubKey ;
		CString csValue , csImagePath;
		
		//Enumerate registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.
		m_objReg.EnumSubKeys ( SERVICES_MAIN_KEY , csArrSubKey ,HKEY_LOCAL_MACHINE ); 

		for ( int  i = 0; i < csArrSubKey.GetCount() ; i++ )
		{
			if (! m_objReg.Get (SERVICES_MAIN_KEY + csArrSubKey.GetAt(i) , _T("Group" ) , csValue , HKEY_LOCAL_MACHINE ) )
				continue;

			if ( csValue.MakeLower() != L"scsi class" )
				continue;

			if (! m_objReg.Get ( SERVICES_MAIN_KEY + csArrSubKey.GetAt(i) , _T("ImagePath") , csImagePath , HKEY_LOCAL_MACHINE ) )
				continue;

			csImagePath.MakeLower();
	
			CPathExpander objPE;
			objPE.ExpandSystemTags ( csImagePath ) ;

			if ( !_taccess_s ( csImagePath , 0 ) )
			{
				if ( objFileVer.DoTheVersionJob ( csImagePath , bToDelete ) ||
					!objFileVer.Open(csImagePath))
				{
					DWORD dwErrorControl = 0;

					SendScanStatusToUI (Special_File ,  m_ulSpyName , csImagePath);
					if(m_objReg.Get(SERVICES_MAIN_KEY + csArrSubKey.GetAt(i), _T("ErrorControl"), dwErrorControl, HKEY_LOCAL_MACHINE))
					{
						if(0 != dwErrorControl && 1 != dwErrorControl)
						{
							EnumKeynSubKey ( CString(_T("HKEY_LOCAL_MACHINE\\")) + CString(SERVICES_MAIN_KEY) +
												csArrSubKey.GetAt(i), m_ulSpyName);
						}
					}

					AddInRestartDeleteList(RD_FILE_BACKUP, m_ulSpyName, csImagePath);
				}
			}
		}

		csImagePath = m_csSysDir + _T("\\drivers\\ndisvvan.sys");
		if(!_taccess_s(csImagePath, 0))
		{
			SendScanStatusToUI(Special_File, m_ulSpyName, csImagePath);
			AddInRestartDeleteList(RD_FILE_BACKUP, m_ulSpyName, csImagePath);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CRandomDriversWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
