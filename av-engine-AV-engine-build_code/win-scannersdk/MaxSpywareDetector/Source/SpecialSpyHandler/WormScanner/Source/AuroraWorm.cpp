/*====================================================================================
   FILE				: AuroraWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Aurora
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: 
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
                    version: 2.5.0.72
                    Resource : Shweta M.
					Description: Excluded the entry samsung\\fw liveupdate\\fwmanager.exe
========================================================================================*/

#pragma once
#include "pch.h"
#include "AuroraWorm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and fix aurora spyware
	Author			: 
	Description		: Aurora makes entries in _T("winlogon\shell") of nail.exe
					  In windows folder it makes scvproc.exe (service) and in system32 drpmon.dll
					  and Spoolsv.exe and hooks itself with explorer
					  when the bIsDelete flag comes true all entries are scanned and sent to UI
					  and when the flag is false it fixes those entries
--------------------------------------------------------------------------------------*/
bool CAuroraWorm::ScanSplSpy(bool bIsDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		CString		csData;
		CStringArray csArrLocations ;

		csArrLocations.Add ( WINLOGON_REG_KEY ) ;
		if ( m_bScanOtherLocations )
			csArrLocations.Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_WINLOGON_REG_KEY) ) ;

		for ( int i = 0 ; i < (int)csArrLocations.GetCount() ; i++ )
		{
			m_objReg.Get( csArrLocations [ i ] , _T("Shell") , csData , HKEY_LOCAL_MACHINE ) ; // check nail.exe,SvcProc.exe,DrPMon.dll
			csData.MakeLower();

			if ( csData.Find( _T("nail.exe") ) != -1 ) 
			{
				m_bSplSpyFound = true;
				if ( bIsDelete )
				{
					CString csExplorer( _T("Explorer.exe"));
					m_objReg.Set( csArrLocations [ i ] , _T("Shell") , csExplorer , HKEY_LOCAL_MACHINE ) ;//reset the shell data with explorer.exe
				}
			}
		}

		if(IsStopScanningSignaled())
			return false;

		if( _EnumValuesForAurora())
			m_bSplSpyFound = true;

		if( FindKillReportProcess( m_objSysInfo.m_strWinDir +  BACK_SLASH + _T("Nail.exe"), m_ulSpyName , bIsDelete))
			m_bSplSpyFound = true;
		
		if( FindKillReportProcess( m_objSysInfo.m_strWinDir +  BACK_SLASH + _T("Spoolsv.exe"), m_ulSpyName , bIsDelete))
			m_bSplSpyFound = true;
		
		if( FindKillReportService( m_objSysInfo.m_strWinDir +  BACK_SLASH + _T("SvcProc.exe"), _T("SvcProc"), m_ulSpyName , bIsDelete))
			m_bSplSpyFound = true;
		
		if( FindKillReportDll( m_objSysInfo.m_strWinDir +  BACK_SLASH + _T("DrPMon.dll"), m_ulSpyName, 
								m_objSysInfo.m_strWinDir +  BACK_SLASH + _T("Spoolsv.exe"), bIsDelete))
			m_bSplSpyFound = true;

		
		m_bSplSpyFound = bIsDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CAuroraWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsAuroraEntry
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: Determine whether the file is an aurora file
	Author			: 
	Description		: checks for _T(" r") or checks agains signatures
--------------------------------------------------------------------------------------*/
bool CAuroraWorm::_IsAuroraEntry(CString csRegData)
{
	try
	{
        //version 2.5.0.72
        // (Anwar)->This is okay for now. If at a later time, we have an additional entry,
        // we, need to move these entries to some array or list and the code below needs to be modified,
        // to read the list or array.
        
		csRegData.MakeLower(); // Conver to lower case for better find result
		if ( csRegData . Find ( _T ("samsung\\fw liveupdate\\fwmanager.exe") ) != -1 )
            return false;

		if(csRegData.Right(2) == _T(" r"))
			return true;

		BYTE bMD5Signature[16] = {0};
		if(m_pFileSigMan->GetMD5Signature(csRegData, bMD5Signature))
		{
			const BYTE MD5_AURORA_1[16] = {0x98,0x47,0xC2,0x77,0xCC,0xCA,0xE9,0xE3,0xA4,0xF9,0x05,0xC2,0xAB,0x3C,0x41,0xD2};
			const BYTE MD5_AURORA_2[16] = {0x4C,0xA2,0xC1,0x81,0x60,0xB4,0xBF,0xA7,0xFD,0xED,0x68,0x9E,0xB2,0xF8,0x11,0x0B};
			const BYTE MD5_AURORA_3[16] = {0x8B,0x29,0x47,0xD9,0x32,0x0C,0xF6,0x05,0x95,0x93,0x5A,0xC5,0xB4,0xC3,0x19,0x78};

			if(!memcmp(bMD5Signature, MD5_AURORA_1, 16) || !memcmp(bMD5Signature, MD5_AURORA_2, 16) || !memcmp(bMD5Signature, MD5_AURORA_3, 16))
				return true;
		}
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CAuroraWorm::_IsAuroraEntry, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _EnumValuesForAurora
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Checks Run entries of aurora in HKLM
	Author			: 
	Description		: enumerates all the entries in run registry key  and determines if its 
					  an aurora entry if such entry is found sets the spyware found flag true for aurora
--------------------------------------------------------------------------------------*/
bool CAuroraWorm::_EnumValuesForAurora()
{
	try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;
		
		CString			csData, csValue;
		CStringArray	csArrLocations ;

		csArrLocations.Add ( RUN_REG_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations.Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;
	
		for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
		{
            vector<REG_VALUE_DATA> vecRegValues;            
	        m_objReg.EnumValues(RUN_REG_PATH, vecRegValues, HKEY_LOCAL_MACHINE);			
            for(size_t iCount=0; iCount < vecRegValues.size(); iCount++)
			{
				if(IsStopScanningSignaled())
					return false;

				csValue = vecRegValues[iCount].strValue;
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[iCount].bData);

				// an aurora entry either matches the signature or has an _T(" r") as a parameter
				if(_IsAuroraEntry(csData))
				{
					m_bSplSpyFound = true;				
                    SendScanStatusToUI (Special_RegVal ,  m_ulSpyName ,HKEY_LOCAL_MACHINE , CString(RUN_REG_PATH) ,csValue, vecRegValues[iCount].Type_Of_Data, vecRegValues[iCount].bData, vecRegValues[iCount].iSizeOfData);
					
					csData.Replace(_T(" r"), _T(""));
					SendScanStatusToUI ( Special_File, m_ulSpyName , csData);
					SendScanStatusToUI ( Special_Process, m_ulSpyName , csData);
				}
			}
		}

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CAuroraWorm::_IsAuroraEntry, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

