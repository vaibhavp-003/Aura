/*======================================================================================
   FILE				: CAecSys.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Aec Sys
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Yuvraj 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 18-3-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "AecSys.h"
#include "ExecuteProcess.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: 
	Purpose			: 
	Author			: Yuvraj
	Description		: main entry point of this class for spyware scanning
--------------------------------------------------------------------------------------*/
bool CAecSys:: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
 	try
	{
		CStringArray csFileArr;
		CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;

		if(IsStopScanningSignaled())
		{
			return(m_bSplSpyFound);
		}

		csFileArr.Add(CSystemInfo::m_strSysDir + _T("\\drivers\\aec.sys"));
		csFileArr.Add(CSystemInfo::m_strSysDir + _T("\\drivers\\aec.sys.bak"));

		csFileArr.Add(csFileArr[1]+_T(">\\??\\")+csFileArr[0]); //entry for rename

		csFileArr.Add(_T("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\aec	#@#iJn5mE0bB0"));
		csFileArr.Add(_T("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\aec	#@#fT1i5y7nM"));
		csFileArr.Add(_T("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\aec	#@#ygL7tV3n"));

		if(!bToDelete)
		{
			if(!_taccess(csFileArr[0],0))
			{
				if(!_taccess(csFileArr[1],0))
				{
					m_bSplSpyFound = true;
					SendScanStatusToUI(Special_File_Report, m_ulSpyName, csFileArr[1]);
					SendScanStatusToUI(Special_File_Report, m_ulSpyName, csFileArr[0]);
				}
			}
		}
		else
		{
			if(!_taccess(csFileArr[0],0))
			{		
				if( _tremove(csFileArr[0]) == -1 )
				{
					//Could not delete
					AddInRestartDeleteList(RD_FILE_BACKUP, m_ulSpyName, csFileArr[0]);
					AddInRestartDeleteList(RD_FILE_RENAME, m_ulSpyName, csFileArr[2]);
				}
				else
				{
					//deleted
					int result = _trename(csFileArr[1], csFileArr[0]);
					if( result != 0 )
					{
						//Could not rename 
						AddInRestartDeleteList(RD_FILE_RENAME, m_ulSpyName, csFileArr[2]);
					}
				}
			}

			//add reg values in ini
			AddInRestartDeleteList(RD_VALUE, m_ulSpyName, csFileArr[3]);
			AddInRestartDeleteList(RD_VALUE, m_ulSpyName, csFileArr[4]);
			AddInRestartDeleteList(RD_VALUE, m_ulSpyName, csFileArr[5]);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CAecSys::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry( csErr, 0, 0 );
	}
	
	return( false );
}

