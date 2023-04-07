/*======================================================================================
   FILE				: COSFiles.Cpp
   ABSTRACT			: This class is used for scanning for System Files 
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
   CREATION DATE	: 03/04/2009
   NOTE				:
   VERSION HISTORY	: 
					version: 2.5.0.74
					Resource : Shweta
					Description: Fix Missing or infected files 
========================================================================================*/

#include "pch.h"
#include "COSFiles.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and replaces Infected or Missing System File
	Author			: 
	Description		: Check if valid OS file is there and replaces the file if match not found 
--------------------------------------------------------------------------------------*/
bool COSFiles::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		if(!bToDelete)
		{
			CFileVersionInfo objFVI;
			WIN32_FILE_ATTRIBUTE_DATA  stFileAttr = {0};
			DWORD dwOrgFileSize = 0, dwBkpFileSize = 0;
			CString csOrgFilePath, csBkpFilePath, csFileName;
			struct
			{
				CString csOrgPath;
				CString csBkpPath;
				CString csFileName;
			}stFilesToCheck[] = 
			{
				{CSystemInfo::m_strSysDir, CSystemInfo::m_strSysDir + _T ("\\dllcache"), _T("\\userinit.exe")},
				{CSystemInfo::m_strSysDir, CSystemInfo::m_strSysDir + _T ("\\dllcache"), _T("\\comres.dll")}
			};

			if(IsStopScanningSignaled())
			{
				return false;
			}

			for(int i = 0; i < _countof(stFilesToCheck); i++)
			{
				if(IsStopScanningSignaled())
				{
					break;
				}

				csOrgFilePath = stFilesToCheck[i].csOrgPath + stFilesToCheck[i].csFileName;
				csBkpFilePath = stFilesToCheck[i].csBkpPath + stFilesToCheck[i].csFileName;

				if(0 == _taccess_s(csOrgFilePath, 0) && 0 == _taccess_s(csBkpFilePath, 0)) //both files present
				{
					if(GetFileAttributesEx(csOrgFilePath, GetFileExInfoStandard, &stFileAttr))
					{
						dwOrgFileSize = stFileAttr.nFileSizeLow;
						if(GetFileAttributesEx(csBkpFilePath, GetFileExInfoStandard, &stFileAttr))
						{
							dwBkpFileSize = stFileAttr.nFileSizeLow;
							if(dwOrgFileSize != dwBkpFileSize)
							{
								if(objFVI.DoTheVersionJob(csOrgFilePath, false))
								{
									m_bSplSpyFound  = true ;
									SendScanStatusToUI(Special_File, m_ulSpyName, csOrgFilePath);
								}
							}
						}
					}
				}
				else if(0 != _taccess_s(csOrgFilePath, 0) && 0 == _taccess_s(csBkpFilePath, 0)) // org absent, bkp present
				{
					m_bSplSpyFound = true;
					SendScanStatusToUI(Special_File_Report, m_ulSpyName, csOrgFilePath);
					CopyFile(csBkpFilePath, csOrgFilePath, TRUE);
				}
			}
		}

		m_bSplSpyFound = bToDelete? false: m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in COSFiles::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}
