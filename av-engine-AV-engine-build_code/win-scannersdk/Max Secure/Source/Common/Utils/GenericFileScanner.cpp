/*=============================================================================
   FILE				: GenericFileScanner.cpp
   ABSTRACT			: Class for generic scanning of files based on heuristic factors
   DOCUMENTS		: 
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created in 2008 as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 23/04/2008
   NOTES			:
   VERSION HISTORY	: 
					Version: 19.0.0.062
					Resource: Anand Srivastava
					Description: Added generic scanner for files
=============================================================================*/
#include "pch.h"
#include "verinfo.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include "PathExpander.h"
#include "GenericFileScanner.h"

/*-------------------------------------------------------------------------------------
Function		: CheckIfFileSuspicious
In Parameters	: const CString&
Out Parameters	: bool
Purpose			: checks if the file present in this CLSID is suspicious
Author			: Anand Srivastava
Description		: check if the file is suspicious
--------------------------------------------------------------------------------------*/
bool CGenericFileScanner::CheckFileInCLSID(const CString& csCLSID, CString& csData,
										   const CStringArray& csArrSpyLocation, bool bX64)
{
	try
	{
		CString csKeyToRead;
		CRegistry objReg;

		if(bX64)
		{
			csKeyToRead = ACTIVEX_REGISTRY_INFO_X64 + csCLSID + L"\\InprocServer32";
		}
		else
		{
			csKeyToRead = CLSID_KEY + csCLSID + L"\\InprocServer32";
		}
		if(!objReg.Get(csKeyToRead, L"", csData, HKEY_LOCAL_MACHINE))
		{
			return (false);
		}

		if(csData == _T(""))
		{
			return false;
		}

		csData.MakeLower();

		// resolve the filename
		CPathExpander objPathExpander;
		objPathExpander.Expand(csData);
		objPathExpander.ExpandSystemTags(csData, bX64);

		return CheckIfFileSuspicious(csData, csArrSpyLocation, bX64);
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CGenericFileScanner::CheckIfFileSuspicious, Error : %d"),
					GetLastError());
		AddLogEntry(csErr, 0, 0);
	}
	return (false);
}


/*-------------------------------------------------------------------------------------
Function		: CheckIfFileSuspicious
In Parameters	: const CString&
Out Parameters	: bool
Purpose			: checks if the file is present and is suspicious
Author			: Anand Srivastava
Description		: check files for version tab and sysdir or windir location
--------------------------------------------------------------------------------------*/
bool CGenericFileScanner::CheckIfFileSuspicious(const CString& csFullFilename,
												const CStringArray &csArrSpyLocation,
												bool bX64)
{
	try
	{
		CString csFilename = csFullFilename;
		CString csFilePath, csPath;
		bool bPathMatch = false;
		int iLastSlash = 0;

		if(_taccess(csFilename, 0))
		{
			return (false);
		}

		iLastSlash = csFilename.ReverseFind(_T('\\'));
		if(-1 == iLastSlash)
		{
			return (false);
		}
		csPath = csFilename.Left(iLastSlash);

		for(INT_PTR iCount = 0, iTotalCount = csArrSpyLocation.GetCount();
					iCount < iTotalCount; iCount++)
		{
			csFilePath = csArrSpyLocation.GetAt(iCount);
			if(_tcsnicmp(csPath, csFilePath, csPath.GetLength()) == 0)
			{
				bPathMatch = true;
				break;
			}
		}
		if(!bPathMatch)
		{
			return (false);
		}

		CFileVersionInfo oFileVersionInfo;
		if(!oFileVersionInfo.DoTheVersionJob(csFilename, false))
		{
			return (false);
		}
		return (true);
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CGenericFileScanner::CheckIfFileSuspicious, Error : %d"),
						GetLastError());
		AddLogEntry(csErr, 0, 0);
	}
	return (false);
}

