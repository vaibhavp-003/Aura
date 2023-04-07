/*=============================================================================
   FILE			 : RestorePoint.cpp
   ABSTRACT		 : 
   DOCUMENTS	 : 
   AUTHOR		 : 
   COMPANY		 : Aura 
 COPYRIGHT NOTICE:
				(C) Aura
      			 Created in 2009 as an unpublished copyright work.  All rights reserved.
     		     This document and the information it contains is confidential and
      		     proprietary to Aura.  Hence, it may not be 
      		     used, copied, reproduced, transmitted, or stored in any form or by any 
      		     means, electronic, recording, photocopying, mechanical or otherwise, 
      		     with out the prior written permission of Aura
CREATION DATE    : 1/4/2009
   NOTES		 :
VERSION HISTORY  : April 1,2009. Created to add Restore Point feature to SD. Ashwinee Jagtap.
============================================================================*/

#include "RestorePoint.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMaxRestorePoint::CMaxRestorePoint()
{
	m_fnSRSetRestorePoint = NULL;
	m_hSrClient = NULL;
	SecureZeroMemory(&m_RestorePtInfo, sizeof(RESTOREPOINTINFO));
	SecureZeroMemory(&m_SMgrStatus, sizeof(STATEMGRSTATUS));

}

CMaxRestorePoint::~CMaxRestorePoint()
{
	if(m_hSrClient != NULL)
	{
		::FreeLibrary(m_hSrClient);
		m_hSrClient = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: StartSetRestorePointStatus
In Parameters	: Description to be given to Restore point
Out Parameters	: BOOL
Purpose			: This Function creates Restore Point.
Author			: Ashwinee Jagatp.
--------------------------------------------------------------------------------------*/
bool CMaxRestorePoint::StartSetRestorePointStatus(CString csDescription)
{
	bool bRet = false;

	// Initialize the RESTOREPOINTINFO structure
	m_RestorePtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;

	// Notify the system that changes are about to be made.
	// An application is to be installed.
	m_RestorePtInfo.dwRestorePtType = APPLICATION_INSTALL;

	// RestPtInfo.llSequenceNumber must be 0 when creating a restore point.
	m_RestorePtInfo.llSequenceNumber = 0;

	// String to be displayed by System Restore for this restore point.
	wcscpy_s(m_RestorePtInfo.szDescription, csDescription);

	// Load the DLL, which may not exist on Windows server
	if(NULL == m_hSrClient)
	{
		m_hSrClient = ::LoadLibrary(_T("srclient.dll"));

		if(NULL == m_hSrClient)
		{
			return bRet;
		}
	}

	// If the library is loaded, find the entry point
	m_fnSRSetRestorePoint = (PFN_SETRESTOREPT)GetProcAddress(m_hSrClient, "SRSetRestorePointW");
	if(NULL == m_fnSRSetRestorePoint)
	{
		AddLogEntry(_T("Failed to find SRSetRestorePoint.\n"));
		return bRet;
	}

	bRet = m_fnSRSetRestorePoint(&m_RestorePtInfo, &m_SMgrStatus) == FALSE ? false : true;
	if(!bRet)
	{
		DWORD dwErr;
		dwErr = m_SMgrStatus.nStatus;
		if(dwErr == ERROR_SERVICE_DISABLED)
		{
			AddLogEntry(_T("System Restore is turned off."));
			return bRet;
		}

		CString csErr;
		csErr.Format(_T("%d"), dwErr);
		AddLogEntry(_T("Failure to create the restore point.Error --> %s"),csErr);
	}
	else
		AddLogEntry(_T("Restore point created\n"));

	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: EndSetRestorePointStatus
In Parameters	:
Out Parameters	: BOOL
Purpose			: This Function Updates the status of Restore Point created.
Author			: Ashwinee Jagatp.
--------------------------------------------------------------------------------------*/
bool CMaxRestorePoint::EndSetRestorePointStatus()
{
	bool bRet = false;

	// Update the RESTOREPOINTINFO structure to notify the
	// system that the operation is finished.
	m_RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;

	// End the system change by using the sequence number
	// received from the first call to SRSetRestorePoint.
	m_RestorePtInfo.llSequenceNumber = m_SMgrStatus.llSequenceNumber;

	// Notify the system that the operation is done and that this
	// is the end of the restore point.
	bRet = m_fnSRSetRestorePoint(&m_RestorePtInfo, &m_SMgrStatus) == FALSE ? false : true;
	if(false == bRet)
	{
		DWORD dwErr;
		dwErr = m_SMgrStatus.nStatus;
		CString csErr;
		csErr.Format(_T("%d"), dwErr);
		AddLogEntry(_T("Failure to end the restore point.Error --> %s"),csErr);

		return bRet;
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: CancelSetRestorePoint
In Parameters	:
Out Parameters	: bool
Purpose			: This Function Deletes Restore Point created.
Author			: Ashwinee Jagatp.
--------------------------------------------------------------------------------------*/
bool CMaxRestorePoint::CancelSetRestorePoint(void)
{
	bool bRet = false;
	// Update the structure to cancel the previous restore point.
	m_RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;

	m_RestorePtInfo.dwRestorePtType = CANCELLED_OPERATION;

	// This is the sequence number returned by the previous call.
	m_RestorePtInfo.llSequenceNumber = m_SMgrStatus.llSequenceNumber;

	// Cancel the previous restore point
	bRet = m_fnSRSetRestorePoint(&m_RestorePtInfo, &m_SMgrStatus) == FALSE ? false : true;
	if(false == bRet)
	{
		DWORD dwErr;
		dwErr = m_SMgrStatus.nStatus;
		CString csErr;
		csErr.Format(_T("%d"), dwErr);
		AddLogEntry(_T("Failure to cancel the restore point.Error --> %s"),csErr);
		return bRet;
	}

	AddLogEntry(_T("Restore point canceled."));

	return bRet;
}