/*=============================================================================
   FILE			 : RestorePoint.h
   ABSTRACT		 : 
   DOCUMENTS	 : 
   AUTHOR		 :
   COMPANY		 : Aura 
COPYRIGHT NOTICE :
				(C) Aura
				Created in 2009 as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 1/4/2009
   NOTES		:
VERSION HISTORY : April 1,2009. Created to add Restore Point feature to SD. Ashwinee Jagtap.
				
============================================================================*/
#include "pch.h"
#include <SRRestorePtAPI.h>

typedef BOOL (WINAPI *PFN_SETRESTOREPT)(PRESTOREPOINTINFO, PSTATEMGRSTATUS);
class CMaxRestorePoint
{
public:
	CMaxRestorePoint();
	~CMaxRestorePoint();
	bool StartSetRestorePointStatus(CString csRestorePoint);
	bool EndSetRestorePointStatus(void);
	bool CancelSetRestorePoint(void);

private:
	PFN_SETRESTOREPT	m_fnSRSetRestorePoint;
	RESTOREPOINTINFO	m_RestorePtInfo;
	STATEMGRSTATUS		m_SMgrStatus;
	HMODULE				m_hSrClient;
};