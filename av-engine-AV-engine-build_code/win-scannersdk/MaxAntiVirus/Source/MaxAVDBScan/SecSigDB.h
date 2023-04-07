/*======================================================================================
FILE				: SecSigDb.h
ABSTRACT			: Secondary Signature Db Manager
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: Secondary Signature Db Manager
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include <windows.h>

#ifndef CSECSIGDB
	#define CSECSIGDB
#endif

#ifndef RETURN_VALUES
	#include "RetValues.h"
#endif

typedef struct _SECSIGINFO
{
	unsigned int	m_iSigID;
	char			m_szSecSig[MAX_SEC_SIG_LEN];
}SECSIGDBINFO;

class CSecSigDB
{
	HANDLE			m_hSecDBMap;
	HANDLE			m_hSecDB;
	LPVOID			m_pSecDBView;

	int	OpenSecDBFileEx(DWORD dwDBSize);
	int InitSecSigStruct(void);

public:
	CSecSigDB(void);
	~CSecSigDB(void);
	
	SECSIGDBINFO	m_SecDBInfo;
	bool			m_bIsValidSecSigDB;
	TCHAR			m_szTempDBName[MAX_PATH];
	
	int OpenSecDB(DWORD dwDBSize);
	int WriteSecSignature(unsigned int iSigID, LPCSTR szSecSig);
	int GetSecondarySig(unsigned int iSigID);
	int CloseSecDB(void);
};
