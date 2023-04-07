/*======================================================================================
FILE				: PolyVulcas.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Vulcas Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int MAX_RVA_VALUES = 0x100;

typedef struct _NameTableAPI
{
	DWORD dwRVAValues;
	DWORD Index;
}NameTableAPI; 

class CPolyVulcas : public CPolyBase
{
	BYTE	byJumptoVirus[0x06];   //Taking a buffer to replace the patched call
	DWORD	m_dwVirusOffset;
	DWORD 	m_dwStartFileOffset;
	DWORD 	m_dwCntInChunks;
	DWORD 	m_dwRVAOffset;
	DWORD 	m_dwAPIIndex;
	DWORD 	m_dwKernelNameOffset;
	WORD	m_wImportSection;

	DWORD 	ReadRVAValues(bool, DWORD, DWORD, NameTableAPI *, bool);
	DWORD	CheckOddEven(BYTE);
	void 	SortRVAValues(NameTableAPI *,DWORD);
	void 	CheckParameters();
	bool	CheckForValidAPI(NameTableAPI *,DWORD,bool);
	bool 	CheckFurtherForVirus();
	bool 	Rem0Operation();
	bool 	Rem1Operation();
	bool 	Rem12Operation();
	bool 	Rem2Operation();
	bool 	Rem3Operation();
	bool 	Rem4Operation();
	bool 	Rem5Operation();
	bool 	Rem7Operation();
	void 	RemAllOperations();

	bool	GetImportAndNameTableRVA(char* szDllName, IMAGE_IMPORT_DESCRIPTOR &objIMPORTTable, DWORD *pdwIndexOffset = NULL);

public:
	CPolyVulcas(CMaxPEFile *pMaxPEFile);
	~CPolyVulcas(void);

	int		DetectVirus(void);
	int		CleanVirus(void);	
};
