/*======================================================================================
FILE				: PolyDion.h
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
NOTES				: This is detection module for malware Dion Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBase.h"

typedef struct _tagGetParamTable
{
	DWORD VirusCodeRVA;
	DWORD VirusCodeFileOffset;
	DWORD OriginalCodeoffset;
	DWORD Size;
}GetParamTable;

typedef struct _tagReplaceStructure
{
	BYTE OriginalPatch[8];
	GetParamTable GetTable[5];
}ReplaceStructure;

class CPolyDion : public CPolyBase
{
	DWORD m_dwCallAddr;
	DWORD m_dwBytesToRead;

	ReplaceStructure m_stGetTable;

	bool CheckStubName(TCHAR FPath[MAX_PATH]);
	bool CheckInitialParameters();
	bool CheckFurtherParameters();

public:
	CPolyDion(CMaxPEFile *pMaxPEFile);
	~CPolyDion(void);

	int DetectVirus(void);
	int CleanVirus(void);	
};
