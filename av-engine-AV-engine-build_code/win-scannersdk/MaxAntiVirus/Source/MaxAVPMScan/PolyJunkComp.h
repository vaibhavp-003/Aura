/*======================================================================================
FILE				: PolyJunkComp.h
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
NOTES				: This is detection module for malware JunkComp Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int JUNK_COMP_BUFF_SIZE = 0x250;

typedef struct stJunkCompReg
{
	char szReg[4];
	DWORD dwRegValue;
}ST_JUNK_COMP_REG;

enum eOperation
{
	COPY = 0,
	ADD,
	SUB,
	XOR
};

class CPolyJunkComp : public CPolyBase
{
	DWORD m_dwVirusBodyStart;
	ST_JUNK_COMP_REG stJunkCompReg[9];
	char szDefaultReg[8][4];
	char szVirCodeReg[4];

	bool GetJunkCompParam();
	bool ValidateJmpAddressAndReadBuffer(DWORD dwJmpAdd);
	bool ValidateVirusBodyStartAddress(DWORD dwVirusCodeStartAdd);
	bool UpdateRegister(char *szReg, DWORD dwRegValue, int iOperation, bool bValidate);

public:
	CPolyJunkComp(CMaxPEFile *pMaxPEFile);
	~CPolyJunkComp(void);

	int		DetectVirus(void);
};