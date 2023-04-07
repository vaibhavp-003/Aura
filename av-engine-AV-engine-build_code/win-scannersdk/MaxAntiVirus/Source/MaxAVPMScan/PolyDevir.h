/*======================================================================================
FILE				: PolyDevir.h
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
NOTES				: This is detection module for malware Devir Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int DEVIR_BUFF_SIZE = 0x1000;
typedef struct
{
	enum DEC_TYPE	DecType;
	enum DEC_TYPE   DecKeyChangeType;
	DWORD			dwDecKey;
	DWORD			dwkeyChangeValue;
	DWORD			dwDecLength;
	DWORD			dwDecStartOffset;
	DWORD			dwIndex;
}DEVIR_DEC_INFO,*PDEVIR_DEC_INFO;

class CPolyDevir : public CPolyBase
{
	DEVIR_DEC_INFO	m_objDevirDecInfo;
	BYTE			*m_bBuffer;
	
public:
	CPolyDevir(CMaxPEFile *pMaxPEFile);
	~CPolyDevir(void);

	int DetectVirus();
	int CleanVirus();

	int DetectAndGetDecParameter();
	int DecryptBuffer();
};

