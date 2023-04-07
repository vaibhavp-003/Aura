/*======================================================================================
FILE				: PolyInduc.h
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
NOTES				: This is detection module for malware Induc Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int INDUC_BUFF_SIZE 		= 0x5000;
const int INDUC_LG_BUFF_SIZE 	= 0x3000;

class CPolyInduc : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwTruncateSize;

	int DetectInducLG();
	int DetectInducIF();
	int DetectInducA();
	int DetectInducB();

	bool CheckInducBDecData(DWORD dwStartIndex, DWORD dwEndIndex);
	
public:
	CPolyInduc(CMaxPEFile *pMaxPEFile);
	~CPolyInduc(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};
