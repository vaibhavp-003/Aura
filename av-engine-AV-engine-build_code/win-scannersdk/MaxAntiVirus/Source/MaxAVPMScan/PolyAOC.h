/*======================================================================================
FILE				: PolyAOC.cpp
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
NOTES				: This is detection module for malwares AOC Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int AOC_BUFF_SIZE = 0x1500;

class CPolyAOC : public CPolyBase
{
	DWORD m_dwKey1;
	DWORD m_dwKey2;
	int m_iKeyOffset;

	bool CheckSignature(DWORD dwOffset);
	bool DecryptionBumbulby();
public:

	CPolyAOC(CMaxPEFile *pMaxPEFile);
    ~CPolyAOC(void);

	int DetectVirus();
	int CleanVirus();

};