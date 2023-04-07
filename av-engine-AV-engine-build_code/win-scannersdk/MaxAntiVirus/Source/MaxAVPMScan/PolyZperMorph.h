/*======================================================================================
FILE				: PolyZperMorph.h
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
NOTES				: This is detection module for malware ZperMorph Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once 
#include "PolyBase.h"

const int ZPERMORPH_BUFF_SIZE = 0x12000;

class CPolyZperMorph : public CPolyBase
{
    DWORD m_dwOriAEP;
	bool CheckSignature();
	bool GetInstruction(DWORD);

public:

	CPolyZperMorph(CMaxPEFile *pMaxPEFile);
	~CPolyZperMorph(void);

	int  DetectVirus();
	int  CleanVirus();
};