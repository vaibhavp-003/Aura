/*======================================================================================
FILE				: PolyBolzano.h
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
NOTES				: This is detection module for malware Bolzano Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

class CPolyBolzano : public CPolyBase
{
	DWORD m_dwCallPatchAdd;
	DWORD m_dwVirusStartOffset;

	bool DetectBolzano();
	
public:
	CPolyBolzano(CMaxPEFile *pMaxPEFile);
	~CPolyBolzano(void);

	int DetectVirus(void);
};
