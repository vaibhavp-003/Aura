/*======================================================================================
FILE				: PolyZMorph.h
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
NOTES				: This is detection module for malware Zmorph Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const DWORD ZMORPH_BUFF_SIZE = 0x4000;
const DWORD KEY_GEN_OFFSET = 0x4000;

class CPolyZMorph : public CPolyBase
{
	DWORD	m_dwOriginalAEP;
	
	bool	DecryptCode();
	int		CheckSignature();

public:
	CPolyZMorph(CMaxPEFile *pMaxPEFile);
	~CPolyZMorph(void);

	int		DetectVirus();
	int		CleanVirus();
};
