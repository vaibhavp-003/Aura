/*======================================================================================
FILE				: PolyHezhi.h
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
NOTES				: This is detection module for malware Hezhi Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

class CPolyHezhi :public CPolyBase
{
	typedef struct stMovs
	{
		BYTE bRegister;
		DWORD dwOffset;
	};
	DWORD	m_dwOrgDataOff;
	DWORD	m_dwStrDecOff;
	DWORD	m_dwOrgAEP;
public:
	CPolyHezhi(CMaxPEFile *pMaxPEFile);
	~CPolyHezhi(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

