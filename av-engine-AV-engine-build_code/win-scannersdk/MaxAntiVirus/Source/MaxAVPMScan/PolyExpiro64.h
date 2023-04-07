/*======================================================================================
FILE				: PolyExpiro64.h
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
NOTES				: This is detection module for malware Expiro (x64) Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"


const int EXPIRO64_BUFF_SIZE = 0x500;

class CPolyExpiro64 :	public CPolyBase
{
	int		m_iExpiroType;
	DWORD   m_dwOAEPExpiro,
			m_dwPatchSize,
			m_dwSizeOfLastSec; // In case of virus code upended to last section.
	bool	m_AppendToLastSec;

public:
	CPolyExpiro64(CMaxPEFile *pMaxPEFile);
	~CPolyExpiro64(void);
	
	int		DetectVirus(void);
	int		CleanVirus(void);
};