/*======================================================================================
FILE				: PolyDetnat.h
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
NOTES				: This is detection module for malware Poly Detnat Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int DETNAT_BUFF_SIZE = 0x100;

class CPolyDetnat :
	public CPolyBase
{
	DWORD	m_dwVirusExecStartOffset;
	DWORD	m_dwOriginalAEP;
	
	bool	IsDetnat_E();
	bool	GetDetnatEParameter(); 

public:
	CPolyDetnat(CMaxPEFile *pMaxPEFile);
	~CPolyDetnat(void);

	int 	DetectVirus(void);
	int 	CleanVirus(void);
};
