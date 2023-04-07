/*======================================================================================
FILE				: PolyMinit.h
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
NOTES				: This is detection module for malware Minit Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const BYTE SIZE_OF_MINIT_SIGNATURE = 24;

class CPolyMinit: public CPolyBase
{
	LPCTSTR m_pFileName;

	DWORD	m_dwUnMapAddress, m_dwSize;

public:
	CPolyMinit(CMaxPEFile *pMaxPEFile, LPCTSTR pFilename);
	~CPolyMinit(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
