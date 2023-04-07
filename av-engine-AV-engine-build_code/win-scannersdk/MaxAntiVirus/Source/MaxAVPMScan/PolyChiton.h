/*======================================================================================
FILE				: PolyChiton.h
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
NOTES				: This is detection module for malware Chiton Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int CHITON_BUFF_SIZE = 1024;

class CPolyChiton : public CPolyBase
{
	int GetChitonGenParam(BYTE *bBuffer, DWORD dwBytesRead);
	DWORD m_dwDecKeyBuffOffset, m_dwVirusCodeOffset, m_dwDecLength, m_dwPatchedOffset;
	int   m_iDirection;

public:
	CPolyChiton(CMaxPEFile *pMaxPEFile);
	~CPolyChiton(void);

	int DetectVirus(void);
	int CleanVirus(void);
};
