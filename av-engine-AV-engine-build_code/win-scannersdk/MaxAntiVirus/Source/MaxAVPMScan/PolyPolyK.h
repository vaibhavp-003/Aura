/*======================================================================================
FILE				: PolyPolyk.h
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
NOTES				: This is detection module for malware PolyK Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBase.h"

class CPolyPolyk : public CPolyBase
{	
	BYTE m_bXorKey, m_bAddKey, m_bUpXorKey;
	WORD m_wCnt1, m_wOP, m_wOP1, m_wOP2, m_wOP3;

	bool SetOperatn(DWORD dwStartOffset);
	bool FoundKey(DWORD OffSet, WORD wCnt, DWORD dwBytes2Read, int flag);
	bool DoDecryption(BYTE m_bXorKey, WORD wCnt);
	
public:
	CPolyPolyk(CMaxPEFile *pMaxPEFile);
	~CPolyPolyk(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

