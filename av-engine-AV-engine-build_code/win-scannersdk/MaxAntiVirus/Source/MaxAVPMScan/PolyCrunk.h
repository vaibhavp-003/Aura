/*======================================================================================
FILE				: PolyCrunk.h
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
NOTES				: This is detection module for malware Crunk Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBase.h"

class CPolyCrunk: public CPolyBase
{
	DWORD m_dwCallPatchAdd;
	DWORD m_dwVirusStartOffset;
	DWORD m_dwCallAddRVA;
	DWORD m_dwDecStartOffset;
	DWORD m_dwVariant;
	bool GetCrunkParam();
	int DecryptBuffer(DWORD, DWORD, DWORD, DWORD, DWORD);
	
public:
	CPolyCrunk(CMaxPEFile *pMaxPEFile);
	~CPolyCrunk(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
