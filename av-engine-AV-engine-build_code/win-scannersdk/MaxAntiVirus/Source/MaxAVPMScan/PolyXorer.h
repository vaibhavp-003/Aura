/*======================================================================================
FILE				: PolyXorer.h
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
NOTES				: This is detection module for malware Xorer Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

class CPolyXorer : public CPolyBase
{
	bool GetXorerMZOffset(DWORD &dwOriFileOffset, DWORD &dwOriFileSize, DWORD &dwDecLevl, DWORD &dwDecLnth);
	bool CopyXorerData(DWORD dwReadStartAddr, 
					   DWORD dwWriteStartAddr, 
					   DWORD dwSizeOfData, 
					   DWORD dwKey = 0,
					   DWORD dwDecryptionSize = 0,
					   DWORD dwStartOfSecondDecryp = 0,
					   DWORD dwDisplacement = 0,
					   DWORD dwDecLevel = 6);
public:
	CPolyXorer(CMaxPEFile * pMaxPEFile);
	~CPolyXorer(void);

	int DetectVirus(void);
	int CleanVirus(void);
};
