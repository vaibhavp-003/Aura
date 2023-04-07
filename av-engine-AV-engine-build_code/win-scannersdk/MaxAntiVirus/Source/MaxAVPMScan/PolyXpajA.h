/*======================================================================================
FILE				: PolyXpajA.h
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
NOTES				: This is detection module for malware Xpaj.A Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int XPAJ_A_BUFF_SIZE		= 0x150;
const int XPAJ_A_STUB_SIZE		= 0x16000;

class CPolyXpajA : public CPolyBase
{		
	DWORD   m_dwFirstKey;
	DWORD   m_dwSecondKey;
	DWORD   m_dwThirdKey;
	DWORD   m_dwFourthKey;
	DWORD   m_dwKey;
	DWORD   m_dwCalledAdd;
	DWORD   m_dwCalledAddOff;
	DWORD   m_dwECX;
	DWORD   m_dwEAX;
	DWORD   m_dwTruncateOff;

	int		DetectXpajA();
	int  	CheckXpajAInstructions();
	
	bool    GetEAX();	
	bool    GetFourthKey();
	bool    GetFirstDecryptionVal(DWORD dwStartRva, DWORD dwOffset);
	bool    GetSecondKey(DWORD dwKeyOffset);
	bool    GetSecondDecryptionVal(DWORD dwFlag);
	bool    GetOriginalValue();
	int     _CleanVirus();
	
public:
	CPolyXpajA(CMaxPEFile *pMaxPEFile);
	~CPolyXpajA(void);

	int		DetectVirus();
	int     CleanVirus();
};
