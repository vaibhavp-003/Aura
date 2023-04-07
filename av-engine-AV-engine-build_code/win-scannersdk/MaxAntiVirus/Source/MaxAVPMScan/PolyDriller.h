/*======================================================================================
FILE				: PolyDriller.h
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
NOTES				: This is detection module for malware Driller Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int DRILLER_A_CODE_SIZE = 0x7000;
const int DRILLER_B_CODE_SIZE = 0x5200;

typedef enum
{
	NO_DRILLER = 0,
	DRILLER_A,
	DRILLER_B,
}DRILLER_TYPE;

class CPolyDriller:public CPolyBase
{	
	DWORD	m_dwType;
	DWORD	m_dwKey;
	DWORD	m_dwOriAEP;
	DWORD	m_dwKeyChngType;
	DWORD	m_dwKeyChngKey;

	DRILLER_TYPE	m_eDrillerType;

	int GetDecryptionParameter(CEmulate &objEmulate);
	int GetKyChangeParameter(CEmulate &objEmulate);
	int DoDecryption(DWORD dwIndex);
	int DecryptKey();
	
	int CleanDrillerA();
	int CleanDrillerB();
	
	int DetectDrillerA();
	int DetectDrillerB();
	
	bool IsDriller();

public:
	CPolyDriller(CMaxPEFile *pMaxPEFile);
	~CPolyDriller(void);

	int DetectVirus();
	int CleanVirus();
};
