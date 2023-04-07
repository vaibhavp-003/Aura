/*======================================================================================
FILE				: PolyHatred.h
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
NOTES				: This is detection module for malware Poly Hatred Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

typedef struct _ROLROR_KEY 
{
	DWORD dwROL_RORType;
	DWORD dwROL_RORValue;
}ROLROR_KEY;

typedef struct _DECRYPTION_KEY 
{
	DWORD dwDecryptionKeyRegister;
	DWORD dwDecryptionKeyValue;
	DWORD dwDecryptionKey_Counter;
}DECRYPTION_KEY;

typedef struct _DECRYPTION_PARAMETERS 
{
	DWORD			dwOffsettoDecrypt_Register;
	DECRYPTION_KEY	m_objDecryptionKey;
	DWORD			dwDecryption_Operation1;
	DWORD			dwLoadDword_Register;
	ROLROR_KEY		m_objROL_ROR;
	DWORD			dwDecryption_Operation2;
	DWORD			dwDecryptionKey_Operation;
}DECRYPTION_PARAMETERS;

typedef struct _Detect_Type 
{
	DWORD dwLoopSize;
	DWORD dwAEPOffset;
	DWORD dwVirusCodeOffset;
}Detect_Type;

class CPolyHatred : public CPolyBase
{
	DECRYPTION_PARAMETERS m_objDecryptParameters;
	Detect_Type m_objDetectType;	
	
	DWORD	m_dwJumpOffset;
	DWORD	m_dwInstructionOffset;
	DWORD	m_dwRegisterUsed[8];

	bool	GetParameters(void);
	void	PerformOperation(DWORD,DWORD*,DWORD*);	

public:
	CPolyHatred(CMaxPEFile * pMaxPEFile);
	~CPolyHatred(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};



