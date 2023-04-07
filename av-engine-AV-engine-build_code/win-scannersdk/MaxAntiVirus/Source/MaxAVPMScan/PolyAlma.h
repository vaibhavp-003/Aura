/*======================================================================================
FILE				: PolyAlma.h
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
NOTES				: This is detection module for malwares Alma Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

typedef struct Alma_PARAMETERS
{
	DWORD dwStbSiz;
	DWORD dwEBP;

	// Decryption Loop 1
	DWORD dwDecryptionOffset1;
	DWORD dwDecryptionCount1;
	DWORD dwCnstSubKey1;
	DWORD dwCnstLeaKey1;
	DWORD dwDecryptionXorKey1;

	// Decryption Loop 2
	DWORD dwDecryptionOffset2;
	DWORD dwDecryptionCount2;
	DWORD dwCnstLeaKey2;
	BYTE  dwDecryptionSubKey2;
}Alma_Struct;


class CPolyAlma : public CPolyBase
{
	Alma_Struct m_objAlma_Struct;
	DWORD		m_dwOriginalAEP;
	
	bool	Get1stDeCryptionParameters(void);
	bool    Get2ndDeCryptionParameters(void);
	int     CleanAlma2414(void) ;
	int     CleanAlma5319(void);
	int		GetOrignalAep(void);
public:
	CPolyAlma(CMaxPEFile *pMaxPEFile);
	~CPolyAlma(void);
	
	int		DetectVirus(void);
	int		CleanVirus(void);	
};


