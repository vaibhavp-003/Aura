/*======================================================================================
FILE				: PolyAlman.h
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
NOTES				: This is detection module for malwares Alman Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int ALMAN_BUFF_SIZE			= 0x300;
const int ALMAN_B_BUFF_SIZE			= 0x49E;
const int ALMAN_PATCHED_BUFF_SIZE	= 0x1000;

enum Alman_Infection_Type
{
	ALMAN_A = 1,
	ALMAN_B
};

typedef struct _tagALMAN_STRUCT
{
	BYTE	byDecryptionKey;
	DWORD	dwAddorXOR;
	DWORD	dwStartAddress;
	DWORD	dwSizeofReplacement;
	DWORD	dwDecCounter;
}Alman_Struct;

class CPolyAlman : public CPolyBase
{
	Alman_Infection_Type	m_eInfectionType;
	Alman_Struct			m_objAlmanStruct;

	//Added 02 June 2011 by Rupali for promopt delete action for corrupt sample.
	DWORD	m_dwAEP;
	DWORD	m_dwSetEndAddress;
	DWORD	m_dwTempEBP_8;
	DWORD	m_dwCounter;
	DWORD	m_dwOriginalAEP;
	BYTE	*m_pbyAlmanBPatchedBuff;
	WORD	m_wInfectedSecNo;

	int		GetAlmanParamters();
	int		CleanAlman_4CD();
	int		CleanAlmanA();
	int		CleanAlmanB();
	int		DecryptAlmanB();
	bool	DecryptAlman_4CD();
	bool	DecryptAlmanA();

public:
	CPolyAlman(CMaxPEFile *pMaxPEFile);
	~CPolyAlman(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
