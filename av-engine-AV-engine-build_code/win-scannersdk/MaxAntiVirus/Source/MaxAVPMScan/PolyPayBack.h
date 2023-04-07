/*======================================================================================
FILE				: PolyPayBack.h
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
NOTES				: This is detection module for malware PayBack Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const DWORD DECRYPTN_LOOP_SZ	= 0x7D;
const DWORD VIRUS_BODY_SZ		= 0x1329;

typedef struct Payback_PARAMETERS
{
	DWORD   dwOrignalAep;
	DWORD   dwDecryptionLOff;
	DWORD   dwDecryptionKey;
	DWORD   dwAEPBuffOffset;
	DWORD   dwVirusSignOffset;
	DWORD   dwVirusBodyOffset;
}Payback_Struct;

class CPolyPayBack : public CPolyBase
{
	Payback_Struct m_objPayback_Struct;

	bool	GetDecryptionParameters(void);
	bool	DecryptAepBuffer(void);
public:
	CPolyPayBack(CMaxPEFile *pMaxPEFile);
	~CPolyPayBack(void);

	int		DetectVirus(void);
	int		CleanVirus(void);	
};
