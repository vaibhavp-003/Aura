/*======================================================================================
FILE				: PolyCTX.h
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
NOTES				: This is detection module for malware CTX Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "PolyBase.h"

const int CTX6886_BUFF_SIZE = 0x4000;

enum eCTX_Decryption_Mode
{
	DEFAULT_OPERATION = 0,
	BYTE_XOR = 0x101,
	BYTE_ADD,
	BYTE_NOT,
	BYTE_SUB,

	DWORD_NOT = 0x1001,
	DWORD_SUB,
	DWORD_ADD,
	DWORD_XOR,
};

class CPolyCTX : public CPolyBase
{
	DWORD					m_dwVirusStartAdd;
	DWORD					m_dwCounter;
	eCTX_Decryption_Mode	eOperation;
	DWORD					m_dwKey;
	DWORD					m_dwCalllOffset;

	int GetDecParam(CEmulate &objEmulate);
	int DoDecryption();
	int DetectCTX();

public:
	CPolyCTX(CMaxPEFile *pMaxPEFile);
	~CPolyCTX(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

