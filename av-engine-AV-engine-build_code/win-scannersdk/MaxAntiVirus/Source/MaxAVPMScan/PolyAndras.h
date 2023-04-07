/*======================================================================================
FILE				: PolyAndras.h
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
NOTES				: This is detection module for malwares PolyAndras Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "PolyBase.h"

const int ANDRAS_BUFF_SIZE = 0xEE0;

enum ANDRAS_DEC_TYPE
{
	ANDRAS_DEFAULT = 0,
	
	ANDRAS_DWORD_ADD,
	ANDRAS_WORD_ADD,
	ANDRAS_BYTE_ADD,

	ANDRAS_DWORD_SUB,
	ANDRAS_WORD_SUB,
	ANDRAS_BYTE_SUB,

    ANDRAS_DWORD_XOR,
	ANDRAS_WORD_XOR,
	ANDRAS_BYTE_XOR,

   	ANDRAS_DWORD_NEG,
	ANDRAS_WORD_NEG,
	ANDRAS_BYTE_NEG,

 };

class CPolyAndras : public CPolyBase
{
	ANDRAS_DEC_TYPE	m_eDecType;
	
	DWORD	m_dwVirusStartAdd;
	DWORD   m_dwOriAEPOffset;
	DWORD	m_dwKey;

	bool GetDecryptionParam(char *szInstruction);
	bool GetDecryptedData();
	int DetectAndras(void);

public:

	CPolyAndras(CMaxPEFile *pMaxPEFile);
	~CPolyAndras(void);

	int DetectVirus(void);
	int CleanVirus(void);
};