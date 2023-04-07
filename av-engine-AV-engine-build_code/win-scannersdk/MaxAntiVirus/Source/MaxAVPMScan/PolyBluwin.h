/*======================================================================================
FILE				: PolyBluwin.h
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
NOTES				: This is detection module for malwares Bluwin Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR	
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int BLUWIN_BUFF_SIZE = 0x80;

enum BLUWIN_DEC_TYPE
{
	NO_BLUWIN_DEC_FOUND = 0x00,
	BLUWIN_DEC_ADD,
	BLUWIN_DEC_SUB,
	BLUWIN_DEC_XOR,
	BLUWIN_DEC_DELETE,
};

class CPolyBluwin : public CPolyBase
{
	BYTE	m_bDecOffset;

	int		CheckSignature(DWORD);

public:
	CPolyBluwin(CMaxPEFile *pMaxPEFile);
	~CPolyBluwin(void);

	int		DetectVirus();
	int		CleanVirus();
};