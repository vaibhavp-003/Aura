/*======================================================================================
FILE				: PolyFlyStdio.h
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
NOTES				: This is detection module for malware FlyStdio Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int FLYSTDIO_BUFF_SIZE = 0x800;

class CPolyFlyStdio : public CPolyBase
{
	int     IsFlyStdioFile(void);
	bool	IsFlyStdioSig(DWORD dwKey,DWORD dwAction,DWORD dwNoofByteToDec);
	bool    IsFlyStdioCheck(DWORD dwBuffOffSet);

public:
	CPolyFlyStdio(CMaxPEFile *pMaxPEFile);
	~CPolyFlyStdio(void);

	int		DetectVirus(void);	
};
