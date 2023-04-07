/*======================================================================================
FILE				: Packers.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for Packed malwares.
					  The repair action is : DELETE
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int PGPME_BUFF_SIZE		= 0x200;

class CPackers : public CPolyBase
{
	int	DetectPGPME();
	int	DetectSVKP();
	int	DetectPetite();	

public:
	CPackers(CMaxPEFile *pMaxPEFile);
	~CPackers(void);

	int		DetectVirus();
};
