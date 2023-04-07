/*======================================================================================
FILE				: PolyCensor.h
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
CREATION DATE		: 11 Apr 2011
NOTES				: This is detection module for malwares Censor Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int CENSOR_BUFF_SIZE = 0x500;

typedef struct _tagCENSORA_STRUCT
{
	DWORD dwDecryptionKey;
	DWORD dwOriAEPAddress;
}CensorA_Struct;

class CPolyCensor : public CPolyBase
{
	CensorA_Struct m_objCensorAStruct;

	BOOL GetCensorAParameters();

public:
	CPolyCensor(CMaxPEFile *pMaxPEFile);
	~CPolyCensor(void);

	int DetectVirus(void);
	int CleanVirus(void);
};
