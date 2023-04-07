/*======================================================================================
FILE				: PolyMabezat.h
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
CREATION DATE		: 17 Mar 2012
NOTES				: This is detection module for malware Polymorphic Mabezat Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int MABEZATGEN_BUFF_SIZE		  = 0x6E8;
const int MABEZATGEN_DETECT_BUFF_SIZE = 0x200;

typedef struct _tagMABEZATGEN_STRUCT
{
	BYTE	byDecryptionKey;
	DWORD	dwOriAEPAddress;
	DWORD	dwOriFileSize;
	DWORD	m_dwOriAEPByteOffset;
}MabezatGEN_Struct;

class CPolyMabezat : public CPolyBase
{
	MabezatGEN_Struct m_objMabezatGENStruct;
	bool GetMabezatParameters(DWORD dwJmpValue);
	bool GetDecryptedData(DWORD dwKeyOffset, DWORD dwDecOffset);
	bool CheckVirusString();
	bool IsCorruptData();

public:
			CPolyMabezat(CMaxPEFile *pMaxPEFile);
			~CPolyMabezat(void);
	
	int		DetectVirus(void);
	int		CleanVirus(void);
};