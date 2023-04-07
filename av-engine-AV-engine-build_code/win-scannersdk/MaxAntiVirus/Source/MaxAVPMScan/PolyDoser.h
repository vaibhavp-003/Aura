/*======================================================================================
FILE				: PolyDoser.h
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
NOTES				: This is detection module for malware Doser Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int DOSER_BUFF_SIZE = 0x2000;

enum DOSER_DEC_TYPE
{
	NO_DOSER_DEC_FOUND = 0x00,
	DOSER_DEC_ADD,
	DOSER_DEC_SUB,
	DOSER_DEC_NOT,
	DOSER_DEC_XOR,
	DOSER_DEC_NEG,
    DOSER_DEC_DELETE,
};

class CPolyDoser : public CPolyBase
{
	DOSER_DEC_TYPE m_eDecType;
   
	BYTE m_byDecKey;
   
	bool CheckDoser4187Sig(DWORD dwOffset);
	bool CheckDoser4539Sig(DWORD dwOffset);
	bool CheckDoser4535Sig(DWORD dwOffset);

public:
	CPolyDoser(CMaxPEFile *pMaxPEFile);
	~CPolyDoser(void);
	
	int DetectVirus();
	int CleanVirus();	
};
