/*======================================================================================
FILE				: PolyExpiro.h
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
NOTES				: This is detection module for malware Expiro Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"


const int EXPIRO_BUFF_SIZE = 0x500;
const int MAX_EXP_REG_LEN		= 0x10;


class CPolyExpiro :	public CPolyBase
{
	int		m_iExpiroType;
	DWORD   m_dwOAEPExpiro;
	DWORD   m_dwPatchSize;
	DWORD   m_dwTemp1;

	DWORD   m_dwExpiroAPAddValue;
	DWORD   m_dwPatchSizeAP;

	bool	GetExpiroAEP();
	bool	CheckPushInstructions();
	bool	GetPatchSize();
	bool    m_bDelFlag;

	DWORD	GetEmulatedRegister(DWORD dwStartAddress , 
								DWORD dwEndAddress ,
								char *szRequiredRegister, 
								DWORD dwDisasmStartAddr,
								DWORD dwCounter);

public:
	CPolyExpiro(CMaxPEFile *pMaxPEFile);
	~CPolyExpiro(void);
	
	int		DetectVirus(void);
	int		CleanVirus(void);
};

