/*======================================================================================
FILE				: PolyTvido.h
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
NOTES				: This is detection module for malware Tvido Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int	TVIDO_BUFF_SIZE		= 0x1000;
const int	TVIDO_KEY_POS 		= 0x21;
const int	TVIDO_DEC_POS 		= 0x33;
const int	TVIDO_ROL_KEY 		= 0x04;
const int	TVIDO_B_BUFF_SIZE	= 0x6000;

class CPolyTvido : public CPolyBase
{
	DWORD		m_dwHdrSigStart;	
	DWORD		m_dwTvidoType;
	DWORD		m_dwStartOfDec;
	DWORD		m_dwDecKey;
	DWORD		m_dwType;
	DWORD		m_dwKeyChngType;
	DWORD		m_dwKeyChngKey;

	void ResetParam();
	
	int DoDecryption();
	int GetDecParam(CEmulate &objEmulate);
	int GetKyChangeParameter(CEmulate &objEmulate);
	int DecryptKey();

public:
	CPolyTvido(CMaxPEFile *pMaxPEFile);
	~CPolyTvido(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	int CleanTvidoA();

	int CleanTvidoB();
};

