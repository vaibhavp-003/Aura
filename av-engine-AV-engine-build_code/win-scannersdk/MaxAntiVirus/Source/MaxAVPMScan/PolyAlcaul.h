/*======================================================================================
FILE				: PolyAlcaul.h
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
NOTES				: This is detection module for malwares Virus.Alcaul.H Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

class CPolyAlcaul : public CPolyBase
{
	DWORD	m_dwOrigAEP;
	DWORD	m_dwOriginalFileStart;
	DWORD	m_dwOriginalFileSize;
	DWORD   m_dwReplaceOffset; 		//Added
	DWORD   m_dwOrigFileSize;		//Added

	enum
	{
		VIRUS_TYPE_ALCAUL_F,
		VIRUS_TYPE_ALCAUL_H,
        VIRUS_TYPE_ALCAUL_B			//Added

	}m_eVirusType;

	bool	GetDecryptionData();
	int		DetectAlcaulH(void);
	int		DetectAlcaulF(void);
    int     DetectAlcaulB(void);		//Added


	int		CleanAlcaulH(void);
	int		CleanAlcaulF(void);
	int		CleanAlcaulB(void);	//Added

public:
	CPolyAlcaul(CMaxPEFile *pMaxPEFile);
	~CPolyAlcaul(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
	
};