/*======================================================================================
FILE				: MaxRTF.h
ABSTRACT			: Scanner for File Type : RTF Files
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
CREATION DATE		: 22-Apr-2010
NOTES				: This class module identifies and scan file types : RTF.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxPEFile.h"

class CMaxRTF
{
	DWORD	NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer);

public:
	CMaxRTF();
	~CMaxRTF();

	bool IsValidRTFFile(CMaxPEFile *pMaxPEFile);
	bool GetFileBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, DWORD& dwNormalisedBUfSize, CMaxPEFile *pMaxPEFile);
	bool Check4RtfExploitEx(LPBYTE byBuffer, DWORD BufferSize, CMaxPEFile *pMaxPEFile);
};
