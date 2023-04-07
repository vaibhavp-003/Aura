/*======================================================================================
FILE				: MaxHelp.h
ABSTRACT			: Scanner for File Type : CHM Files
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
NOTES				: This class module identifies and scan file types : CHM.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxPEFile.h"

class CMaxHelp
{
   	DWORD   m_dwReadOffset;
	DWORD   m_dwReadDIROffset;
	DWORD   m_dwTotalFileSize;
	DWORD   m_dwDIRSize;

public:

	CMaxHelp();
	~CMaxHelp();

	bool IsValidHelpFile(CMaxPEFile *pMaxPEFile);
	bool TraverseDirectoy(LPBYTE byBuffer,CMaxPEFile *pMaxPEFile);
	bool GetHelpBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile);
		
private:

	DWORD	dwNormalisedBufSize;	
	DWORD	NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer);	
};
