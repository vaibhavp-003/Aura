/*======================================================================================
FILE				: ScriptSig.h
ABSTRACT			: Scanner for File Type : Script Files
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
NOTES				: This class module identifies and scan file types : Script. (.html, .asp, .js, etc)
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "MaxPEFile.h"

const int MAX_FILE_SIZE_TO_SCAN	= (1024 * 1024 * 100);
const int MAX_FILE_READ_BUFFER = (1024 * 64);
const int VIRUS_FILE_TYPE_HELP = 36;
const int MAX_FILE_END_READ_BUFFER = 1024;

#define MAX_SIG_SIZE_IN_BYTES	(250)

class CScriptSig
{
public:
	CScriptSig();
	virtual ~CScriptSig();

	bool IsItValidScript(CMaxPEFile *pMaxPEFile);
	bool IsValidScriptExtension(CMaxPEFile *pMaxPEFile);
	bool GetFileBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile);
	bool GetJClassFileBuffer(LPBYTE byBuffer, DWORD& cbBufSize, int iIndex, DWORD& dwTotalBytesLeft, CMaxPEFile *pMaxPEFile);
	bool CheckForExploitScript(LPBYTE pbyBuffer, DWORD cbBufSize);

private:

	LPBYTE	m_byReadBuffer;
	DWORD	m_cbReadBuffer;
	DWORD	m_dwTotalBytesRead;
  	LPBYTE   m_byReadEndBuffer;
	DWORD	m_cbReadBuffer1;

	DWORD	m_dwEscapeChrCnt;

	void	ResetMemberVariables();
	DWORD	NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer);
	LPBYTE	MemStr(LPBYTE byBuffer, DWORD cbBuffer, LPCSTR bySubStr, DWORD cbSubStr);
};
