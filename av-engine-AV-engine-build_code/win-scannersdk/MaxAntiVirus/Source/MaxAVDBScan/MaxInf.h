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
NOTES				: This class module identifies and scan file types : INF.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxPEFile.h"

#define MAX_BUFFER_SIZE     (20 * 1024)
#define MAX_INF_SIG_LEN		(250)
#define MIN_INF_SIG_LEN		(10)

class CMaxInf
{
public:
	CMaxInf();
	virtual ~CMaxInf();

	bool	IsThisValidFile(LPCTSTR szFilePath);
	bool	MakeSignature(LPTSTR szSig, DWORD cchSig, LPBYTE byBuffer, DWORD cbBuffer);
	bool    GetBuffer(LPBYTE byBuffer, DWORD& cbBuffer, CMaxPEFile *pMaxPEFile);

private:
	DWORD   m_dwBytesRead;
	DWORD   m_dwTotalBytesRead;
	LPBYTE  m_byReadBuffer;
	DWORD   m_cbReadBuffer;
	DWORD   m_dwScanBuffCnt;

	bool    IsValidInf(LPBYTE byBuffer, DWORD cbBuffer);
	bool    ReadBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD &dwBytesRead, CMaxPEFile *pMaxPEFile);
	bool    NormalizeBuffer(LPBYTE byBuffer, DWORD& cbBuffer);	
	bool	GetOneLine(LPBYTE byBuffer, DWORD cbBuffer, DWORD dwIndex, DWORD& dwLength);
};