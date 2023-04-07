#pragma once

#include <pch.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

class CMaxBMAlgo
{
public:
	CMaxBMAlgo(void);
	~CMaxBMAlgo(void);

	BOOL	AddPatetrn2Search(BYTE *pszPatern,DWORD dwLen);
	BOOL	Search4Pattern(BYTE *pBuffer,DWORD dwBuffLen,DWORD *Offset = NULL);	
private:
	BYTE	m_bPattern[MAX_PATH];
	DWORD	m_dwPatLength;
	BOOL	IsPatternFound(BYTE *pBuffer,DWORD dwBuffLen);
	int		GetCharPosition(BYTE bChar2Search, DWORD dwStart);
};
