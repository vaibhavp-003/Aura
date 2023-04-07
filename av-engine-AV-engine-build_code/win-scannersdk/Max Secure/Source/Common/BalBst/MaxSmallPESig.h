#pragma once
#include <BaseTsd.h>
#include <stdio.h>
#include <windows.h>
#include <memory.h>

class CMaxSmallPESig
{
public:
	CMaxSmallPESig(void);
	~CMaxSmallPESig(void);

	bool	GetNewPESig(ULONG64 ulPESig, unsigned char *pNewPESig);
	bool	GetNewPESig(ULONG64 ulPESig, unsigned char *pNewPESig, PULONG64 pulSig);
	bool	GetNewPESig(unsigned char *szPESig, unsigned char *pNewPESig);
	bool	GetNewPESig(unsigned char *szPESig, unsigned char *pNewPESig, PULONG64 pulSig);
	bool	GetUlongFromSz(unsigned char *szPESig, PULONG64 pulSig);
	bool	GetSzFromUlong(unsigned char *szPESig, ULONG64 ulSig);
};
