#include "pch.h"
#include "MaxSmallPESig.h"


CMaxSmallPESig::CMaxSmallPESig(void)
{
}

CMaxSmallPESig::~CMaxSmallPESig(void)
{
}

bool CMaxSmallPESig::GetNewPESig(unsigned char *szOldPESig, unsigned char *pNewPESig, PULONG64 pulSig)
{
	bool			bRet = false;
	unsigned char	szNewPESig[0x06] = {0x00};
	DWORD			dwMiddleWord = 0x00, dwDummy = 0x00, dwDummy2 = 0x00;
	unsigned char	szRevPESig[0x08] = {0x00};

	if (pNewPESig == NULL || szOldPESig == NULL)
	{
		return bRet;
	}

	szNewPESig[0x00] = szOldPESig[0x07];
	szRevPESig[0x05] = szOldPESig[0x07];
	
	szNewPESig[0x01] = szOldPESig[0x06];
	szRevPESig[0x04] = szOldPESig[0x06];
	
	dwDummy = ((szOldPESig[0x05] / 0x10) * 0x1000) +  ((szOldPESig[0x04] % 0x10) * 0x100) +  ((szOldPESig[0x03] / 0x10) * 0x10);
	dwDummy2 = (szOldPESig[0x05] % 0x10) +  (szOldPESig[0x04] / 0x10) +  (szOldPESig[0x03] % 0x10) + szOldPESig[0x02];
	dwDummy2 = (dwDummy2 / 0x10) + (dwDummy2 % 0x10);
	dwMiddleWord = dwDummy + dwDummy2;

	WORD	wData = dwMiddleWord;
	memcpy(&szNewPESig[0x02],&wData,sizeof(WORD));

	szRevPESig[0x03] = szNewPESig[0x02];
	szRevPESig[0x02] = szNewPESig[0x03];
	
	szNewPESig[0x04] = szOldPESig[0x01];
	szRevPESig[0x01] = szOldPESig[0x01];

	szNewPESig[0x05] = szOldPESig[0x00];
	szRevPESig[0x00] = szOldPESig[0x00];
	
	memcpy(pNewPESig,&szNewPESig[0x00],sizeof(szNewPESig));

	if (pulSig)
	{
		*pulSig = *((ULONG64 *)&szRevPESig[0x00]);
	}

	return true;
}

bool CMaxSmallPESig::GetNewPESig(ULONG64 ulPESig, unsigned char *pNewPESig, PULONG64 pulSig)
{
	bool			bRet = false;
	unsigned char	szOldPESig[0x08] = {0x00};
	unsigned char	szNewPESig[0x06] = {0x00};
	unsigned char	szRevPESig[0x08] = {0x00};
	DWORD			dwMiddleWord = 0x00, dwDummy = 0x00, dwDummy2 = 0x00;

	if (pNewPESig == NULL)
	{
		return bRet;
	}

	memcpy(&szOldPESig[0x00],(void *)&ulPESig,sizeof(ULONG64));
	szNewPESig[0x00] = szOldPESig[0x07];
	szRevPESig[0x05] = szOldPESig[0x07];

	szNewPESig[0x01] = szOldPESig[0x06];
	szRevPESig[0x04] = szOldPESig[0x06];

	dwDummy = ((szOldPESig[0x05] / 0x10) * 0x1000) +  ((szOldPESig[0x04] % 0x10) * 0x100) +  ((szOldPESig[0x03] / 0x10) * 0x10);
	dwDummy2 = (szOldPESig[0x05] % 0x10) +  (szOldPESig[0x04] / 0x10) +  (szOldPESig[0x03] % 0x10) + szOldPESig[0x02];
	dwDummy2 = (dwDummy2 / 0x10) + (dwDummy2 % 0x10);
	dwMiddleWord = dwDummy + dwDummy2;

	WORD	wData = dwMiddleWord;
	memcpy(&szNewPESig[0x02],&wData,sizeof(WORD));

	szRevPESig[0x03] = szNewPESig[0x02];
	szRevPESig[0x02] = szNewPESig[0x03];
	
	szNewPESig[0x04] = szOldPESig[0x01];
	szRevPESig[0x01] = szOldPESig[0x01];

	szNewPESig[0x05] = szOldPESig[0x00];
	szRevPESig[0x00] = szOldPESig[0x00];

	memcpy(pNewPESig,&szNewPESig[0x00],sizeof(szNewPESig));

	if (pulSig)
	{
		*pulSig = *((ULONG64 *)&szRevPESig[0x00]);
	}

	return true;
}


bool CMaxSmallPESig::GetNewPESig(ULONG64 ulPESig, unsigned char *pNewPESig)
{
	bool			bRet = false;
	unsigned char	szOldPESig[0x08] = {0x00};
	unsigned char	szNewPESig[0x06] = {0x00};
	DWORD			dwMiddleWord = 0x00, dwDummy = 0x00, dwDummy2 = 0x00;

	if (pNewPESig == NULL)
	{
		return bRet;
	}

	memcpy(&szOldPESig[0x00],(void *)&ulPESig,sizeof(ULONG64));
	szNewPESig[0x00] = szOldPESig[0x07];
	szNewPESig[0x01] = szOldPESig[0x06];

	dwDummy = ((szOldPESig[0x05] / 0x10) * 0x1000) +  ((szOldPESig[0x04] % 0x10) * 0x100) +  ((szOldPESig[0x03] / 0x10) * 0x10);
	dwDummy2 = (szOldPESig[0x05] % 0x10) +  (szOldPESig[0x04] / 0x10) +  (szOldPESig[0x03] % 0x10) + szOldPESig[0x02];
	dwDummy2 = (dwDummy2 / 0x10) + (dwDummy2 % 0x10);
	dwMiddleWord = dwDummy + dwDummy2;

	WORD	wData = dwMiddleWord;
	memcpy(&szNewPESig[0x02],&wData,sizeof(WORD));

	szNewPESig[0x04] = szOldPESig[0x01];
	szNewPESig[0x05] = szOldPESig[0x00];

	memcpy(pNewPESig,&szNewPESig[0x00],sizeof(szNewPESig));


	return true;
}



bool CMaxSmallPESig::GetNewPESig(unsigned char *szOldPESig, unsigned char *pNewPESig)
{
	bool			bRet = false;
	unsigned char	szNewPESig[0x06] = {0x00};
	DWORD			dwMiddleWord = 0x00, dwDummy = 0x00, dwDummy2 = 0x00;

	if (pNewPESig == NULL || szOldPESig == NULL)
	{
		return bRet;
	}

	//memcpy(&szOldPESig[0x00],&szPESig[0x00],sizeof(ULONG64));
	szNewPESig[0x00] = szOldPESig[0x07];
	szNewPESig[0x01] = szOldPESig[0x06];
	
	dwDummy = ((szOldPESig[0x05] / 0x10) * 0x1000) +  ((szOldPESig[0x04] % 0x10) * 0x100) +  ((szOldPESig[0x03] / 0x10) * 0x10);
	dwDummy2 = (szOldPESig[0x05] % 0x10) +  (szOldPESig[0x04] / 0x10) +  (szOldPESig[0x03] % 0x10) + szOldPESig[0x02];
	dwDummy2 = (dwDummy2 / 0x10) + (dwDummy2 % 0x10);
	dwMiddleWord = dwDummy + dwDummy2;

	WORD	wData = dwMiddleWord;
	memcpy(&szNewPESig[0x02],&wData,sizeof(WORD));
	
	szNewPESig[0x04] = szOldPESig[0x01];
	szNewPESig[0x05] = szOldPESig[0x00];

	memcpy(pNewPESig,&szNewPESig[0x00],sizeof(szNewPESig));

	return true;
}

bool CMaxSmallPESig::GetUlongFromSz(unsigned char *szPESig, PULONG64 pulSig)
{
	unsigned char	szDummy[0x08] = {0x00};
	int				i = 0x00, j = 0x05;
	ULONG64			ulDummy = 0x00;

	if (szPESig == NULL)
	{
		if (pulSig)
		{
			*pulSig = ulDummy;
		}
		return false;
	}

	for (; i < 0x06; i++, j--)
	{
		szDummy[i] = szPESig[j];
	}

	ulDummy = *((ULONG64 *)&szDummy[0x00]);

	if (pulSig)
	{
		*pulSig = ulDummy;
	}

	return true;
}

bool CMaxSmallPESig::GetSzFromUlong(unsigned char *szPESig, ULONG64 ulSig)
{
	unsigned char	szDummy[0x08] = {0x00};
	unsigned char	szSmallSig[0x06] = {0x00};
	int				i = 0x00, j = 0x05;

	if (szPESig == NULL)
	{
		return false;
	}

	memcpy(&szDummy[0x00],&ulSig,sizeof(ULONG64));

	for (; i < 0x06; i++, j--)
	{
		szSmallSig[i] = szDummy[j];
	}
	
	//memcpy(&szSmallSig[0x00],&szDummy[0x02],0x06);
	memcpy(szPESig,&szSmallSig[0x00],0x06);

	return true;
}