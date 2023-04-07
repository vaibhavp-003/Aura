#include "pch.h"
#include <stdlib.h>
#include <stdio.h>
#include "MaxSHA.h"

CMaxSHA256::CMaxSHA256()
{
}

CMaxSHA256::~CMaxSHA256()
{
}

int CMaxSHA256::HashFile(LPCTSTR pszFile,LPTSTR pszHash)
{
	FILE			*fp = NULL;
	unsigned char	pBuf[SIZE_HASH_BUFFER];
	unsigned long	uRead = 0;
	unsigned char	pTemp[64] = {0};
	int				i = 0;

	if (pszFile == NULL || pszHash == NULL)
	{
		return 0;
	}

	fp = _wfopen(pszFile, L"rb");
	if(fp == NULL)
	{
		return 0;
	}
	sha256_begin(&m_sha256);

	while(1)
	{
		uRead = fread(pBuf, 1, SIZE_HASH_BUFFER, fp);

		if(uRead != 0)
		{
			sha256_hash(pBuf, uRead, &m_sha256);
		}

		if(uRead != SIZE_HASH_BUFFER) break;
	}

	fclose(fp); 
	fp = NULL;

	sha256_end(pTemp, &m_sha256);

	TCHAR szHexValue[65]={0};
	
	for(i = 0; i < 32; i++)
	{
		_stprintf(&szHexValue[i*2],L"%02X",pTemp[i]);
	}
	szHexValue[64]=L'\0';
	
	_tcscpy(pszHash,szHexValue);
	//printf("%s",szHexValue);

	return 1;
}

/*
int CMaxSHA256::HashFile(char *pszFile,LPSTR pszHash)
{
	FILE *fp = NULL;
	char buffer[32] = {0};
	unsigned char pBuf[SIZE_HASH_BUFFER];
	unsigned long uRead = 0;
	unsigned char pTemp[64] = {0};
	int i = 0;

	fp = fopen(pszFile, "rb");
	if(fp == NULL) 
		return 0;
	sha256_begin(&m_sha256);

	while(1)
	{
		uRead = fread(pBuf, 1, SIZE_HASH_BUFFER, fp);

		if(uRead != 0)
		{
			sha256_hash(pBuf, uRead, &m_sha256);
		}

		if(uRead != SIZE_HASH_BUFFER) break;
	}

	fclose(fp); fp = NULL;

	sha256_end(pTemp, &m_sha256);


	char szHexValue[65]={0};
	
	for(i = 0; i < 32; i++)
	{
		sprintf(&szHexValue[i*2],"%02X",pTemp[i]);
	}
	szHexValue[64]='\0';
	strcpy(szHash,szHexValue);
	printf("%s",szHexValue);

	return 0;
}
*/