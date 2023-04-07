#pragma once
#include "Emulate.h"
#include "UnpackBase.h"

const int MAX_SECTIONS = 20;	// hardcoded in ASPack

typedef struct _SECTION_RECORD
{
	DWORD dwRVA;
	DWORD dwSize;
}SECTION_RECORD;

typedef struct _SECTION_RECORD_NEW
{
	DWORD dwRVA;
	DWORD dwSize;
	DWORD dwAttributes;
}SECTION_RECORD_NEW;

class CASPackUnpack: public CUnpackBase
{
	DWORD	m_dwOriAEP;
	DWORD	m_dwSecStrtAdd;
	DWORD	m_dwResolveCallAdd;
	
	WORD	m_wUnPackSecNo;
	BYTE	m_byAspackCode[4096];
	BYTE    byDecryptFlag;
	DWORD   m_dwImportTableRVA;
	BYTE    *bybuffDecrypt;
	DWORD   dwCount;

	SECTION_RECORD	*m_pstructSecRcrd;
	SECTION_RECORD_NEW	*m_pstructNewSecRcrd;
	DWORD	m_dwSize;
	
	int		DecompressData(void *input, void *output, unsigned int inputsize, unsigned int outputsize);
	BYTE	*PeLoadSection(DWORD dwRVA, DWORD *size = 0);
	bool	ResolveE8E9Calls(BYTE *byBuff, DWORD dwSize);
	bool	Emulate();

public:
	CASPackUnpack(CMaxPEFile *pMaxPEFile);
	~CASPackUnpack(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);

	TCHAR	szLogLine[1024];
};

extern "C" int __stdcall Decompress(void *src, void *dst, unsigned int dstsize, void *temp, unsigned int srcsize);


