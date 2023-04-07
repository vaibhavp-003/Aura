#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

enum
{
	e1B8 = 0,
	e1A0
};

typedef struct _PETCOPYBLOCKINFO
{
	DWORD dwBlockSize;
	DWORD dwSrcRVA;
	DWORD dwDestRVA;
}PETCOPYBLOCKINFO;

typedef struct _PETDECOMPRESSBLOCKINFO
{
	DWORD dwSrcRVA;
	DWORD dwBlockSize;
	DWORD dwDestRVA;
	DWORD dwFillWithZeroSize;
}PETDECOMPRESSBLOCKINFO;


typedef struct _PETDECOMPRESSBLOCKINFOe1A0
{
	DWORD dwSrcRVA;
	DWORD dwUBlockSize;
	DWORD dwDestRVA;
	DWORD dwBlank;
	DWORD dwSrcSize;
}PETDECOMPRESSBLOCKINFOe1A0;

class CPetite2xxUnpacker: public CUnpackBase
{	
	DWORD			m_dwOrigAEP;
	DWORD           m_dwOffset;
	DWORD           m_dwSEHHandler;

	PETCOPYBLOCKINFO		*m_pStructPetCopyBlockInfo;
	PETDECOMPRESSBLOCKINFO	*m_pStructPetDecompressBlockInfo;
	PETDECOMPRESSBLOCKINFOe1A0 *m_pStructPetDecompressBlockInfoe1A0;
	
	int m_ePetite2xxType;

	bool ResolveE8E9Calls(BYTE*,DWORD dwSize,BYTE byCompare=0);
	
public:
	CPetite2xxUnpacker(CMaxPEFile *pMaxPEFile);
	~CPetite2xxUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
};
