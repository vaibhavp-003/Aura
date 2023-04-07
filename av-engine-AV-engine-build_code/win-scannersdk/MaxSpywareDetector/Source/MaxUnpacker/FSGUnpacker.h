#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


class CFSGUnpacker: public CUnpackBase
{
	enum 
	{
		XCHG=0,
		MOV
	};

	typedef struct _BlockInfo
	{
		DWORD dwDestRVA;
		DWORD dwSrcRVA;
		DWORD ImportOffset;
		DWORD dwA[0x08];
		DWORD dwAEP;
	}BlockInfo;

	DWORD m_dwOffset;
	BlockInfo* m_pStructDecompressBlockInfo;
	int iType;
	
public:
	CFSGUnpacker(CMaxPEFile *pMaxPEFile, int iCurrentLevel);
	~CFSGUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
	bool ResolveImports(BYTE **,DWORD &dwImportSize,DWORD dwImportOffset,BYTE*);
	bool ResolveImportsMOV(BYTE **,DWORD &dwImportSize,DWORD dwImportOffset,BYTE*);
};
