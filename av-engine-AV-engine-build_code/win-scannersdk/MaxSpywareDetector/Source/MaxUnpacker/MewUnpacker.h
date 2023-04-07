#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

typedef struct _LZMABlockInfo
{
	DWORD dwDestSize;
	DWORD dwDestRVA;
	DWORD dwSrcSize;
}LZMABlockInfo;


class CMewUnpacker: public CUnpackBase
{
	DWORD m_dwOffset;
	LZMABlockInfo* m_pStructLZMABlockInfo;
	
public:
	CMewUnpacker(CMaxPEFile *pMaxPEFile);
	~CMewUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
	bool ResolveCalls(BYTE *,DWORD dwSize);
	bool ResolveImports(BYTE **,DWORD &dwImportSize,DWORD dwImportOffset,BYTE*);
};
