#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CKbyshooUnpacker : public CUnpackBase
{	
	typedef struct _DecompressInfo
	{
		DWORD dwAEP;
		DWORD dwA[0x4];
		DWORD dwDestSize;
		DWORD dwSrcSize;
		DWORD dwSrvRVA;
		DWORD dwOffsettoStartResolve;
		DWORD dwFlagToResolve;
		DWORD dwBytetoCompareResolve;
		DWORD ResolveCallsCounter;
	}DecompressInfo;

	typedef struct _MoveBytesInfo
	{
		DWORD dwDestRVA;
		DWORD dwSize;
	}MoveBytesInfo;

	DecompressInfo *m_pStructDecompressInfo;
	MoveBytesInfo  *m_pStructMoveBytesInfo;
public:
	CKbyshooUnpacker(CMaxPEFile *pMaxPEFile);
	~CKbyshooUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
	bool ResolveCalls(BYTE *bybuff,DWORD dwCallsCounter,DWORD dwBytetoCompare);
	bool ResolveImports(BYTE **,BYTE *byDestbuff,BYTE *byFullFilebuff,DWORD byDestbuffdwOffset,DWORD *);
};
