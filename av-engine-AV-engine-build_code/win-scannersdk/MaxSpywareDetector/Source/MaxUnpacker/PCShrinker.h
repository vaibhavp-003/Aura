#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CPCShrinkerUnpacker : public CUnpackBase
{	
	typedef struct _DecompressInfo
	{
		DWORD dwSrcRVA;
		DWORD dwSrcSize;
	}DecompressInfo;

	typedef struct _NoDecompressCompareInfo
	{
		DWORD dwSize;
		DWORD dwRVA;
	}NoDecompressCompareInfo;

	typedef struct _SimpleMove
	{
		DWORD dwSrcRVA;
		DWORD dwDestRVA;
		DWORD dwSize;
		DWORD dwFillWithZeroSize;
	}SimpleMoveInfo;

	DecompressInfo *m_pStructDecompressInfo;
	SimpleMoveInfo *m_pStructSimpleMoveInfo;
	DWORD m_dwOriAEP;
	DWORD m_dwOffset;
	
public:
	CPCShrinkerUnpacker(CMaxPEFile *pMaxPEFile);
	~CPCShrinkerUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};
