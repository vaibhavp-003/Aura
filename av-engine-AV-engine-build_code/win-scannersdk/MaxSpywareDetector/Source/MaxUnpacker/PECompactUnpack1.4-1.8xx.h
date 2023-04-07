#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"
#include "Emulate.h"

class CPECompactOldUnpack : public CUnpackBase
{	
	typedef struct _DecompressInfo
	{
	DWORD dwDecompressionOffset;
	DWORD dwBlockInfoOffset;
	DWORD dwCopyBlockInfoOffset;
	DWORD dwImageBase;
	DWORD dwLoaderStart;
	DWORD dwResolveImports;
	DWORD dwRealImageBase;	
	}DecompressInfo;

	typedef struct _BlockDecompressInfo
	{
		DWORD dwRVASource;
		DWORD dwSrcSize;
	}BlockDecompressInfo;

	typedef struct _BlockCopyInfo
	{
		DWORD dwRVASource;
		DWORD dwRVADest;
		DWORD dwSize;
		DWORD dwDestFillWithZeroSize;
	}BlockCopyInfo;


	int m_eDLLCompress;

	DecompressInfo *m_pStructDecompressInfo;
	BlockDecompressInfo  *m_pStructBlockDecompressInfo;
	BlockCopyInfo        *m_pStructBlockCopyInfo;
public:
	CPECompactOldUnpack(CMaxPEFile *pMaxPEFile);
	~CPECompactOldUnpack(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);
	bool CheckAlgorithm(DWORD,BYTE*,DWORD,DWORD,DWORD,DWORD,DWORD*,BYTE*);
	bool ResolveE8E9Calls(BYTE*,DWORD dwOffset,DWORD dwSize,BYTE *);
	bool ResolveImports(BYTE **,BYTE *byDestbuff,BYTE *byFullFilebuff,DWORD byDestbuffdwOffset,DWORD *);
	DWORD CallEmulatorDissambler(int,DWORD,BYTE*,CEmulate objEmulate,DWORD dwSize,DWORD *,DWORD *dwSizetoResolve,BYTE*);
};
