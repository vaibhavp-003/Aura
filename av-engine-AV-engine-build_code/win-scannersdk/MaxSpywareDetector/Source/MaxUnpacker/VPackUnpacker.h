#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CVPackUnpacker : public CUnpackBase
{	
	typedef struct _DecompressInfo
	{
		DWORD dwNoofBlocks;
		DWORD dwOffsetofCode;
		DWORD dwOffsetofImport;
		DWORD dwSizeofImport;
		DWORD dwAEP;
		DWORD dwResourcesRVAx2;
		DWORD dwResourcesSizex2;
		DWORD dwDelayImportDescRVAxD;
		DWORD dwDelayImportDescSizexD;
		DWORD dwExportRVAx1;
		DWORD dwExportSize1;
	}DecompressInfo;

	typedef struct _BlockDecompressInfo
	{
		DWORD dwOffsettoSourceRVA;
		DWORD dwDestSize;
		DWORD dwDestRVA;
		DWORD dwSrcSize;
	}BlockDecompressInfo;

	DecompressInfo *m_pStructDecompressInfo;
	BlockDecompressInfo  *m_pStructBlockDecompressInfo;
public:
	CVPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CVPackUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
	bool ResolveImports(BYTE **,BYTE *byDestbuff,BYTE *byFullFilebuff,DWORD byDestbuffdwOffset,DWORD *);
};
