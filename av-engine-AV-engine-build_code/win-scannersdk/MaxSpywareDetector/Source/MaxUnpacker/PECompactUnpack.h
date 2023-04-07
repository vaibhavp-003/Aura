#pragma once
#include "Emulate.h"
#include "UnpackBase.h"

typedef struct _LOADER_DECODER_INFO
{
	DWORD dwRvaCompressedLoader;
	DWORD dwUncompressedLoaderSize;
	DWORD dwOffsetToLoaderEntry;
	DWORD dwRvaDecoder;
	DWORD dwRvaVirtualAlloc;
	DWORD dwRvaVirtualFree;
	DWORD dwRealImageBase;		
}LOADER_DECODER_INFO, *PLOADER_DECODER_INFO;

typedef struct _PEC_HOST_INFO
{
	WORD OffsettoPecBlock;
	WORD wTotalDecoders;
	DWORD dwCompressedImageBase;
	DWORD dwActualImageBase;
	DWORD dwOrigAEP;
	DWORD dwModDecompressAlgoOffs;                      //
	DWORD dwRVALoaderDecoder;
	DWORD c;
	DWORD dwKernel32LoadLibrary;
	DWORD e;
	DWORD f;
	DWORD g;
    DWORD dwWorkingMemoryRequired; //0x2C
	DWORD dwOffsetInLoader;		   //0x30
	DWORD dwImportTableRVA;        //0x34
	DWORD h2;                      //0x38
	DWORD wNoOfPecBlocks;          //0x3C
	DWORD dwStubRVA;               //0x40
	DWORD dwRVAOrigBytes;          //0x44
	DWORD dwNewEntryinLastSection; //0x48
	DWORD dwOffsetInLoader2;       //0x4C
}PEC_HOST_INFO;

typedef struct _PEC_BLOCK
{
	DWORD dwRVASource;    //0x00
	DWORD dwRVADest;      //0x04 
	DWORD dwBlockCSize;   //0x08
	DWORD dwBlockUSize;   //0x0C
	WORD  wFlag_Encoded;  //0x10
	WORD  wFilterIndex;   //0x12
	DWORD dwOverKillSize; //0x14
	DWORD dwAddMoreBytes; //0x18
}PEC_BLOCK;

class CPECompactUnpack: public CUnpackBase
{	
	LOADER_DECODER_INFO	m_objStructLdrDcdrInfo;
	PEC_BLOCK *m_pStructPecBlockInfo;
	PEC_HOST_INFO *m_pStructPecHostInfo;
	int m_eDLLCompress;

	DWORD		m_dwDetectType;
	DWORD       m_dwBypassSEH;
	
	bool ResolveAddresses(DWORD);
	bool CheckAlgorithm(WORD,DWORD,BYTE*,DWORD*,BYTE*,bool,bool=false,DWORD=0,DWORD=0,bool=false,bool bUseVirtualSizeforSource=false);
	bool ResolveE8E9Calls(BYTE*);
	bool ResolveFilter(void);	
	bool Emulate(); 

public:

	CPECompactUnpack(CMaxPEFile *pMaxPEFile);
	~CPECompactUnpack(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};
