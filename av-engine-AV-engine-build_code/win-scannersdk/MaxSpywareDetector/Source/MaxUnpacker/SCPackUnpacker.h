#pragma once
#include "Emulate.h"
#include "UnpackBase.h"

typedef struct _LOADER_DECODER_INFO_SCPACK
{
	DWORD dwNoOfCompressedSections;
	DWORD dwOriginalAEP;
	DWORD dwDLLApiImport;
	DWORD dwImageBase;
	DWORD dwResourceTableRVA;
	DWORD dwResourceTableSize;
}LOADER_DECODER_INFO_SCPACK;

typedef struct _COMPRESSED_CODE_INFO
{
	DWORD dwUncompressedRVA;
	DWORD dwSize;
}COMPRESSED_CODE_INFO;

class CSCPackUnpacker: public CUnpackBase
{
	LOADER_DECODER_INFO_SCPACK	m_objStructLdrDcdrInfo;
	COMPRESSED_CODE_INFO *m_objStructCode_Info;

	bool LoadDLL(void);

public:
	CSCPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CSCPackUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);
};
