#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

typedef struct _LOADER_RLPACK
{
	DWORD CompressedRVA;
	DWORD UncompressedRVA;
}LOADER_DECODER_INFO_RLPACK;

typedef enum RLPack_Type
{
	LZMA_RL = 0,
	APLIB_RL,
};

class CRLUnpacker: public CUnpackBase
{	
	bool ResolveCalls(DWORD dwStart, DWORD dwSize, DWORD dwFlag);
	bool ResolveImportAddresses(BYTE *bySrcbuff, DWORD dwSize);
	DWORD CheckForAPI(BYTE *ReadAPIEncrypt, BYTE **byImportTablebuffOrig, BYTE *byImportTablebuff, DWORD *dwAPICounter, DWORD dwDLLNo, DWORD dwStartWriteDLLName, DWORD *dwImportSize, DWORD dwBuildImportSize);	
	BYTE *ReadAPI(HMODULE hDLLName, DWORD dwAPIEncrypted, bool *bOrdinal);	

public:	
	CRLUnpacker(CMaxPEFile *pMaxPEFile);
	~CRLUnpacker(void);
	
	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};
