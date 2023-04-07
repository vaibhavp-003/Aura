#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"
#include "Emulate.h"


class CPolyCryptPEDecryptor: public CUnpackBase
{
	typedef struct _SingleBlockInfo
	{
		DWORD dwDecryptRVA;
		DWORD dwSize;
		DWORD dwRVA;
	}SingleBlockInfo;

	typedef struct DecompressMainBlockInfo
	{
		DWORD dwAEP;
		DWORD dwA;
		DWORD dwResolveImports;
		DWORD dwB[0x04];
		DWORD dwNoofBlocks;
	}DecompressBlockInfo;


	DecompressBlockInfo *m_pStructMainBlockInfo;
	SingleBlockInfo     *m_pStructSingleBlockInfo;

public:
	CPolyCryptPEDecryptor(CMaxPEFile *pMaxPEFile);
	~CPolyCryptPEDecryptor(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
	void DecryptParts(BYTE *bybuff,DWORD dwCounter,WORD *wKey);
	bool DecryptKey(BYTE *byKeyHigh,BYTE *byKeyLow,BYTE byCounterHigh,BYTE byCounterLow,WORD *wKey,DWORD dwOffset,BYTE *);
};
