#pragma once
#include "MaxPEFile.h"
#include "Emulate.h"
#include "UnpackBase.h"

class CPECryptCFDecrypt: public CUnpackBase
{	
	typedef struct _DecryptBlock
	{
		DWORD dwRVA;
		DWORD dwSize;
	}DecryptBlock;

	DWORD m_dwOffset;
	DecryptBlock *m_pStructDecryptBlockInfo;

public:
	CPECryptCFDecrypt(CMaxPEFile *pMaxPEFile);
	~CPECryptCFDecrypt(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
