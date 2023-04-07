#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CBitArtsUnpack: public CUnpackBase
{
	typedef struct _DecryptBlock
	{
		DWORD dwRVA;
		DWORD dwSize;
	}DecryptBlock;

	DecryptBlock *m_pStructDecryptBlockInfo;

public:
	CBitArtsUnpack(CMaxPEFile *pMaxPEFile);
	~CBitArtsUnpack(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
