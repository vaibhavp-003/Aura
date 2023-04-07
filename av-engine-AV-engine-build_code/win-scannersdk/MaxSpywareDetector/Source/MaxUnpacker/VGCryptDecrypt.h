#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CVGCryptDecrypt: public CUnpackBase
{

	typedef struct _DecryptBlock
	{
		DWORD dwRVA;
		DWORD dwSize;
	}DecryptBlock;

	DecryptBlock *m_pStructDecryptBlockInfo;

public:
	CVGCryptDecrypt(CMaxPEFile *pMaxPEFile);
	~CVGCryptDecrypt(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
