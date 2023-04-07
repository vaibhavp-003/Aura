#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CAverCryptDecryptor:public CUnpackBase
{
	typedef struct _DecryptBlock
	{
		DWORD AEP;
		DWORD dwStartSection;
		DWORD dwImageBase;
		DWORD dwNoOfSections;
		DWORD dwFlagAdd200;
		DWORD dwA[0x3];
		DWORD dwXORKeys[0x5];
	}DecryptBlock;

public:
	
	CAverCryptDecryptor(CMaxPEFile *pMaxPEFile);
	~CAverCryptDecryptor(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	

};