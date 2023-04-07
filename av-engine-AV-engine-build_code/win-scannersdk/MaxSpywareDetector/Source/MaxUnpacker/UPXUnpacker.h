#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"
#include "Emulate.h"

/*
typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName, DWORD dwCodeOffset, DWORD dwSigOffset, bool bLZMA);
typedef bool (*LPFNUnPackUPXFile64)(char *pFileName, char *pUnpackFileName);
*/

//typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName);
typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName, DWORD dwCodeOffset, DWORD dwSigOffset, bool bLZMA);
typedef bool (*LPFNUnPackUPXFile64)(char *pFileName, char *pUnpackFileName);

class CUPXUnpacker: public CUnpackBase
{
    static HMODULE	m_hUPXUnpacker;
	static HMODULE	m_hUPXUnpacker64;
	static LPFNUnPackUPXFile m_lpfnUnPackUPXFile;
	static LPFNUnPackUPXFile64 m_lpfnUnPackUPXFile64;

public:
	CUPXUnpacker(CMaxPEFile *pMaxPEFile, int iCurrentLevel);
	~CUPXUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
	

	static bool LoadUPXDll();
	static bool UnLoadUPXDll();
	static bool UnLoadUPXDll64();
};



