#pragma once
#include "MaxPEFile.h"
#include "PEC2CodecSDK.h"

#define SA(x)	align(x, m_pMaxPEFile->m_stPEHeader.SectionAlignment)
#define FA(x)	align(x, m_pMaxPEFile->m_stPEHeader.FileAlignment)
#define FANotDefault(x,y)	align(x, y)
#define MKQWORD(h,l)	((((unsigned __int64)(h))<<32)|(l))

const int NO_OF_DLL = 5;

enum 
{
	LZMA2=0,
	JCALG1,
	LZMAMod,
	LZMA,
	FFCE,
	FFCEMod,
	FFCEMod2,
	APLIB,
	APLIBMod,
	SimpleMove,
	CryptHashADVAPI,
	Neolite,
	XORSUB,
	INVALID
};

typedef struct _PEC2_DECODER_EXTRA 
{
	DWORD	dwLoadLibraryA;
	DWORD	dwGetProcAddress;
	DWORD	dwVitualAlloc;
	DWORD	dwVirtualFree;
}PEC2_DECODER_EXTRA;

typedef struct _PEBUNDLE_DLL
{
	HMODULE hUnpacker;
	PFNDecodeSmall lpfnDecodeSmall;
}PEBUNDLE_DLL;

class CUnpackBase
{
private:
	DWORD m_dwPRDLargestSection;
	DWORD m_dwSRDLargestSection;
		
protected:
	static PEC2_DECODER_EXTRA	m_DecoderExtra;

	CMaxPEFile	*m_pMaxPEFile;	
	BYTE		*m_pbyBuff;
	DWORD		m_dwImageBase;
	int		    m_iCurrentLevel;

	bool ReOrganizeFile(LPCTSTR szTempFileName,bool bOnlyfile = true, bool bOnlyOverlay = true,int Type=0x00);
	bool AddNewSection(DWORD =0,WORD wDecrementSections=0);

	bool LoadDLLs(int i);

	DWORD LZMADecompress(BYTE byLZMAProp[], DWORD dwSrcSize, DWORD dwDestSize, DWORD dwRead, DWORD dwWrite, BYTE *byBuff = NULL,BYTE *byReadbuff=NULL,BYTE byPackerSpecial=0x00,bool bCheckDestSize = true);
	DWORD APLIBDecompress(DWORD dwSrcSize, DWORD dwDestSize, DWORD dwRead, DWORD dwWrite, BYTE *byDestbuff = NULL, int iCtype = 0x00,BYTE *bybuff = NULL, DWORD *dwActualSrcSize = NULL);
	bool LZSSUncompress(DWORD,DWORD*,DWORD,DWORD,CMaxPEFile *pMaxPEFile,DWORD*,BYTE *SrcBuff=NULL,BYTE *WriteInBuff=NULL,bool bFFCEMd=false);
	DWORD NeoliteUncompress(DWORD,DWORD*,DWORD,DWORD,CMaxPEFile *pMaxPEFile,DWORD*,BYTE *SrcBuff=NULL,BYTE *WriteInBuff=NULL);
	bool CheckBit1(BYTE*,DWORD*,DWORD*,DWORD,bool &,int iType=0);
	bool PetiteUncompress(DWORD,DWORD*,DWORD,DWORD,BYTE *SrcBuff=NULL,BYTE *WriteInBuff=NULL,int Itype=0,DWORD=0x10000,DWORD=0x40000);
	bool LZSSModUncompress(DWORD dwSrcSize,DWORD *dwDestSize,DWORD dwRead,DWORD dwWrite,CMaxPEFile *pMaxPeFile,DWORD *dwIncrement,BYTE *bySrcbuff /*==NULL*/,BYTE *byBuff /*==NULL*/);

public:
	static PEBUNDLE_DLL m_PEBundle[NO_OF_DLL];
	static int m_iDataCnt;
	static HANDLE	m_hEvent;
	
	CMaxPEFile	m_objTempFile;
	
	CUnpackBase(CMaxPEFile *pMaxPEFileint, int iCurrentLevel = 0);
	virtual	~CUnpackBase(void);

	virtual bool IsPacked(void) = 0;
	virtual bool Unpack(LPCTSTR szTempFileName) = 0;
};

class CStealthackUnpacker: public CUnpackBase
{
public:
	CStealthackUnpacker(CMaxPEFile *pMaxPEFile);
	~CStealthackUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};

class CUPXPatch: public CUnpackBase
{
public:
	CUPXPatch(CMaxPEFile *pMaxPEFile);
	~CUPXPatch(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};

unsigned int align(unsigned int x, unsigned int alignment);
