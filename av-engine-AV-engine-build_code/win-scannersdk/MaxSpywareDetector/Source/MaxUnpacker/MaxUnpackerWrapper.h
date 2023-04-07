#pragma once

#include "MaxPEFile.h"
#include "Emulate.h"
#include "ASPackUnpack.h"
#include "NSPackUnpacker.h"
#include "PECompactUnpack.h"
#include "MPressUnpacker.h"
#include "SCPackUnpacker.h"
#include "DexCryptor.h"
#include "RLUnpacker.h"
#include "PogoUnpacker.h"
#include "XPackUnpacker.h"
#include "PePackUnpacker.h"
#include "SMPackUnpacker.h"
#include "SPackUnpacker.h"
#include "CExeUnpacker.h"
#include "SimplePackUnpack.h"
#include "DalKryptorDecrypt.h"
#include "Petite2.xxUnpacker.h"
#include "NeoliteUnpacker.h"
#include "AHPackUnpacker.h"
#include "YodaCryptorUnpacker.h"
#include "WinUpackUnpack.h"
#include "MaskPEUnpacker.h"
#include "VGCryptDecrypt.h"
#include "PECryptCFDecrypt.h"
#include "KbyshooUnpacker.h"
#include "PCShrinker.h"
#include "RPCryptDeJunker.h"
#include "VPackUnpacker.h"
#include "NPackUnpacker.h"
#include "PolyCryptPEDecrypter.h"
#include "TelockDecryptor.h"
#include "PECompactUnpack1.4-1.8xx.h"
#include "MewUnpacker.h"
#include "FSGUnpacker.h"
#include "UPXUnpacker.h"
#include "EmbeddedFile.h"
#include "BitArtsUnpacker.h"
#include "AverCryptDecryptor.h"
#include "SoftComUnpacker.h"
#include "NullSoft.h"
#include "MSExpand.h"

#include "NonPEFile.h"

#define TEMP_FOLDER		_T("\\TempData")
#define TEMP_FILE		_T("\\TempUPX")

//const int MAX_RECURSION_LEVEL = 20; //Swapnil Comment
const int MAX_RECURSION_LEVEL = 1;

enum
{
	NOT_PACKED = 0,
	UNPACK_SUCCESS,
	UNPACK_FAILED,
	UNPACK_EXPECTION
};

typedef enum
{
	eVALIDPE = 0,
	eMEW,
	eUPACK,
	eFSG,	
	eUPX,
	ePESPIN,
	eWWPACK,
	eASPACK,
	eNSPACK,
	ePECOMPACT,
	eScPack,
	eMPressPack,
	eDexCryptor,
	eRLPack,
	ePOGOPack,
	eXPack,
	ePePack,
	eSMPack,
	eSPack,
	eCExePack,
	eSimplePack,
	eDalKryptor,
	ePetite2xx,
	eNeolite,
	eAHPack,
	eYodaUnpack,
	eStealthPE,
	eWinUpack,
	eMaskPE,
	eEmbeddedFile,
	ePECryptCF,
	eVGCrypt,
	eKbyshoo,
	eRPCrypt,
	eVPack,
	ePCShrinker,
	ePolyPECrypt,
	eNpack,
	eTelock,
	ePECOMPACTOld,
	eBitArts,
	eAverCrypt,
	eSoftCom,
	eUPXPatch,
	eNullSoft,
	eMSExpand,
	eUNKNOWN
}PACKERS_TYPE;

/*
typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName, DWORD dwCodeOffset, DWORD dwSigOffset, bool bLZMA);
typedef bool (*LPFNUnPackUPXFile64)(char *pFileName, char *pUnpackFileName);
*/

//typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName);
typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName, DWORD dwCodeOffset, DWORD dwSigOffset, bool bLZMA);
typedef bool (*LPFNUnPackUPXFile64)(char *pFileName, char *pUnpackFileName);

class CMaxUnpackerWrapper
{
public:
	static LPFNUnPackUPXFile	m_lpfnUnPackUPXFile;
	static LPFNUnPackUPXFile64	m_lpfnUnPackUPXFile64;
	static HMODULE				m_hUPXUnpacker;	
	static HMODULE				m_hUPXUnpacker64;	

	PACKERS_TYPE m_ePackerType;

	CMaxUnpackerWrapper(CMaxPEFile *pInputFile, CMaxPEFile *pOutputFile);
	virtual ~CMaxUnpackerWrapper(void);

	int		UnpackFile();
	bool	TryallUnpackers(bool bDetectOnly = false);
	
private:	
	CMaxPEFile	*m_pInputFile;
	CMaxPEFile	*m_pOutputFile;
	CMaxPEFile	*m_pCurrentFile;
		
	int		m_iCurrentLevel;
	
	HANDLE	m_hTempFile;

	TCHAR	m_szFilePath[MAX_PATH];
	TCHAR	m_szTempFilePath[MAX_PATH];
	TCHAR	m_szTempFolderPath[MAX_PATH];
	TCHAR	m_szOnlyFileName[MAX_PATH];
	
	void	CloseFile();
	
	bool	CreateTempFile();
	bool	Initialize();
	int		GetUnPackedFile();
	
	void	CloseTempFile();
	void	DeleteTempFile();
	void	GetRandomFilePath(LPTSTR szFileName);

	bool	ExtractFile(DWORD dwStartOffset = 0, DWORD dwSize = 0);
	
	PACKERS_TYPE CheckFileInRrsSection(bool bDetectOnly);
	PACKERS_TYPE CheckFileInOverlay(bool bDetectOnly);
	
	bool UnpackUPXFile();
	int UnpackPEFile();
};
