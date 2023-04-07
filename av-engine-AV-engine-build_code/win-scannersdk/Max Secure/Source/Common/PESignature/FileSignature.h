#pragma once
#include "PESig.h"

typedef enum
{
	eVALIDPE = 0,
	ePESIGMAIN,
	ePESIGUNPACK,
	eUNPACKED,
	eHERUPACK,
	ePRISIG,
	eSECSIG,
	eMEW,
	eUPACK,
	eUPACK039,
	eUPACK11,
	eFSG,
	eFSG20,
	eFSG133,
	eFSG131,
	eUPX,
	eUPXNRV2B, 
	eUPXNRV2D,
	eUPXNRV2E,
	ePETITE,
	ePESPIN,
	eYC13,
	eWWPACK,
	eASPACK,
	eNSPACK,
	eUNKNOWN
}PACKERS_TYPE;

typedef enum
{
	eEXCUTABLE_AND_WRITABLE_SECTION = 0,
	eCODE_OR_EXCUTABLE_SECTION,
	eNOT_PRINTABLE_NAME,
	eNO_EXCUTABLE_SECTION,
	eSUM_OF_SECTION_SIZE,
	ePOSITION_OF_PESIGNATURE,
	eENTRYPOINT_SECTION_NOT_EXCUTABLE,
	eENTRYPOINT_SECTION_NOT_CODE
}PACKER_CHARACTERISTIC;

const int	MAX_SECTIONS				= 0x40;
const float PACKER_THRESHOLD_LIMIT		= 1.4f;
const int	PACKERS_COUNT				= eUNKNOWN + 1;
const int	PACKER_CHARACTERISTIC_COUNT	= 8;
const int	MAX_RECURSION_LEVEL			= 7;
const int	EP_BUFFSIZE					= 4096;

typedef struct tag_exe_section {
    DWORD rva;
    DWORD vsz;
    DWORD raw;
    DWORD rsz;
    DWORD chr;
    DWORD urva; /* PE - unaligned VirtualAddress */
    DWORD uvsz; /* PE - unaligned VirtualSize */
    DWORD uraw; /* PE - unaligned PointerToRawData */
    DWORD ursz; /* PE - unaligned SizeOfRawData */
}EXE_SECTION,*LPEXESECTION;

class CFileSignature
{
public:
	CFileSignature(void);
	virtual ~CFileSignature(void);

	DWORD dwUnPackSuccess[PACKERS_COUNT];
	DWORD dwUnPackFailed[PACKERS_COUNT];
	int CreateSignature(LPCTSTR cFullFileName, PESCANNERSIG &PEScannerSig, bool bDeepScan);

private:
	CPESig m_objPESignature;

	bool					m_bDeepScan;
	bool					m_bMD5Success;
	bool					m_bIsValidPE;
	bool					m_bHasPEHeader;
	IMAGE_DOS_HEADER		m_DosHeader;
	IMAGE_NT_HEADERS32		m_ImageNTHdr;
	IMAGE_SECTION_HEADER	m_ImgSectionHdr[MAX_SECTIONS];
	EXE_SECTION				m_ExeSection[MAX_SECTIONS];
	DWORD					m_dwEPOffset;
	DWORD					m_dwEPRVA;
	DWORD					m_dwEPBuffSize;
	char					m_epbuff[EP_BUFFSIZE];
	DWORD					m_hdr_size;
	unsigned int			m_minval;
	unsigned int			m_maxval;

	int		m_iEPSectionIndex;
	WORD	m_dwNoOfSections;
	ULONG64	m_ulFileSize;
	HANDLE	m_hCurrentFile;
	TCHAR	m_szUnPackedFileName[MAX_PATH];
	LPPESCANNERSIG m_lpPEScannerSig;

	PACKERS_TYPE m_eTopLevelPacker;
	bool m_bSuccessfullyUnpacked;
	bool m_bIsPacked;
	int m_iCurrentLevel;
	void GetUnPackedFile(LPCTSTR szFileName);
	bool OpenFile(LPCTSTR szFileName);
	void CloseFile();
	bool LoadFilePEHeader();
	void AlignExeSectionInfo();
	DWORD GetRawAddress(DWORD rva, EXE_SECTION *shp, WORD nos, unsigned int *err, ULONG64 fsize);
	off_t MaxSeekSect(EXE_SECTION *s);
	bool IsPackedFileHeuristically();
	void PrepareMD5Signature();

	bool CheckSetupType();
	bool CheckSetupTypeOther();
	bool CheckInstallShieldAFW();
	bool CheckRARSetup();
	bool SignatureSearch(LPBYTE byBuffer, DWORD cbBuffer, LPBYTE byByteSet, DWORD cbByteSet);

	WORD m_wIndex;
	int m_ifound;
	PACKERS_TYPE TryAllUnPacker();
	PACKERS_TYPE CheckForUPACK();
	PACKERS_TYPE CheckForFSG2();
	PACKERS_TYPE CheckForFSG133();
	PACKERS_TYPE CheckForFSG131();
	PACKERS_TYPE CheckForUPXPack();
	PACKERS_TYPE CheckForPETITE();
	PACKERS_TYPE CheckForPESPIN();
	PACKERS_TYPE CheckForYODAPACK();
	PACKERS_TYPE CheckForWWPack();
	PACKERS_TYPE CheckForASPACK();
	PACKERS_TYPE CheckForNSPACK();
	PACKERS_TYPE CheckForMEWPack();

	HANDLE	m_hTempFile;
	TCHAR	m_szTempFileName[MAX_PATH];
	TCHAR	m_szTempFolderName[MAX_PATH];
	bool	m_bTempFileCreated;
	bool	CreateTempFile();
	void	DeleteTempFile();
	void	CloseTempFile();
};
