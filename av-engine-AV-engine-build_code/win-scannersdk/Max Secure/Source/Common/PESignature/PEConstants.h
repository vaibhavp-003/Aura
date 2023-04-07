#pragma once

const int	SIZE_OF_CRC64	 = 8;
const int	MAX_SPY_NAME_LEN = 60;
const int	iMAX_SECTIONS	 = 0x40 ;
const int	iMAX_PRI_SIG_LEN = 0x80 ;
const int	iMAX_SEC_SIG_LEN = 0x80 ;
const int	iMAX_MD5_SIG_LEN = 0x10 ;
const int	iMAX_THREAT_NAME_LEN = 0x96;
const int	iMAX_FILE_BEGIN_SEC_SIZE = 0x400 ;
const WORD	EXE_SIGNATURE	 = 0x5A4D ;
const DWORD PE_SIGNATURE	 = 0x00004550 ;
const DWORD MAX_READ_BUFFER	 = 0x00100000 ;
const DWORD MAX_HDR_BUFFER	 = 0x00001000 ;

const int	PE_SIG_ALL = 0;
const int	PE_SIG_PRI = 1;
const int	PE_SIG_SEC = 2;
const int	PE_SIG_MD5 = 3;

const int	SIG_STATUS_BUFFER_INVALID				= 0;
const int	SIG_STATUS_OPEN_FAILED					= 1;
const int	SIG_STATUS_NOT_PE_FILE					= 2;
const int	SIG_STATUS_ZERO_BYTE_FILE				= 3;
const int	SIG_STATUS_MD5_SUCCESS					= 4;
const int	SIG_STATUS_PRIMARY_SIGNATURE_FAILED		= 5;
const int	SIG_STATUS_SECONDARY_SIGNATURE_FAILED	= 6;
const int	SIG_STATUS_EPSMD5_SIGNATURE_FAILED		= 7;
const int	SIG_STATUS_PE_SUCCESS					= 8;
const int	SIG_STATUS_FILE_DATA_INVALID			= 9;
const int	SIG_STATUS_FILE_DATA_ONLY_NULLS			= 10;

#ifdef _PE_FOR_PARSELOG_
#pragma pack(1)
typedef struct
{
	ULONG64	ulPriSig;
	ULONG64	ulSecSig;
	ULONG64	ulMD5Sig;
	ULONG64	ulMD5Sig15MB;
	BYTE	byMD5Sig[iMAX_MD5_SIG_LEN];
	DWORD	dwModifiedTimeHigh;
	DWORD	dwModifiedTimeLow;
	ULONG64	ulFileSize;
	unsigned char iStatus			: 8;		//Max value can be 256
	unsigned short wSetupType		: 8;		//Max value can be 256
	unsigned char bIsPacked			: 1;
	unsigned char bUnPackSuccess	: 1;
	unsigned char bPESigSuccess		: 1;
	unsigned char KaspScanned		: 1;
	unsigned char SpyDocScanned		: 1;
	unsigned char SpySweepScanned	: 1;
	unsigned char IsValidPE			: 1;
	unsigned char bDeepScanDone		: 1;
	unsigned char bHasPEHeader		: 1;
	unsigned char Reserved			: 7;
	unsigned char wTopLevelPacker	: 5;		//Max value can be 32
	unsigned char wNoOfUnpacks		: 3;		//Max value can be 7
	TCHAR		  szThreatName[iMAX_THREAT_NAME_LEN];
	TCHAR		  szFileName[MAX_PATH];
}PESCANNERSIG, *LPPESCANNERSIG;
#pragma pack()
#else //_PE_FOR_PARSELOG_
#pragma pack(1)
typedef struct
{
	ULONG64	ulPriSig;
	ULONG64	ulSecSig;
	ULONG64	ulMD5Sig;
	DWORD	dwModifiedTimeHigh;
	DWORD	dwModifiedTimeLow;
	unsigned char iStatus		: 3;
	unsigned char bDeepScanDone	: 1;
	unsigned short wSetupType	: 8;
	unsigned char Reserved		: 4;
}PESCANNERSIG, *LPPESCANNERSIG;
#pragma pack()
#endif //#ifdef _PE_FOR_PARSELOG_

#pragma pack(1)
typedef struct
{
	BYTE byPriSig[iMAX_PRI_SIG_LEN];
	BYTE bySecSig[iMAX_SEC_SIG_LEN];
	BYTE byMD5Sig[iMAX_MD5_SIG_LEN];
}PESIG, *PPESIG, *LPPESIG;
#pragma pack()

#pragma pack(1)
typedef struct
{
	BYTE byPriSig[SIZE_OF_CRC64];
	BYTE bySecSig[SIZE_OF_CRC64];
	BYTE byMD5Sig[iMAX_MD5_SIG_LEN];
	TCHAR szSpyName[MAX_SPY_NAME_LEN];
	DWORD dwFileIndex;
	unsigned char wTopLevelPacker : 4;
	unsigned char bIsPacked : 1;
	unsigned char bUnPackSuccess : 1;
	unsigned char bPESigSuccess : 1;
	unsigned char wNoOfUnpacks;
	unsigned char wSetupType;
}PESIGDB, *PPESIGDB, *LPPESIGDB;
#pragma pack()

//PE Signature New Structures!

#pragma pack(1)
typedef struct _tagPESignatureRaw
{
	BYTE	bySig1[iMAX_PRI_SIG_LEN];
	BYTE	bySig2[iMAX_SEC_SIG_LEN];
	BYTE	bySig3[iMAX_SEC_SIG_LEN];
	BYTE	bySig4[iMAX_SEC_SIG_LEN];
	BYTE	bySig5[iMAX_SEC_SIG_LEN];
	BYTE	byEMD5[iMAX_MD5_SIG_LEN];
}PESIGRAW, *PPESIGRAW, *LPPESIGRAW;
#pragma pack()

#pragma pack(1)
typedef struct _tagPESignatureCRC
{
	ULONG64	ulPri;
	ULONG64	ulSec;
	ULONG64	ulMD5;
}PESIGCRC, *PPESIGCRC, *LPPESIGCRC;
#pragma pack()

#ifndef DONT_USE_MD5_DECLS
//MD5 Creation code

typedef struct
{
	DWORD state[4];					/* state (ABCD) */
	DWORD count[2];					/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];		/* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, unsigned char *, unsigned int);
void MD5Final(unsigned char [16], MD5_CTX *);
#endif