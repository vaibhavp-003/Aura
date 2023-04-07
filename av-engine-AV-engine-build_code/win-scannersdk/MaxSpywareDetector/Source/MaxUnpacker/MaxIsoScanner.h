#pragma once

#include "MaxPEFile.h"
#include "MaxMACUBFile.h"
#include "zlib.h"
#include "bzlib.h"
#include <assert.h>



const unsigned char	ISO_HDR_SIGNATURE[]	= {0x45, 0x52, 0x02, 0x00};
const unsigned char bMAC_UB_BE[] = {0xCA, 0xFE, 0xBA, 0xBE};
const unsigned char bMAC_UB_LE[] = {0xBE, 0xBA, 0xFE, 0xCA};

#define ADC_PLAIN 0x01
#define ADC_2BYTE 0x02
#define ADC_3BYTE 0x03

#define BT_ADC   0x80000004
#define BT_ZLIB  0x80000005
#define BT_BZLIB 0x80000006

#define CHUNKSIZE 0x100000
#define DECODEDSIZE 0x100000

#define BT_ZERO 0x00000000
#define BT_RAW 0x00000001
#define BT_IGNORE 0x00000002
#define BT_COMMENT 0x7ffffffe
#define BT_TERM 0xffffffff

#ifdef __MINGW32__
#define fseek fseek64
#endif
#pragma pack(1)
struct _kolyblk {
	DWORD	Signature;
	DWORD	Version;
	DWORD	HeaderSize;
	DWORD	Flags;
	ULONG64 RunningDataForkOffset;
	ULONG64 DataForkOffset;
	ULONG64 DataForkLength;
	ULONG64 RsrcForkOffset;
	ULONG64 RsrcForkLength;
	DWORD	SegmentNumber;
	DWORD	SegmentCount;
	DWORD	SegmentID1;
	DWORD	SegmentID2;
	DWORD	SegmentID3;
	DWORD	SegmentID4;
	DWORD	DataForkChecksumType;
	DWORD	Reserved1;
	DWORD	DataForkChecksum;
	DWORD	Reserved2;
	char	Reserved3[120];
	ULONG64 XMLOffset;
	ULONG64 XMLLength;
	char	Reserved4[120];
	DWORD	MasterChecksumType;
	DWORD	Reserved5;
	DWORD	MasterChecksum;
	DWORD	Reserved6;
	char	Reserved7[120];
	DWORD	ImageVariant;
	ULONG64 SectorCount;
	char	Reserved8[12];
}/* __attribute__ ((__packed__))*/;




struct _mishblk {
	DWORD	 BlocksSignature;
	DWORD	 InfoVersion;
	ULONG64	 FirstSectorNumber;
	ULONG64	 SectorCount;
	ULONG64	 DataStart;
	DWORD	 DecompressedBufferRequested;
	DWORD	 BlocksDescriptor;
	char	 Reserved1[24];
	DWORD	 ChecksumType;
	DWORD	 Reserved2;
	DWORD	 Checksum;
	DWORD	 Reserved3;
	char	 Reserved4[120];
	DWORD	 BlocksRunCount;
	char	*Data;
} /*__attribute__ ((__packed__))*/;

#pragma pack
int convert_int(int i);
ULONG64 convert_int64(ULONG64 i);
DWORD	convert_char4(unsigned char *c);
ULONG64 convert_char8(unsigned char *c);

void read_kolyblk(FILE* F, struct _kolyblk* k);
void fill_mishblk(char* c, struct _mishblk* m);

const char plist_begin[] = "<plist version=\"1.0\">";
const char plist_end[] = "</plist>";
const char list_begin[] = "<array>";
const char list_end[] = "</array>";
const char chunk_begin[] = "<data>";
const char chunk_end[] = "</data>";
const char blkx_begin[] = "<key>blkx</key>";
const char name_key[] = "<key>Name</key>";
const char name_begin[] = "<string>";
const char name_end[] = "</string>";


class CMaxIsoScanner
{
private:

	int				debug ;
	int				verbose;
	int				listparts;
	int				extractpart;
	double			percent;
	unsigned int	offset;
	char			*plist;
	char			*blkx;
	unsigned int	blkx_size;
	char			*data_begin;
	char			*data_end;
	//const char		*OutPath;
	char			*partname_begin;
	char			*partname_end;
	char			*mish_begin ;
	char			partname[255] ;
	unsigned int	*partlen;
	unsigned int	data_size;
	char			reserved[5];
	char			sztype[64];
	unsigned int	block_type;
	unsigned int	dw_reserved;
	bool			bIsBigIndian;
	char			*input_file;
	char			*output_file;
	int				i, err, partnum , scb;
	ULONG64			out_offs, out_size, in_offs, in_size, in_offs_add, add_offs, to_read, to_write, chunk;
	Bytef			*tmp , *otmp , *dtmp ;
	FILE			*FIN, *FOUT, *FDBG;

	struct			_mishblk *parts;	
	z_stream		z;
	bz_stream		bz;
	bool			Check4ISOhrd();
	int				ExtractISOFile(CMaxPEFile *pMaxSecureFile);
	int				adc_decompress(int in_size, unsigned char *input, int avail_size, unsigned char *output, int *bytes_written);
	int				adc_chunk_type(char _byte);
	int				adc_chunk_size(char _byte);
	int				adc_chunk_offset(unsigned char *chunk_start);
	int				mem_overflow();
	int				error_dmg_corrupted();
	void			percentage();
	bool			read_kolyblk(struct _kolyblk* k, bool bcheck = true);
	bool			OffSetBasedSignature(unsigned char *m_pbyBuff,DWORD dwSizeofSig,DWORD *dwIndex);
	void			decode_base64(const char *inp, unsigned int isize,char *out, unsigned int *osize);
	unsigned char	decode_base64_char(const char c);
	void			cleanup_base64(char *inp, const unsigned int size);
	bool			is_base64(const char c);
	
	CMaxPEFile		*m_pMaxSecureFile;
	TCHAR			m_szTempPath[1024];

	bool			CreateEmptyFile(LPCTSTR	pszFilePath);
public:
//	CMaxIsoScanner(){};
	CMaxIsoScanner(CMaxPEFile *pMaxSecureFile/*, CDBManager *pDBManager*/);
	~CMaxIsoScanner(void);

	unsigned char *m_pbyBuffer;
	CMaxPEFile	  *m_pOutFile;

	DWORD	 iFileSize;
	DWORD	 iOffset; 
	DWORD	 iBuffSize;
	DWORD	 iFileCnt;
	DWORD	 m_iTotalBytesWritten;
	DWORD	 iBytesWritten;

	bool	IsValidDMGFile();
	bool	ExtractDMGFile(CMaxPEFile *pMaxSecureFile);
	bool	SetDestDirPath(LPCTSTR pszDestPath);
	
};



