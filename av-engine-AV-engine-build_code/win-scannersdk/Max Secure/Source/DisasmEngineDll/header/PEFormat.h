#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 4018)
#pragma warning(disable: 4244)
#pragma warning(disable: 4996)
#pragma warning(disable: 6001)
#pragma warning(disable: 6202)//**Imp** TO Be Reviewed
#pragma warning(disable: 6031)
#pragma warning(disable: 6244)
#pragma warning(disable: 6328)
#endif

#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

#pragma pack  (1)

#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

typedef struct _PMS_IMAGE_DOS_HEADER
{											 // DOS .EXE header
	unsigned short int   e_magic;                     // Magic number
	unsigned short int   e_cblp;                      // Bytes on last page of file
	unsigned short int   e_cp;                        // Pages in file
	unsigned short int   e_crlc;                      // Relocations
	unsigned short int   e_cparhdr;                   // Size of header in paragraphs
	unsigned short int   e_minalloc;                  // Minimum extra paragraphs needed
	unsigned short int   e_maxalloc;                  // Maximum extra paragraphs needed
	unsigned short int   e_ss;                        // Initial (relative) SS value
	unsigned short int   e_sp;                        // Initial SP value
	unsigned short int   e_csum;                      // Checksum
	unsigned short int   e_ip;                        // Initial IP value
	unsigned short int   e_cs;                        // Initial (relative) CS value
	unsigned short int   e_lfarlc;                    // File address of relocation table
	unsigned short int   e_ovno;                      // Overlay number
	unsigned short int   e_res[4];                    // Reserved words
	unsigned short int   e_oemid;                     // OEM identifier (for e_oeminfo)
	unsigned short int   e_oeminfo;                   // OEM information; e_oemid specific
	unsigned short int   e_res2[10];                  // Reserved words
	signed long int		e_lfanew;                    // File address of new exe header
} PMS_IMAGE_DOS_HEADER ;
#pragma pack  ()

#pragma pack  (1)
typedef struct _PMS_IMAGE_FILE_HEADER
{
	unsigned short int   Machine;
	unsigned short int   NumberOfSections;
	unsigned long int	TimeDateStamp;
	unsigned long int	PointerToSymbolTable;
	unsigned long int	NumberOfSymbols;
	unsigned short int   SizeOfOptionalHeader;
	unsigned short int   Characteristics;
} PMS_IMAGE_FILE_HEADER;
#pragma pack  ()

#define IMAGE_SIZEOF_FILE_HEADER             20

#pragma pack  (1)
typedef struct _PMS_IMAGE_DATA_DIRECTORY
{
	unsigned long int   VirtualAddress;
	unsigned long int   Size;
} PMS_IMAGE_DATA_DIRECTORY ;
#pragma pack  ()

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

#pragma pack  (1)
typedef struct _PMS_IMAGE_OPTIONAL_HEADER
{
	unsigned short int   Magic;
	unsigned char		MajorLinkerVersion;
	unsigned char		MinorLinkerVersion;
	unsigned long int	SizeOfCode;
	unsigned long int	SizeOfInitializedData;
	unsigned long int	SizeOfUninitializedData;
	unsigned long int	AddressOfEntryPoint;
	unsigned long int	BaseOfCode;
	unsigned long int	BaseOfData;

	//
	// NT additional fields.
	//

	unsigned long int	ImageBase;
	unsigned long int	SectionAlignment;
	unsigned long int	FileAlignment;
	unsigned short int   MajorOperatingSystemVersion;
	unsigned short int   MinorOperatingSystemVersion;
	unsigned short int   MajorImageVersion;
	unsigned short int   MinorImageVersion;
	unsigned short int   MajorSubsystemVersion;
	unsigned short int   MinorSubsystemVersion;
	unsigned long int	Win32VersionValue;
	unsigned long int	SizeOfImage;
	unsigned long int	SizeOfHeaders;
	unsigned long int	CheckSum;
	unsigned short int   Subsystem;
	unsigned short int   DllCharacteristics;
	unsigned long int	SizeOfStackReserve;
	unsigned long int	SizeOfStackCommit;
	unsigned long int	SizeOfHeapReserve;
	unsigned long int	SizeOfHeapCommit;
	unsigned long int	LoaderFlags;
	unsigned long int	NumberOfRvaAndSizes;
	PMS_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PMS_IMAGE_OPTIONAL_HEADER ;
#pragma pack  ()

#define IMAGE_SIZEOF_SHORT_NAME              8

#pragma pack  (1)
typedef struct _PMS_IMAGE_SECTION_HEADER 
{
	unsigned char   Name[IMAGE_SIZEOF_SHORT_NAME];
	union	{
				unsigned long int   PhysicalAddress;
				unsigned long int   VirtualSize;
			} Misc;
	unsigned long int   VirtualAddress;
	unsigned long int   SizeOfRawData;
	unsigned long int   PointerToRawData;
	unsigned long int   PointerToRelocations;
	unsigned long int   PointerToLinenumbers;
	unsigned short int  NumberOfRelocations;
	unsigned short int  NumberOfLinenumbers;
	unsigned long int   Characteristics;
} PMS_IMAGE_SECTION_HEADER ;
#pragma pack  ()

#pragma pack  (1)
typedef struct _LE_HEADER
{
	unsigned char			Signature [ 2 ] ;
	unsigned char			UnusedBuf1 [ 22 ] ;
	unsigned long int     	EIPObjectNo ;
	unsigned long int		EIP ;
	unsigned long int     	ESPObjectNo ;
	unsigned long int		ESP ;
	unsigned long int		PageSize ;
	unsigned char			UnusedBuf2 [ 20 ] ;
	unsigned long int		ObjectTableOffset ;
	unsigned long int		NoOfObjects ;
	unsigned char			UnusedBuf3 [ 56 ] ;
	unsigned long int		DataPagesOffset ;
}LEHEADER;
#pragma pack  ()

#pragma pack  (1)
typedef struct _LE_OBJECT_TABLE_ENTRY
{
	unsigned long int	   	VirtualSize ;
	unsigned long int		BaseAddress ;
	unsigned long int		Flags ;
	unsigned long int		PageTableIndex ;
	unsigned long int		NoOfPageTableEntries;
	unsigned long int		Reserved;
}LE_OBJECT_TABLE_ENTRY;
#pragma pack  ()

#pragma pack  (1)
typedef struct _PMS_IMAGE_NT_HEADERS {
	unsigned long int Signature;
	PMS_IMAGE_FILE_HEADER FileHeader;
	PMS_IMAGE_OPTIONAL_HEADER OptionalHeader;
} PMS_IMAGE_NT_HEADERS ;
#pragma pack  ()

#define	FEATURE_32BIT_EXEC_PATH		1	//000 - 00001
#define	FEATURE_16BIT_EXEC_PATH		4	//000 - 00100
#define	FEATURE_GET_FILE_LENGTH		8	//000 - 01000
#define	FEATURE_ONLY_OP_CODE		16	//000 - 10000

#define	FEATURE_32_BYTES_LENGTH		32	//001 - 00000
#define	FEATURE_64_BYTES_LENGTH		64	//010 - 00000

#define	FEATURES_ALL				FEATURE_32_BYTES_LENGTH + FEATURE_ONLY_OP_CODE + FEATURE_32BIT_EXEC_PATH + FEATURE_16BIT_EXEC_PATH + FEATURE_GET_FILE_LENGTH
