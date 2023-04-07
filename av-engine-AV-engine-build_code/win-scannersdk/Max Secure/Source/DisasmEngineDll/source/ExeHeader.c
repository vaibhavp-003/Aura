#include <windows.h>
#include <stdio.h>
#include <io.h>
#include "peformat.h"
#include "elfformat.h"
#include <stdlib.h>
#include <crtdbg.h>  // For _CrtSetReportMode

LONGLONG lFileSizeLimitForMD5 = 5242880;
const int iSizeOfBuffer = 65536;
unsigned char *g_buffer = NULL;
int MDFile(HANDLE hFile, BYTE *Signature, unsigned char *buffer, int iSizeOfBuffer);

#define	MAXEXT					256
#define	EXECUTIONPATHLENGTH		8 * 1024

#define UNKNOWN			-1
#define VI_COM			5
#define VI_EXE			6
#define VI_NE			7
#define VI_LE			8
#define	VI_PE			9
#define VI_DOC			10
#define VI_XLS			11
#define VI_DOC97		12
#define VI_XLS97		13
#define VI_PPT97		14
#define VI_EMBEDDED		15
#define VI_ELF			16

#pragma pack  (1)
typedef struct Vector1
{
	unsigned short int Offset ;
	unsigned short int Segment ;
}VECTOR1 ;
#pragma pack  ()

#pragma pack  (1)
typedef struct ExeHeader1
{
	unsigned short int	exSignature ;		 // .EXE signature
	unsigned short int	exExtraBytes ;		 // number of bytes in last (partial) page
	unsigned short int	exPages ;			 // number of whole and part pages in file
	unsigned short int	exRelocItems ;		 // number of pointers in relocation table
	unsigned short int	exHeaderSize ;		 // size of header, in paragraphs
	unsigned short int	exMinAlloc ;		 // minimum allocation
	unsigned short int	exMaxAlloc ;		 // maximum allocation
	unsigned short int	exStackSegment ;	 // initial ss
	unsigned short int	exStackOffset ;		 // sp value
	unsigned short int	exCheckSum ;		 // complemented checksum
	unsigned short int	exCodeOffset ; 		 // ip value
	unsigned short int	exCodeSegment ;		 // initial cs
	unsigned short int	exRelocTable ;		 // byte offset to relocation table
	unsigned short int	exOverlay ;		 // overlay number
	unsigned char		exUnused [ 0x20 ] ;
	unsigned long int	exLocation ;
} EXEHEADER ;
#pragma pack  ()

#pragma pack (1)
typedef struct tagSegments
{
	unsigned long int BaseAddress ;
	unsigned long int Offset ;
	unsigned long int FileOffset ;
	unsigned long int SegmentSize ;
} SEGMENTS ;
#pragma pack ()

#pragma pack  ( 1 )
typedef struct segmenttable
{
	unsigned short int OffsetInFile ;
	unsigned short int LengthOfImageInFile ;
	unsigned short int SegmentAttributes ;
	unsigned short int NumOfBytesToAllocateForSegment ;
} SEGMENTTABLE ;
#pragma pack  ( )

#pragma pack  ( 1 )
typedef struct newexehdr
{
	unsigned char Signature [ 2 ] ;
	unsigned char LinkerVer [ 2 ] ;	// Maj , Min
	unsigned short int EntryTableStart ;
	unsigned short int LengthOfEntryTable ;
	unsigned long int FileLoadCRC ;
	unsigned char DGROUPType : 2 ;
	unsigned char GlobalInit : 1 ;
	unsigned char ProtectedMode : 1 ;
	unsigned char Instr8086 : 1 ;
	unsigned char Instr80286 : 1 ;
	unsigned char Instr80386 : 1 ;
	unsigned char Instr80x87 : 1 ;
	unsigned char ApplicationFlags : 3 ;
	unsigned char FamilyApp : 1 ;
	unsigned char unsused1 : 1 ;
	unsigned char ExeOrError : 1 ;
	unsigned char NonConfirming : 1 ;
	unsigned char DLLOrDriver : 1 ;
	unsigned short int AutoDSIndex ;
	unsigned short int	InitLocalHeapSize ;
	unsigned short int	InitStackSize ;
	unsigned short int	IP ;
	unsigned short int	CS ;
	unsigned short int	SP ;
	unsigned short int	SS ;
	unsigned short int 	SegmentCount ;
	unsigned short int	ModuleRefCount ;
	unsigned short int	LengthOfNonResTable ;
	unsigned short int 	SegmentTableOffset ;
	unsigned short int	ResourceTableOffset ;
	unsigned short int	ResNamesTableOffset ;
	unsigned short int	ModuleRefTableOffset ;
	unsigned short int	ImportedNamesTableOffset ;
	unsigned long int 	NonResNamesTableOffset ;
	unsigned short int	MoveableEntryPoint ;
	unsigned short int	FileAlignSizeShiftCount ;
	unsigned short int	NumberOfResTableEntries ;
	unsigned char		TargetOS ;
	unsigned char		LongFileNames : 1 ;
	unsigned char 	ProtectedMode2X : 1 ;
	unsigned char		ProportionalFont2X : 1 ;
	unsigned char		GangLoadArea : 1 ;
	unsigned char 	unused2 : 4 ;
	unsigned short int	StartOfGangLoadArea ;
	unsigned short int	LengthOfGangLoadArea ;
	unsigned short int	CodeSwapAreaSize ;
	unsigned short int	WinVer ;
} NEWEXEHDR ;
#pragma pack  ( )

unsigned long int MakeDeassembly ( HANDLE RHandle , unsigned int Flag , LARGE_INTEGER EntryPoint , signed short int Mode ,
						  void * ExecutionPathPtr , signed short int InternalFileType ,
						  unsigned char * MemoryPtr , unsigned long int MemPtrLength ,
						  void * ExecutionPathWidth , SEGMENTS * Segments , unsigned long int ImageBase ,
						  unsigned long int BaseOfCode , LARGE_INTEGER * CurrentEntryPoint , int * NewEntryPointSectionNumber ) ;

extern int OutHandle ;

void * Malloc ( int Size )
{
	HGLOBAL Ptr ;

	Ptr = GlobalAlloc ( GMEM_FIXED , Size ) ;
	return ( Ptr ) ;
}

void Free ( void * Ptr )
{ 
	GlobalFree ( ( HGLOBAL * ) Ptr ) ;
}

int GetFileLength ( HANDLE Handle , LARGE_INTEGER * FileLength )
{
	LARGE_INTEGER FilePointer ;

	FilePointer . QuadPart = 0 ;

	SetFilePointerEx ( Handle , FilePointer , & FilePointer , FILE_BEGIN ) ;

	FileLength -> QuadPart = FilePointer . QuadPart ;

	return ( 0 ) ;
}

int GetPEIntegrity ( HANDLE RHandle , LARGE_INTEGER Location , long int * EntryPointInFile , SEGMENTS * Segments , unsigned long int * ImageBase , unsigned long int * BaseOfCode ,
					unsigned char * ExtendedHeader , unsigned char * _OptionalHeader , unsigned char * _SectionHeader , int * EntryPointSectionNumber )
{
	PMS_IMAGE_OPTIONAL_HEADER OptionalHeader ;
	PMS_IMAGE_SECTION_HEADER SectionHeader ;
	PMS_IMAGE_FILE_HEADER FileHeader ;
	LARGE_INTEGER FileOffset ;
	unsigned long int Signature ;
	unsigned char * SectionHeaderPtr ;
	DWORD BytesRead ;
	long int EntryPoint ;
	int i = 0 , NumberOfSections ;

	//initialise Entry points
	EntryPoint = 0 ;

	SetFilePointerEx ( RHandle , Location , NULL , FILE_BEGIN ) ;

	ReadFile ( RHandle , ( unsigned char * ) & Signature , sizeof ( unsigned long int ) , & BytesRead , NULL ) ;

	if ( IMAGE_NT_SIGNATURE != Signature )
	{
		return ( 1 ) ;
	}

	ReadFile ( RHandle , ( unsigned char * ) & FileHeader , sizeof ( PMS_IMAGE_FILE_HEADER ) , & BytesRead , NULL ) ;

	if ( ExtendedHeader != NULL )
		memcpy ( ExtendedHeader , ( unsigned char * ) & FileHeader , sizeof ( PMS_IMAGE_FILE_HEADER ) ) ;

	//read optional header
	if ( FileHeader . SizeOfOptionalHeader > sizeof ( OptionalHeader ) )
		ReadFile ( RHandle , ( unsigned char * ) & OptionalHeader , sizeof ( OptionalHeader ) , & BytesRead , NULL ) ;
	else
		ReadFile ( RHandle , ( unsigned char * ) & OptionalHeader , FileHeader . SizeOfOptionalHeader , & BytesRead , NULL ) ;

	if ( _OptionalHeader != NULL )
		memcpy ( _OptionalHeader , ( unsigned char * ) & OptionalHeader , sizeof ( OptionalHeader ) ) ;

	* ImageBase = OptionalHeader . ImageBase ;
	* BaseOfCode = OptionalHeader . BaseOfCode ;

	SectionHeaderPtr = _SectionHeader ;

	// check for corrupted number of sections

	NumberOfSections = FileHeader . NumberOfSections ;
	if ( FileHeader . NumberOfSections > 32 )
		NumberOfSections = 32 ;

	if ( FileHeader . SizeOfOptionalHeader > sizeof ( OptionalHeader ) )
	{
		FileOffset . QuadPart = FileHeader . SizeOfOptionalHeader - sizeof ( OptionalHeader ) ;
		SetFilePointerEx ( RHandle , FileOffset , &FileOffset , FILE_CURRENT ) ;
	}

	if ( _SectionHeader != NULL )
	{
		//read section headers
		for ( i = 0 ; i < NumberOfSections ; i++ )
		{
			//read section header
			ReadFile ( RHandle , ( unsigned char * ) & SectionHeader , sizeof ( SectionHeader ) , & BytesRead , NULL ) ;

			memcpy ( SectionHeaderPtr , ( unsigned char * ) & SectionHeader , sizeof ( SectionHeader ) ) ;
			SectionHeaderPtr += sizeof ( SectionHeader ) ;

			if ( OptionalHeader . FileAlignment != 0 )
			{
				if ( SectionHeader . PointerToRawData % OptionalHeader . FileAlignment != 0 )
				{
					SectionHeader . PointerToRawData /= OptionalHeader . FileAlignment ;
					SectionHeader . PointerToRawData *= OptionalHeader . FileAlignment ;
				}
			}

			if ( i < 128 )
			{
				Segments [ i ] . BaseAddress = OptionalHeader . BaseOfCode ;
				Segments [ i ] . Offset		 = SectionHeader . VirtualAddress ;
				Segments [ i ] . FileOffset  = SectionHeader . PointerToRawData ;
				Segments [ i ] . SegmentSize = SectionHeader . SizeOfRawData ;
			}

			if ( ( OptionalHeader . AddressOfEntryPoint >= SectionHeader . VirtualAddress ) &&
				( OptionalHeader . AddressOfEntryPoint <= ( SectionHeader . VirtualAddress + SectionHeader . SizeOfRawData ) ) )
			{
				EntryPoint = OptionalHeader . AddressOfEntryPoint - SectionHeader . VirtualAddress ;
				EntryPoint += SectionHeader . PointerToRawData ;
				if ( EntryPointSectionNumber != NULL )
					* EntryPointSectionNumber = i ;
			}
		}//end for
	}

	//if EIP not calculated take the last segment for calculation
	if ( EntryPoint == 0 )
	{
		//FF1B21A0.EXE
		if(OptionalHeader . SectionAlignment != 0)
			EntryPoint = OptionalHeader . AddressOfEntryPoint % OptionalHeader . SectionAlignment ;
	}

	* EntryPointInFile = EntryPoint ;

	if ( * EntryPointInFile == 0 )
		* EntryPointInFile = OptionalHeader . AddressOfEntryPoint ;

	return ( 0 ) ;
}//GetPEIntegrity ()

//Function to calculate entrypoint for LE files
int GetLEIntegrity ( HANDLE RHandle , long int * EntryPoint )
{
	long OffSet = 0, HeaderOffset ;
	LEHEADER LeHeader ;
	LE_OBJECT_TABLE_ENTRY ObjectTableEntry ;
	unsigned long int ObjectNo ;
	DWORD BytesRead ;
	LARGE_INTEGER FilePosition ;

	FilePosition . QuadPart = 0x3C ;
	SetFilePointerEx ( RHandle , FilePosition , NULL , FILE_BEGIN ) ;

	// at 0x3C we get offset to the LE header
	//
	ReadFile ( RHandle , ( unsigned char * ) & HeaderOffset , sizeof ( unsigned long ) , & BytesRead , NULL ) ;

	// seek to header offset and read leheader
	//
	FilePosition . QuadPart = HeaderOffset ;
	SetFilePointerEx ( RHandle , FilePosition , NULL , FILE_BEGIN ) ;

	ReadFile ( RHandle , ( unsigned char * ) & LeHeader , sizeof ( LEHEADER ) , & BytesRead , NULL ) ;

	// compare with LE signature
	//
	if ( 0 != memcmp ( "LE" , LeHeader . Signature , 2 ))
	{
		return ( 1 ) ;
	}

	// calculate offset to the object table
	//
	FilePosition . QuadPart = HeaderOffset + LeHeader . ObjectTableOffset ;
	SetFilePointerEx ( RHandle , FilePosition , NULL , FILE_BEGIN ) ;

	// seek to that position and read each entry
	//
	ObjectNo = LeHeader . EIPObjectNo ;
	while ( 1 )
	{
		if ( 0 == ObjectNo )
			break ;

		memset ( & ObjectTableEntry , 0 , sizeof ( LE_OBJECT_TABLE_ENTRY ) ) ;
		ReadFile ( RHandle , ( unsigned char * ) & ObjectTableEntry , sizeof ( LE_OBJECT_TABLE_ENTRY ) , & BytesRead , NULL ) ;

		ObjectNo-- ;
	}

	// get datapagesoffset
	//
	OffSet = LeHeader . DataPagesOffset ;

	if ( 0 != LeHeader . EIPObjectNo )
	{
		OffSet += ( ObjectTableEntry . PageTableIndex - 1 ) * LeHeader . PageSize ;
	}

	* EntryPoint = LeHeader . EIP + OffSet ;

	return ( 0 ) ;

}//GetLEIntegrity()

//Function to calculate entrypoint for NE files
int GetNEIntegrity ( HANDLE RHandle , LARGE_INTEGER Location , NEWEXEHDR * NewExeHdr , long int * EntryPoint )
{
	SEGMENTTABLE SegmentTable ;
	long int TempOffset ;
	DWORD BytesRead ;
	LARGE_INTEGER FilePosition ;

	FilePosition . QuadPart = Location . QuadPart ;
	SetFilePointerEx ( RHandle , Location , NULL , FILE_BEGIN ) ;

	ReadFile ( RHandle , ( unsigned char * ) NewExeHdr , sizeof ( NEWEXEHDR ) , & BytesRead , NULL ) ;

	if ( 0 != strncmp ( ( char * ) ( NewExeHdr -> Signature ) , "NE" , 2 ) )
	{
		return ( 1 ) ;
	}	

	FilePosition . QuadPart = ( NewExeHdr -> SegmentTableOffset + Location . QuadPart + ( ( NewExeHdr -> CS - 1 ) * sizeof ( SEGMENTTABLE ) ) ) ;
	SetFilePointerEx ( RHandle , FilePosition , 0 , FILE_BEGIN ) ;

	ReadFile ( RHandle , ( char * ) & SegmentTable , sizeof ( SEGMENTTABLE ) , & BytesRead , NULL ) ;

	TempOffset = SegmentTable . OffsetInFile ;

	* EntryPoint = ( TempOffset << NewExeHdr -> FileAlignSizeShiftCount ) + NewExeHdr -> IP ;
	
	return ( 0 ) ;

}//GetNEIntegrity()

//	this function gives entry point in the COM files
//
int ResolveCOMEntryPoint ( unsigned char * COMFile, long int * EntryPoint )
{
	if ( ( 0xE9 == * COMFile ) || ( 0xE8 == * COMFile ) )
		 * EntryPoint = ( ( unsigned long int ) * ( COMFile + 2 ) << 8 ) + * ( COMFile + 1 ) + 3 ;
	else
	{
		if ( 0xEB == * COMFile )
			* EntryPoint = * ( COMFile + 1 ) + 2 ;
	}

	return ( 0 ) ;
}//ResolveCOMEntryPoint ()

//	this function gives entry point in the EXE files
int ResolveEXEEntryPoint ( EXEHEADER * ex , LARGE_INTEGER FileLength , int InternalFileType ,
								long int * EntryPoint )
{
	if ( VI_EXE == InternalFileType )
	{
		* EntryPoint = ( ( ( long int ) ex -> exCodeSegment << 4 ) + ex -> exCodeOffset ) +
					   ( ex -> exHeaderSize << 4 ) ;

		if ( ( unsigned long int ) * EntryPoint > FileLength . QuadPart  )
		{
			* EntryPoint = ( unsigned short int ) ( ( ( unsigned short int ) ex -> exCodeSegment << 4 ) + ex -> exCodeOffset )
							           + ( ( unsigned short int ) ex -> exHeaderSize << 4 ) ;
		}
	}

	return ( 0 ) ;
}//ResolveEXEEntryPoint ()


//	checking for EXE and COM files
//	ie.check EXE file whether it is actually EXE file or other one
//	ie.check COM file whether it is actually COM file or other one
int PositionHandleAtEntryPoint ( EXEHEADER * ExeHeader , unsigned char * COMFile , LARGE_INTEGER FileLength , int InternalFileType , long int * EntryPoint )
{
	int RetVal ;

	if ( ( 0x5A4D == ExeHeader -> exSignature ) ||	//'MZ'
		 ( 0x4D5A == ExeHeader -> exSignature ) ) 	//'ZM'
	{
		RetVal = ResolveEXEEntryPoint ( ExeHeader , FileLength , InternalFileType , EntryPoint ) ;
	}
	else
	{
		RetVal = ResolveCOMEntryPoint ( COMFile , EntryPoint ) ;
	}
	return ( RetVal ) ;

}//PositionHandleAtEntryPoint ()

//Function to calculate entrypoint for ELF ( Linux ) files
int GetELFIntegrity ( HANDLE Handle , long * EntryPoint )
{
	ELF_HEADER Header = { 0 } ;
	ELF_SECTION_HEADER32 SectionHeader = { 0 } ;
	ELF_PROGRAM_HEADER32 ProgramHeader ;
	int i ;
	unsigned char Buffer [ 100 ] = { 0 } ;
	LARGE_INTEGER FilePosition ;
	DWORD BytesRead ;

	FilePosition . QuadPart = 0 ;
	SetFilePointerEx ( Handle , FilePosition , NULL , FILE_BEGIN ) ;

	ReadFile ( Handle , ( unsigned char * ) & Header , sizeof ( ELF_HEADER ) , & BytesRead , NULL ) ;

	if ( memcmp ( Header . ElfIdent . Magic , ELFMAG , 4 ) != 0 )
	{
		// Not an ELF file format
		return ( 1 ) ;
	}

	if ( Header . Phoff != 0 )
	{
		// Program Header Table

		FilePosition . QuadPart = Header . Phoff ;
		SetFilePointerEx ( Handle , FilePosition , NULL , FILE_BEGIN ) ;

		for ( i = 0 ; i < Header . Phnum ; i ++ )
		{
			memset ( & ProgramHeader , 0 , sizeof ( ELF_PROGRAM_HEADER32 ) ) ;
			ReadFile ( Handle , ( unsigned char * ) & ProgramHeader , sizeof ( ELF_PROGRAM_HEADER32 ) , &BytesRead , NULL ) ;

			if ( ProgramHeader . Offset == 0 )
			{
				* EntryPoint = ( long int ) ( Header . Entry - ProgramHeader . Vaddr ) ;

				return ( 0 ) ;
			}
		}
	}

	if ( Header . Shoff != 0 )
	{
		// Sections start here

		FilePosition . QuadPart = Header . Shoff ;
		SetFilePointerEx ( Handle , FilePosition , NULL , SEEK_SET ) ;

		for ( i = 0 ; i < Header . Shnum ; i ++ )
		{
			memset ( & SectionHeader , 0 , sizeof ( ELF_SECTION_HEADER32 ) ) ;
			ReadFile ( Handle , ( unsigned char * ) & SectionHeader , sizeof ( ELF_SECTION_HEADER32 ) , &BytesRead , NULL ) ;

			if ( ( Header . Entry >= SectionHeader . Addr ) && ( Header . Entry <= ( SectionHeader . Addr + SectionHeader . Size ) ) )
			{
				// Entry point found
				* EntryPoint = ( long ) SectionHeader . Offset ;
				return ( 0 ) ;
			}
		}
	}

	return ( 2 ) ;

}//GetELFIntegrity

//Calculate enrtypoint of the file depending on its type
int GetEntryPointAndEliminationAnalysis ( HANDLE RHandle , short int InternalFileType , LARGE_INTEGER * _EntryPoint , SEGMENTS * Segments , unsigned long int * ImageBase , unsigned long int * BaseOfCode ,
										 unsigned char * DOSHeader , unsigned char * ExtendedHeader , unsigned char * OptionalHeader , unsigned char * SectionHeader , int * EntryPointSectionNumber )
{
	int RetValue ;
	LARGE_INTEGER FileLength , FilePosition ;
	unsigned char COMFile [ 80 ] ;
	EXEHEADER ExeHeader ;
	NEWEXEHDR NewExeHdr ;
	DWORD BytesRead ;
	long int EntryPoint ;

	* ImageBase = 0 ;
	* BaseOfCode = 0 ;

	FilePosition . QuadPart = 0 ;
	GetFileLength ( RHandle , & FileLength ) ;
	SetFilePointerEx ( RHandle , FilePosition , NULL , FILE_BEGIN ) ;

	memset ( COMFile , 0 , sizeof ( COMFile ) ) ;
	memset ( & ExeHeader , 0 , sizeof ( EXEHEADER ) ) ;

	ReadFile ( RHandle , COMFile , sizeof ( COMFile ) , & BytesRead , NULL ) ;

	memcpy ( ( unsigned char * ) & ExeHeader , COMFile , sizeof ( EXEHEADER ) ) ;
	if ( DOSHeader != NULL )
		memcpy ( DOSHeader , COMFile , sizeof ( EXEHEADER ) ) ;

	if ( EntryPointSectionNumber != NULL && ExtendedHeader != NULL )
//	if ( EntryPointSectionNumber != NULL )
		* EntryPointSectionNumber = -1 ;

	switch ( InternalFileType )
	{
		case VI_EXE :
			RetValue = PositionHandleAtEntryPoint ( & ExeHeader , COMFile , FileLength ,
													InternalFileType , & EntryPoint ) ;
			break ;

		case VI_NE :
			FilePosition . QuadPart = ExeHeader . exLocation ;
			RetValue = GetNEIntegrity ( RHandle , FilePosition , & NewExeHdr , & EntryPoint ) ;
			break ;

		case VI_PE :
			FilePosition . QuadPart = ExeHeader . exLocation ;
			RetValue = GetPEIntegrity ( RHandle , FilePosition , & EntryPoint , Segments , ImageBase , BaseOfCode , ExtendedHeader , OptionalHeader , SectionHeader , EntryPointSectionNumber ) ;
			break ;

		case VI_COM :
			RetValue = PositionHandleAtEntryPoint ( & ExeHeader , COMFile , FileLength ,
													InternalFileType , & EntryPoint ) ;
			break ;

		case VI_LE :
			RetValue = GetLEIntegrity ( RHandle , & EntryPoint ) ;
			break ;

		case VI_ELF :
			RetValue = GetELFIntegrity ( RHandle , & EntryPoint ) ;
			break ;
	}

	_EntryPoint -> QuadPart = EntryPoint ;

	return ( RetValue ) ;

}//GetEntryPointAndEliminationAnalysis ()

//this function gives whether EXE is 16 bit or 32 bit
//and return its type
int GetEXEFileType ( HANDLE Handle , int * ExeFileType )
{
	PMS_IMAGE_DOS_HEADER DosHeader ;
	unsigned char Signature [ 4 ] ;
	DWORD BytesRead ;
	LARGE_INTEGER FilePosition ;
	ELF_HEADER Header = { 0 } ;

	FilePosition . QuadPart = 0 ;
	SetFilePointerEx ( Handle , FilePosition , & FilePosition , FILE_BEGIN ) ;

	ReadFile ( Handle , ( unsigned char * ) & Header , sizeof ( ELF_HEADER ) , &BytesRead , NULL ) ;

	if ( memcmp ( Header . ElfIdent . Magic , ELFMAG , 4 ) == 0 )
	{
		// ELF file format
		* ExeFileType = VI_ELF ;
		return ( 0 ) ;
	}

	SetFilePointerEx ( Handle , FilePosition , NULL , FILE_BEGIN ) ;

	ReadFile ( Handle , ( unsigned char * ) & DosHeader , sizeof ( PMS_IMAGE_DOS_HEADER ) , & BytesRead , NULL ) ;
	
	if ( 0x40 != DosHeader . e_lfarlc )
		* ExeFileType = VI_EXE ;

	FilePosition . QuadPart = DosHeader . e_lfanew ;
	SetFilePointerEx ( Handle , FilePosition , & FilePosition , FILE_BEGIN ) ;
	ReadFile ( Handle , Signature , sizeof ( Signature ) , & BytesRead , NULL ) ;

	if ( ! memcmp ( "PE" , Signature , 2 ) )
		* ExeFileType = VI_PE ;
	else if ( ! memcmp ( "NE" , Signature , 2 ) )
		* ExeFileType = VI_NE ;
	else if ( ! memcmp ( "LE" , Signature , 2 ) )
		* ExeFileType = VI_LE ;
	else
		* ExeFileType = VI_EXE ;

	return ( 0 ) ;

}//GetEXEFileType ()

int IsItValidCOMEXE ( HANDLE Handle , int * InternalFileType , LARGE_INTEGER *FileLength)
{
	unsigned char Buffer [ 10 ] ;
	int ExeFileType ;
	unsigned long RetValue = 0 ;
	DWORD BytesRead ;
	LARGE_INTEGER FilePointer;

	if ( Handle == INVALID_HANDLE_VALUE )
	{
		return ( 2 ) ;
	}

	FilePointer . QuadPart = 0 ;

	SetFilePointerEx ( Handle , FilePointer , NULL , SEEK_SET ) ;

	memset ( Buffer, 0, sizeof ( Buffer ) ) ;

	if ( ReadFile ( Handle , Buffer , sizeof ( Buffer ) , &BytesRead , NULL ) == 0 )
	{
		return ( 3 ) ;
	}

	//if first two bytes are MZ or ZM then it is a EXE file
	if ( ! memcmp ( Buffer, "MZ",  2 ) || ! memcmp ( Buffer, "ZM",  2 ) )
	{
		RetValue = GetEXEFileType ( Handle, &ExeFileType ) ;

		if ( RetValue != 0 )
		{
			return ( RetValue ) ;
		}
		else
		{
			* InternalFileType = ExeFileType ;
			return ( 0 ) ;
		}
	}
	else
	{
		//// if COM file is greater than 64k, it is not valid COM file
		//GetFileLength ( Handle, FileLength ) ;

		//if ( FileLength -> QuadPart <= 65536L )
		//{
		//	* InternalFileType = VI_COM ;
		//	return ( 0 ) ;
		//}
		//else
		//{
		//	return ( 4 ) ;
		//}
		return ( 4 ) ;
	}

	return ( 5 ) ;
}//IsItValidCOMEXE

int GetDosAndWin32EntryPoint ( HANDLE handle , unsigned int Flag , unsigned char * hExecutionPath , short int InternalFileType , unsigned char * hExecutionPathWidth ,
	unsigned char * DOSHeader , unsigned char * ExtendedHeader , unsigned char * OptionalHeader , unsigned char * SectionHeader , LARGE_INTEGER * _EntryPoint ,
	int * EntryPointSectionNumber , int * NewEntryPointSectionNumber )
{
	int RetVal ;
	LARGE_INTEGER EntryPoint ;
	SEGMENTS Segments [ 128 ] = { 0 } ;
	LARGE_INTEGER CurrentEntryPoint ;
	unsigned long int BaseOfCode , ImageBase ;

	EntryPoint . QuadPart = 0 ;
	CurrentEntryPoint . QuadPart = 0 ;
	BaseOfCode = 0 ;
	RetVal = GetEntryPointAndEliminationAnalysis ( handle, InternalFileType, &EntryPoint , Segments , &ImageBase , &BaseOfCode , DOSHeader , ExtendedHeader , OptionalHeader , SectionHeader , EntryPointSectionNumber ) ;
	if ( 0 != RetVal )
	{
		return ( RetVal ) ;
	}

	_EntryPoint -> QuadPart = EntryPoint . QuadPart ;

	//malloc hExecutionPath here
	if ( InternalFileType == VI_COM || InternalFileType == VI_EXE )
	{
		//for 16 bit
		memset ( hExecutionPath , 0 , EXECUTIONPATHLENGTH ) ;
		memset ( hExecutionPathWidth , 0 , EXECUTIONPATHLENGTH ) ;

		RetVal = MakeDeassembly ( handle , Flag , EntryPoint , 16 , hExecutionPath , InternalFileType ,
								  NULL , 0 , hExecutionPathWidth , Segments , ImageBase , BaseOfCode , & CurrentEntryPoint , NULL ) ;
	}
	else
	{
		//for 32 bit
		memset ( hExecutionPath , 0 , EXECUTIONPATHLENGTH ) ;
		memset ( hExecutionPathWidth , 0 , EXECUTIONPATHLENGTH ) ;

		RetVal = MakeDeassembly ( handle , Flag , EntryPoint , 32 , hExecutionPath , InternalFileType ,
								  NULL , 0 , hExecutionPathWidth , Segments , ImageBase , BaseOfCode , & CurrentEntryPoint , NewEntryPointSectionNumber ) ;
	}

	return ( RetVal ) ;
}//GetDosAndWin32EntryPoint

_declspec (dllexport) int GetSignatureInformationInternal ( unsigned int Flag , WCHAR * FilePath , unsigned char * ExecPath , unsigned char * ExecWidth , unsigned char * Exec16Path , unsigned char * Exec16Width , unsigned char * DOSHeader , unsigned char * ExtendedHeader , unsigned char * OptionalHeader , unsigned char * SectionHeader , int * _InternalFileType , LARGE_INTEGER * _EntryPoint , LARGE_INTEGER * FileLength , int * EntryPointSectionNumber , int * NewEntryPointSectionNumber , BYTE * MD5Signature, int iExecutableType)
{
	int RetVal , InternalFileType ; 
	HANDLE Handle ;
	unsigned char * ExecutionPath , * ExecutionPathWidth ;
	LARGE_INTEGER NewEntryPoint ;

	Handle = CreateFile ( FilePath , GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE , NULL , OPEN_EXISTING , 0 , NULL ) ;
	if ( Handle == INVALID_HANDLE_VALUE )
	{
		return ( 10 ) ;
	}

	RetVal = IsItValidCOMEXE ( Handle , &InternalFileType, FileLength) ;
	if ( 0 != RetVal )
	{
		CloseHandle ( Handle ) ;
		return ( RetVal ) ;
	}

	NewEntryPoint . QuadPart = 0 ;
	SetFilePointerEx ( Handle , NewEntryPoint , NULL , FILE_BEGIN ) ;

	if ( Flag & FEATURE_GET_FILE_LENGTH )
		GetFileSizeEx ( Handle , FileLength ) ;

	if(MD5Signature && (lFileSizeLimitForMD5 == -1 || FileLength->QuadPart <= lFileSizeLimitForMD5))
	{
		NewEntryPoint . QuadPart = 0 ;
		SetFilePointerEx ( Handle , NewEntryPoint , NULL , FILE_BEGIN ) ;
		MDFile(Handle, MD5Signature, g_buffer, iSizeOfBuffer);
	}

	if((iExecutableType != 0) && (iExecutableType != 1))
	{
		CloseHandle ( Handle ) ;
		return ( 0 );
	}

	ExecutionPath = ( unsigned char * ) Malloc ( EXECUTIONPATHLENGTH ) ;
	if ( NULL == ExecutionPath )
	{
		CloseHandle ( Handle ) ;
		return ( 11 ) ;
	}

	ExecutionPathWidth = ( unsigned char * ) Malloc ( EXECUTIONPATHLENGTH ) ;
	if ( NULL == ExecutionPathWidth )
	{
		Free ( ExecutionPath ) ;
		CloseHandle ( Handle ) ;
		return ( 12 ) ;
	}

	if ( Flag & FEATURE_32BIT_EXEC_PATH )
	{
		RetVal = GetDosAndWin32EntryPoint ( Handle , Flag , ExecutionPath , InternalFileType , ExecutionPathWidth , DOSHeader , ExtendedHeader , OptionalHeader , SectionHeader , _EntryPoint , EntryPointSectionNumber , NewEntryPointSectionNumber ) ;

		strcpy ( ExecPath , ExecutionPath ) ;
		strcpy ( ExecWidth , ExecutionPathWidth ) ;
	}

	if ( 0 == RetVal && ( InternalFileType == VI_PE || InternalFileType == VI_NE  || InternalFileType == VI_LE ) )
	{
		if ( Flag & FEATURE_16BIT_EXEC_PATH )
		{
			memset ( ExecutionPath , 0 , EXECUTIONPATHLENGTH ) ;
			memset ( ExecutionPathWidth , 0 , EXECUTIONPATHLENGTH ) ;
			NewEntryPoint . QuadPart = 0 ;

			InternalFileType = VI_EXE ;
			RetVal = GetDosAndWin32EntryPoint ( Handle , Flag , ExecutionPath , InternalFileType , ExecutionPathWidth , NULL , NULL , NULL , NULL , &NewEntryPoint , EntryPointSectionNumber , NewEntryPointSectionNumber ) ;
			if ( 0 == RetVal )
			{
				strcpy ( Exec16Path , ExecutionPath ) ;
				strcpy ( Exec16Width , ExecutionPathWidth ) ;

				Free ( ExecutionPath ) ;
				Free ( ExecutionPathWidth ) ;
				CloseHandle ( Handle ) ;
				return ( 0 ) ;
			}
		}
	}

	Free ( ExecutionPath ) ;
	Free ( ExecutionPathWidth ) ;
	CloseHandle ( Handle ) ;

	return ( 13 ) ;

}//GetSignatureInformationInternal

_declspec (dllexport) int GetSignatureInformationNew ( unsigned int Flag , WCHAR * FilePath , unsigned char * ExecPath , unsigned char * ExecWidth , unsigned char * Exec16Path , unsigned char * Exec16Width , unsigned char * DOSHeader , unsigned char * ExtendedHeader , unsigned char * OptionalHeader , unsigned char * SectionHeader , int * _InternalFileType , LARGE_INTEGER * _EntryPoint , LARGE_INTEGER * FileLength , int * EntryPointSectionNumber , int * NewEntryPointSectionNumber , BYTE * MD5Signature, int iExecutableType)
{
	lFileSizeLimitForMD5 = -1;	// No file size limit for all new calls!
	return GetSignatureInformationInternal(Flag, FilePath, ExecPath, ExecWidth, Exec16Path, Exec16Width, DOSHeader, ExtendedHeader, OptionalHeader, SectionHeader, _InternalFileType, _EntryPoint, FileLength, EntryPointSectionNumber, NewEntryPointSectionNumber, MD5Signature, iExecutableType);
}

_declspec (dllexport) int GetSignatureInformation ( unsigned int Flag , WCHAR * FilePath , unsigned char * ExecPath , unsigned char * ExecWidth , unsigned char * Exec16Path , unsigned char * Exec16Width , unsigned char * DOSHeader , unsigned char * ExtendedHeader , unsigned char * OptionalHeader , unsigned char * SectionHeader , int * _InternalFileType , LARGE_INTEGER * _EntryPoint , LARGE_INTEGER * FileLength , int * EntryPointSectionNumber , int * NewEntryPointSectionNumber , BYTE * MD5Signature, int iExecutableType)
{
	lFileSizeLimitForMD5 = 10485760; //5242880;	// 10 MB file size limit for all old function calls!
	return GetSignatureInformationInternal(Flag, FilePath, ExecPath, ExecWidth, Exec16Path, Exec16Width, DOSHeader, ExtendedHeader, OptionalHeader, SectionHeader, _InternalFileType, _EntryPoint, FileLength, EntryPointSectionNumber, NewEntryPointSectionNumber, MD5Signature, iExecutableType);
}

void InvalidParamHandler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
{
	//TODO:
	OutputDebugStringA("==>DISASM:InvalidParamHandler");
}

BOOL APIENTRY DllMain ( HANDLE hInstance, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	if ( DLL_PROCESS_ATTACH == ul_reason_for_call )
	{
		_invalid_parameter_handler lpNewHandler = NULL,lpOldHandler = NULL;
		lpNewHandler = InvalidParamHandler;
		lpOldHandler = _set_invalid_parameter_handler(lpNewHandler);
		// Disable the message box for assertions.
		 _CrtSetReportMode(_CRT_ASSERT, 0);

		g_buffer = (unsigned char*)Malloc(iSizeOfBuffer);
	}
	if ( DLL_PROCESS_DETACH == ul_reason_for_call )
	{
		Free(g_buffer);
	}
	lpReserved = lpReserved ;
	return ( TRUE ) ;
}//DllMain ()

