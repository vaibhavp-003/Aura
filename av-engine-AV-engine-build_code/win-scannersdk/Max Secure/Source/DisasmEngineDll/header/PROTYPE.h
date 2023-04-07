//Prototypes.h

#ifndef	PROTYPE

	#define	PROTYPE


#include <stdio.h>

#include "comtypes.h"
#include "defines.h"
#include "oscomdef.h"
#include "retvalue.h"

#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

//File Related Functions

//==============================================================================
OS_ULONG OS_Splitpath ( OS_SCTBYTE* Path, OS_SBYTE* Drive, OS_SBYTE* Dir,
						OS_SBYTE* Fname, OS_SBYTE* Ext ) ;

OS_ULONG OS_Makepath ( OS_SBYTE* Path, OS_SCTBYTE* Drive, OS_SCTBYTE* Dir,
						OS_SCTBYTE* Fname, OS_SCTBYTE* Ext ) ;

//==============================================================================

OS_ULONG OS_Creat ( OSFILEHANDLE * Handle, OS_SCTBYTE* FileName, OSFILEMODE Pmode ) ;

OS_ULONG OS_Open ( OSFILEHANDLE* FileHandle, OS_SCTBYTE* PathName,
						OSFILEFLAGS Oflag, OSFILEMODE Pmode, OSFILESHFLAG Sflag ) ;

OS_ULONG OS_Close ( OSFILEHANDLE FileHandle ) ;

OS_ULONG OS_Read ( OSFILEHANDLE FileHandle, OS_BYTE* Buffer, OSFILEDATA Bytes,
						OSFILEDATA* BytesRead ) ;

OS_ULONG OS_Write ( OSFILEHANDLE FileHandle, OS_BYTE* Buffer, OSFILEDATA Bytes,
						OSFILEDATA* BytesWritten ) ;

OS_ULONG OS_Lseek ( OSFILEHANDLE handle, /*OS_ULONG */OS_LONG FileOffset, OS_SHORT FromWhere,
						OS_ULONG * FilePos ) ;

OS_ULONG OS_Unlink ( OS_SCTBYTE * FileName ) ;

OS_ULONG OS_Getmode ( OS_SCTBYTE* FileName, OSFILEMODE *Pmode );

OS_ULONG OS_Chmod ( OS_SCTBYTE* FileName, OSFILEMODE Pmode ) ;

OS_ULONG OS_Filelength ( OSFILEHANDLE handle, OS_LONG * FLength ) ;

OS_ULONG OS_Chsize ( OSFILEHANDLE Handle, OS_LONG Size );

OS_ULONG OS_GetFileAttribute ( OS_SCTBYTE * FilePath , OSFILEMODE * Attribute ) ;

OS_ULONG OS_SetFileAttribute ( OS_SCTBYTE * FilePath , OSFILEMODE Attribute ) ;


//==============================================================================

OS_ULONG OS_Rename ( OS_SCTBYTE* OldName, OS_SCTBYTE* NewName ) ;

OS_ULONG OS_Access ( OS_SCTBYTE* FileName, OSFILEMODE aMode ) ;

//==============================================================================

//Dir Related Functions

OS_ULONG OS_Chdir ( OS_SCTBYTE* Path ) ;
OS_ULONG OS_OpenDir ( OSDIRHANDLE* handle, OS_SCTBYTE* PathName ) ;
OS_ULONG OS_ReadDir ( OSDIRHANDLE* handle, OS_FileStruct* FileStruct, OS_SHORT Attrib ) ;
OS_ULONG OS_CloseDir ( OSDIRHANDLE* Handle ) ;

//==============================================================================

// Error Functions

OS_SHORT GetEquivalentErrorCode ( OSERRORNO ErrorNo ) ;
/*void SetErrorValues ( RETURNVALUE* RetVal, OS_USHORT ModuleNumber,
						OS_USHORT LineNumber, OS_USHORT AppErrNumber,
						OS_USHORT SystemErrNumber ) ;*/
void SetErrorValues ( RETURNVALUE* RetVal, OS_USHORT ModuleNumber,
					OS_USHORT LineNumber, OS_USHORT AppErrNumber,
					OS_USHORT SystemErrNumber ) ;

//==============================================================================

// Memory Related Functions

OS_ULONG OS_Malloc ( OSGLOBALMEM* ptr , OS_ULONG Bytes , OS_SHORT Flag )  ;
OS_ULONG OS_Free ( OSGLOBALMEM Ptr ) ;
OS_ULONG OS_GlobalLock ( OSGLOBALMEM ptr , OSGLOBALPTR* MemPtr ) ;
OS_ULONG OS_GlobalUnLock ( OSGLOBALMEM ptr ) ;
//AMOL
void PrintMemoryAllocated ( char * ) ;
void PrintMCB (void);
//AMOL

//==============================================================================
//Stream Related functions

OS_ULONG OS_Fopen ( FILE **Fptr, OS_SCTBYTE* FileName, OS_SCTBYTE* mode ) ;
OS_ULONG OS_Fclose ( FILE *ptr ) ;
OS_ULONG OS_Fseek ( FILE *ptr, OS_ULONG FileOffset, OS_SHORT FromWhere ) ;
OS_ULONG OS_Ftell ( FILE* ptr, OS_ULONG * FileOffset ) ;
OS_ULONG OS_Fread ( void* Buffer , OS_ULONG Size, OS_ULONG Count, FILE* Fptr ) ;
OS_ULONG OS_Fwrite ( const void* Buffer, OS_ULONG Size, OS_ULONG Count, FILE* Fptr ) ;
OS_ULONG OS_Fgets ( OS_SBYTE *String, OSFILECOUNT n, FILE *Fptr ) ;
OS_ULONG OS_Fputs ( OS_SCTBYTE* String, FILE* Fptr ) ;
OS_ULONG OS_Fgetc ( FILE* Fptr, OSFILECOUNT *Value ) ;
OS_ULONG OS_Fputc ( OSFILECOUNT* Value, FILE* Fptr ) ;
//OS_ULONG OS_Feof ( FILE* Fptr, OSFILECOUNT* Value ) ;
OS_ULONG OS_Feof ( FILE* Fptr ) ;
OS_ULONG OS_Fgetpos ( FILE *Fptr, OSFILEPOS *pos ) ;
OS_ULONG OS_Fsetpos ( FILE *Fptr, OSFILEPOS *pos ) ;
OS_ULONG OS_Fflush ( FILE* Fptr ) ;

//==============================================================================

// String Related
OS_ULONG OS_Strupr ( OS_SBYTE* String ) ;

//==============================================================================

//Date/Time related functions.

OS_ULONG OS_GetDateTime ( OSFILEHANDLE handle, OS_DATETIME * pDateTime );
OS_ULONG OS_SetDateTime ( OSFILEHANDLE handle, OS_DATETIME * pDateTime );

#endif