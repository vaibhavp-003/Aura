
/*======================================================================================
FILE             : Getstr.cpp
ABSTRACT         : File to get strings from binary file.
DOCUMENTS	     : 
AUTHOR		     : 
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 01 Jul, 2009.
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "stdafx.h"
#include <stdio.h>
#include <io.h>
#include <stdarg.h>
#include "GetStr.h"

#define ONE_KB			0x400
#define IO_BUF_SIZE		ONE_KB * 4

/*--------------------------------------------------------------------------------------
Function       : Strcpy 
In Parameters  : TCHAR * Dst, DWORD cbDst, TCHAR const * Src, 
Out Parameters : bool
Description    : Copy string
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool Strcpy ( TCHAR * Dst , DWORD cbDst , TCHAR const * Src )
{
	if ( _tcslen ( Src ) >= cbDst )
		return ( false ) ;

	SecureZeroMemory ( Dst , cbDst * sizeof(TCHAR) ) ;
	_tcscpy_s ( Dst , cbDst , Src ) ;
	return ( true ) ;
}

/*--------------------------------------------------------------------------------------
Function       : Strcat 
In Parameters  :  TCHAR * Dst, DWORD cbDst, TCHAR const * Src, 
Out Parameters : bool ool 
Description    : Append a string
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool Strcat ( TCHAR * Dst , DWORD cbDst , TCHAR const * Src )
{
	if ( _tcslen ( Src ) + _tcslen ( Dst ) >= cbDst )
		return ( false ) ;

	_tcscat_s ( Dst , cbDst , Src ) ;
	return ( true ) ;
}

/*--------------------------------------------------------------------------------------
Function       : GetExeType 
In Parameters  : TCHAR const * Filename, TCHAR * ExeType, DWORD cbExeType, 
Out Parameters : bool 
Description    : Check PE header and find file is PE file or not.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool GetExeType ( TCHAR const * Filename , TCHAR * ExeType , DWORD cbExeType )
{
	IMAGE_DOS_HEADER DosHeader = { 0 } ;
	IMAGE_NT_HEADERS NtHeader = { 0 } ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	DWORD BytesRead = 0 ;

	hFile = CreateFile ( Filename , GENERIC_READ , FILE_SHARE_READ ,
						 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL ,
						 NULL ) ;
	if ( hFile == INVALID_HANDLE_VALUE )
	{
		printf ( "Error opening file: %s\r\n" , Filename ) ;
		return ( false ) ;
	}

#pragma warning(disable: 6031)
	ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &BytesRead , 0 ) ;
#pragma warning(default: 6031)
	SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
#pragma warning(disable: 6031)
	ReadFile ( hFile , &NtHeader , sizeof ( NtHeader ) , &BytesRead , 0 ) ;
#pragma warning(default: 6031)
	CloseHandle ( hFile ) ;
	
	memcpy ( ExeType , &NtHeader.Signature , 2 ) ;

	if ( _tcsnicmp ( ExeType , _T("PE") , 2 ) >= 0 )
	{
		return Strcpy ( ExeType , cbExeType , _T("Win32 Executable") ) ;
	}
	else if ( _tcsnicmp ( ExeType , _T("NE") , 2 ) >= 0 )
	{
		return Strcpy ( ExeType , cbExeType , _T("Win16 Executable") ) ;
	}
	else if ( _tcsnicmp ( ExeType , _T("LE") , 2 ) >= 0 )
	{
		return Strcpy ( ExeType , cbExeType , _T("OS//2 Executable") ) ;
	}
	else
	{
		memcpy ( ExeType , &DosHeader , 2 ) ;
		
		//if ( !_tcsnicmp ( ExeType , _T("MZ") , 2 ) || !_tcsnicmp ( ExeType , _T("ZM") , 2 ) )
		if ( ( _tcsnicmp ( ExeType , _T("MZ") , 2 ) >= 0 ) || ( _tcsnicmp ( ExeType , _T("ZM") , 2 ) >= 0 )) 
			return Strcpy ( ExeType , cbExeType , _T("DOS Executable") ) ;
		else
			return Strcpy ( ExeType , cbExeType , _T("Non Executable") ) ;
	}
}

/*--------------------------------------------------------------------------------------
Function       : JoinStrings 
In Parameters  :  TCHAR * Dst, DWORD cbDst, TCHAR const * first, ..., 
Out Parameters : bool ool 
Description    : join two strings.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool JoinStrings ( TCHAR * Dst , DWORD cbDst , TCHAR const * first , ... )
{
	TCHAR const * str = first ;
	va_list marker ;
	bool bRetVal = true ;

	va_start ( marker , first ) ;
	SecureZeroMemory ( Dst , cbDst ) ;

	while ( str && bRetVal )
	{
		if ( Dst [ 0 ] == '\0' )
		{
			if ( !Strcpy ( Dst , cbDst , str ) )
				bRetVal = false ;
		}
		else
		{
			if ( !Strcat ( Dst , cbDst , str ) )
				bRetVal = false ;
		}

		str = va_arg ( marker , TCHAR* ) ;
	}

	va_end ( marker ) ;
	return ( bRetVal ) ;
}

/*--------------------------------------------------------------------------------------
Function       : ischar 
In Parameters  : CHAR ch, 
Out Parameters : bool 
Description    : Check char is in 0-9 or A-Z or a-z or _, , ., \, /, ~
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool ischar ( CHAR ch )
{
	return (
			( ch >= '0' && ch <= '9' ) ||
			( ch >= 'A' && ch <= 'Z' ) ||
			( ch >= 'a' && ch <= 'z' ) ||
			( ch == '_' ) || ( ch == ' ' ) ||
			( ch == '.' ) || ( ch == '\\') ||
			( ch == '/' ) || ( ch == '~' )
		   ) ;
}

/*--------------------------------------------------------------------------------------
Function       : WriteOnlyStrings 
In Parameters  : HANDLE hFile, CHAR * Buffer, DWORD cbBuffer, 
Out Parameters : BOOL 
Description    : Write string to the file.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
BOOL WriteOnlyStrings ( HANDLE hFile , CHAR * Buffer , DWORD cbBuffer )
{
	DWORD i = 0 , iWB = 0 , bw = 0 , rv = 0 ;
	TCHAR WriteBuffer [ IO_BUF_SIZE ] = { 0 } ;
	bool bBufferOverFlow = false ;
	TCHAR lpCR[] = {0x0d, 0x0a, 0x00};

	for ( i = 0 ; i < cbBuffer ; i++ )
	{
		if ( ischar ( Buffer [ i ] ) )
		{
			// error handling, write buffer full
			if ( iWB >= sizeof WriteBuffer )
			{
				// set a flag on for buffer overflow
				bBufferOverFlow = true ;

				// write 'WriteBuffer' in the file
				rv = WriteFile ( hFile , WriteBuffer , iWB * sizeof( TCHAR ) , &bw , 0 ) ;
				if ( 0 == rv || ( iWB * sizeof( TCHAR ) != bw ) )
				{
					return ( FALSE ) ;
				}

				// reset the buffer
				iWB = 0 ;
				SecureZeroMemory ( WriteBuffer , sizeof (WriteBuffer) ) ;

				// if the next character is not in out charset
				// write a new line char
				if ( i + 1 < cbBuffer && !ischar ( Buffer [ i + 1 ] ) )
				{
					
					//WriteFile ( hFile , "\r\n" , 2 , &bw , 0 ) ;
					WriteFile ( hFile , lpCR , 4 , &bw , 0 ) ;

					// if the string has ended, set overflow false
					bBufferOverFlow = false ;
				}
			}

			WriteBuffer [ iWB++ ] = Buffer [ i ] ;
		}
		else
		{
			if ( bBufferOverFlow || iWB > 3 )
			{
				rv = WriteFile ( hFile , WriteBuffer , iWB * sizeof( TCHAR ), &bw , 0 ) ;
				if ( 0 == rv || ( iWB * sizeof( TCHAR ) != bw ) )
				{
					DWORD ret  = GetLastError();
					return ( FALSE ) ;
				}

				//WriteFile ( hFile , "\r\n" , 2 , &bw , 0 ) ;
				WriteFile ( hFile , lpCR , 4 , &bw , 0 ) ;

				bBufferOverFlow = false ;
			}

			if ( 0 != iWB )
			{
				iWB = 0 ;
				SecureZeroMemory ( WriteBuffer , sizeof (WriteBuffer)) ;
			}
		}
	}

	return ( TRUE ) ;
}

/*--------------------------------------------------------------------------------------
Function       : UncompressFile 
In Parameters  : TCHAR const * FileName, 
Out Parameters : bool 
Description    : uncompress file.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool UncompressFile ( TCHAR const * FileName )
{
USES_CONVERSION;

	TCHAR command [ MAX_PATH ] = { 0 } ;
	TCHAR UpxFilename [ MAX_PATH ] = { 0 };

	//if ( _tcschr ( A2T(__argv [ 0 ]) , '\\' ) )
	//	{
	//		_tcscpy ( UpxFilename, A2T ( __argv [ 0 ] ) );
	//		//if ( !JoinStrings ( UpxFilename , sizeof ( UpxFilename ) * sizeof ( TCHAR ) , A2T(__argv [ 0 ]) , NULL ) )
	//		//	return ( false ) ;

	//		* ( _tcsrchr ( UpxFilename , '\\' ) ) = '\0' ;

	//		_tcscat ( UpxFilename, _T( "\\upx.exe" ) );
	//		//if ( !Strcat ( UpxFilename , sizeof ( UpxFilename ) * sizeof (TCHAR) , _T("\\upx.exe") ) )
	//		//	return ( false ) ;
	//	}
	//}
	//else
	//{
	//	_tcscpy_s ( UpxFilename , _T("upx.exe") ) ;
	//}

	if ( _taccess ( UpxFilename , 0 ) )
		return ( false ) ;

	if ( !JoinStrings ( command , sizeof ( command ) / sizeof(TCHAR), UpxFilename , _T(" -d \"") , FileName , _T("\"") , NULL ) )
		return ( false ) ;

	_tsystem ( command ) ;

	return ( true ) ;
}

/*--------------------------------------------------------------------------------------
Function       : DumpTextStrings 
In Parameters  :  TCHAR const * TargetFileName, TCHAR const * LogFile, 
Out Parameters : bool ool 
Description    : Dump strings to the text file.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool DumpTextStrings ( TCHAR const * TargetFileName , TCHAR const * LogFile )
{
	HANDLE hTargetFile = NULL , hLogFile = NULL ;
	CHAR Buffer [ IO_BUF_SIZE ] = { 0 } ;
	DWORD BytesRead = 0 , TotalBytesRead = 0 , FileLength = 0 ;
	DWORD BytesToRead = 0 , ApiStatus = 0 , BytesWritten = 0 ;
	TCHAR ExecutableType [ 100 ] = { 0 } ;
	WORD wBOM = 0xFEFF;
	TCHAR lpCR[] = {0x0d, 0x0a, 0x00};
	//PVOID pBuffer = NULL;

	if ( !GetExeType ( TargetFileName , ExecutableType , sizeof ( ExecutableType )/sizeof( TCHAR ) ) )
	{
		printf ( "Failed determining executable file type for: %s\r\n" , TargetFileName ) ;
		return ( false ) ;
	}
	
	hTargetFile = CreateFile ( TargetFileName , GENERIC_READ ,
								FILE_SHARE_READ , 0 , OPEN_EXISTING , 
								FILE_ATTRIBUTE_NORMAL , NULL ) ;
	if ( hTargetFile == INVALID_HANDLE_VALUE )
	{
		printf ( "Error opening file: %s\r\n" , TargetFileName ) ;
		return ( false ) ;
	}

	hLogFile = CreateFile ( LogFile , GENERIC_WRITE ,
							FILE_SHARE_READ , 0 , CREATE_NEW ,
							FILE_ATTRIBUTE_NORMAL , NULL ) ;
	if ( hLogFile == INVALID_HANDLE_VALUE )
	{
		//printf ( "Error creating file: %s\r\n" , LogFile ) ;
		CString csLogFile=LogFile;
		CloseHandle ( hTargetFile ) ;
		return ( false ) ;
	}

	//Write BOM
	BytesWritten = 0 ;
	//::WriteFile(hLogFile, &wBOM, sizeof(WORD), &BytesWritten, NULL);

	BytesWritten = 0 ;
	WriteFile ( hLogFile , _T("ExecutableType: ") , _tcslen ( _T("ExecutableType: ") ) * sizeof( TCHAR ) ,
				&BytesWritten , 0 ) ;
	BytesWritten = 0 ;
	WriteFile ( hLogFile , ExecutableType , _tcslen ( ExecutableType ) * sizeof( TCHAR ),
				&BytesWritten , 0 ) ;
	BytesWritten = 0 ;
	WriteFile ( hLogFile , lpCR , 4 , &BytesWritten , 0 ) ;

	FileLength = GetFileSize ( hTargetFile , NULL ) ;

	while ( TotalBytesRead < FileLength )
	{
		if ( sizeof Buffer < ( FileLength - TotalBytesRead ) )
			BytesToRead = sizeof Buffer ;
		else
			BytesToRead = FileLength - TotalBytesRead ;

		ApiStatus = ReadFile ( hTargetFile ,(PVOID) Buffer , BytesToRead ,
							   &BytesRead , 0 ) ;
		if ( 0 == ApiStatus || ( BytesToRead != BytesRead ) )
		{
			//CloseHandle ( hLogFile ) ;
			//CloseHandle ( hTargetFile ) ;
			break ;
		}

		ApiStatus = WriteOnlyStrings ( hLogFile , Buffer , BytesRead ) ;
		if ( FALSE == ApiStatus )
		{
			//CloseHandle ( hLogFile ) ;
			//CloseHandle ( hTargetFile ) ;
			break ;
		}

		SecureZeroMemory ( Buffer , sizeof Buffer ) ;
		TotalBytesRead += BytesRead ;
	}

	CloseHandle ( hTargetFile ) ;
	CloseHandle ( hLogFile ) ;

	return ( true ) ;
}

//void DisplayUsage ( void )
//{
//	////OutputDebugString("Looks for sample.exe in the current folder\r\nIf found, dumps all the ascii strings in sample.txt\r\n");
//}

/*--------------------------------------------------------------------------------------
Function       : IsDots 
In Parameters  : TCHAR const * Filename, 
Out Parameters : bool 
Description    : Is Dot present in file path
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool IsDots ( TCHAR const * Filename )
{
	return ( !_tcscmp ( Filename , _T(".") ) || !_tcscmp ( Filename , _T("..") ) ) ;
}

/*--------------------------------------------------------------------------------------
Function       : EnumerateFolder 
In Parameters  : TCHAR const * Folder, 
Out Parameters : bool 
Description    : Enumerate folder.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool EnumerateFolder ( TCHAR const * Folder )
{
	WIN32_FIND_DATA FindData = { 0 } ;
	HANDLE hSearch = INVALID_HANDLE_VALUE ;
	BOOL bDone = TRUE ;
	TCHAR SearchPath [ MAX_PATH ] = { 0 } ;
	TCHAR FullPath [ MAX_PATH ] = { 0 } ;
	TCHAR LogFilePath [ MAX_PATH ] = { 0 } ;
	TCHAR Filename [ MAX_PATH ] = { 0 } ;

	if ( !JoinStrings ( SearchPath , sizeof ( SearchPath ) / sizeof ( TCHAR ) , Folder , _T("\\*") , NULL ) )
		return ( false ) ;

	hSearch = FindFirstFile ( SearchPath , &FindData ) ;
	if ( INVALID_HANDLE_VALUE == hSearch )
	{
		return ( false ) ;
	}

	while ( bDone )
	{
		if ( !JoinStrings ( FullPath , sizeof ( FullPath ) /sizeof ( TCHAR ), Folder , _T("\\") , FindData . cFileName , NULL ) )
			break ;

		if ( ( FindData . dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) ==
										   FILE_ATTRIBUTE_DIRECTORY )
		{
			if ( !IsDots ( FindData . cFileName ) )
				EnumerateFolder ( FullPath ) ;
		}
		else
		{
			SecureZeroMemory ( Filename , sizeof ( Filename ) ) ;
			// _splitpath ( FullPath , 0 , 0 , Filename , 0 ) ;
			
			_tsplitpath_s ( FullPath , 0 , 0 , 0, 0, Filename , MAX_PATH, 0, 0 ) ;

			if ( Filename [ 0 ] != 0 )
				if ( JoinStrings ( LogFilePath , sizeof ( LogFilePath ) / sizeof( TCHAR ), Folder , _T("\\") , Filename , _T(".txt") , NULL ) )
					DumpTextStrings ( FullPath , LogFilePath ) ;
		}


		SecureZeroMemory ( &FindData , sizeof ( FindData ) ) ;
		bDone = FindNextFile ( hSearch , &FindData ) ;
	}

	FindClose ( hSearch ) ;
	return ( false ) ;
}

/*
int main ( int argc , char * argv[] )
{
	char * TargetFileName = "sample.exe" , * LogFile = "sample.txt" ;

	// asking help
	if ( argc == 2 && !strcmp ( argv [ 1 ] , "/?" ) )
	{
		DisplayUsage() ;
		return ( 0 ) ;
	}

	// asking help
	if ( argc == 2 && ( argv [ 1 ] [ 0 ] == '?' ) )
	{
		DisplayUsage() ;
		return ( 0 ) ;
	}

	// using sample.exe from current path
	if ( argc == 1 && _access ( TargetFileName , 0 ) )
	{
		DisplayUsage() ;
		return ( 0 ) ;
	}

	if ( 1 == argc )
	{
		DumpTextStrings ( TargetFileName , LogFile ) ;
	}
	else
	{
		EnumerateFolder ( argv [ 1 ] ) ;
	}

	return ( 0 ) ;
}*/