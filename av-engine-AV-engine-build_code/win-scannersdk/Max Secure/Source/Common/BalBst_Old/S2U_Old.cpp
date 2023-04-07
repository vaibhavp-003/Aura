#include "pch.h"
#include "S2U_Old.h"

BYTE HEADER_S2U_OLD [ 24 ] = { "MAXDBVERSION00.00.00.01" } ;

CS2U_Old :: CS2U_Old ( bool bIsEmbedded ) : CBalBST_Old ( bIsEmbedded )
{
	m_bSaveError = false ;
	m_bLoadError = false ;
}

CS2U_Old :: ~CS2U_Old()
{
	RemoveAll() ;
}

COMPARE_RESULTOLD CS2U_Old :: Compare ( ULONG64 dwKey1 , ULONG64 dwKey2 )
{
	LPTSTR f = (LPTSTR)dwKey1 ;
	LPTSTR s = (LPTSTR)dwKey2 ;
	int iResult = 0 ;

	while ( *f && *s && *f == *s ) f++ , s++ ;
	iResult = *f - *s ;
	if ( iResult > 0 )
		return ( LARGEOLD ) ;
	else if ( iResult < 0 )
		return ( SMALLOLD ) ;
	else
		return ( EQUALOLD ) ;
}

void  CS2U_Old :: FreeKey ( ULONG64 dwKey )
{
	if ( ( ( LPBYTE ) dwKey < m_pBuffer ) || ( ( LPBYTE ) dwKey >= m_pBuffer + m_nBufferSize ) )
		Release_Old ( ( LPVOID & ) dwKey ) ;
}

void  CS2U_Old :: FreeData ( ULONG64 dwData )
{
}

bool CS2U_Old :: AppendItemAscOrder ( LPCTSTR szKey , DWORD dwData )
{
	TCHAR * newString = 0 ;

	newString = DuplicateString_Old ( szKey ) ;
	if ( NULL == newString )
		return ( false ) ;

	if ( !AddNODEOLDAscOrder ( ( ULONG64 ) newString , dwData ) )
	{
		Release_Old ( ( LPVOID & ) newString ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CS2U_Old :: AppendItem ( LPCTSTR szKey , DWORD dwData )
{
	TCHAR * newString = 0 ;

	newString = DuplicateString_Old ( szKey ) ;
	if ( NULL == newString )
		return ( false ) ;

	if ( !AddNODEOLD ( ( ULONG64 ) newString , dwData ) )
	{
		Release_Old ( ( LPVOID & ) newString ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CS2U_Old :: DeleteItem ( LPCTSTR szKey )
{
	return ( DeleteNODEOLD ( ( ULONG64 ) szKey ) ) ;
}

bool CS2U_Old :: SearchItem ( LPCTSTR szKey , DWORD * pulData )
{
	ULONG64 dwData = 0 ;

	if ( ! FindNODEOLD ( ( ULONG64 ) szKey , dwData ) )
		return ( false ) ;

	if ( pulData ) *pulData = ( DWORD ) dwData ;
	return ( true ) ;
}

bool CS2U_Old :: GetKey ( PVOID pVPtr , LPTSTR& pStr )
{
	pStr = ( LPTSTR& ) ( ( ( PNODEOLD ) pVPtr ) -> dwKey ) ;
	return ( true ) ;
}

bool CS2U_Old :: GetData ( PVOID pVPtr , DWORD& dwData )
{
	dwData = ( DWORD ) ( ( PNODEOLD ) pVPtr ) -> dwData ;
	return ( true ) ;
}

bool CS2U_Old :: Load ( LPCTSTR szFileName )
{
	ULONG64 * pCurrentPtr = 0 ;
	ULONG64 dwBaseAddress = 0 ;
	DWORD dwBytesProcessed = 0 ;
	DWORD dwFileSize = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	DWORD dwBytesRead = 0 ;
	TCHAR * pString = 0 ;
	BYTE VERSION_FROM_FILE [ sizeof ( HEADER_S2U_OLD ) ] = { 0 } ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;

	if ( !MakeFullFilePath_Old ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( FALSE == ReadFile ( hFile , VERSION_FROM_FILE , sizeof ( VERSION_FROM_FILE ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( memcmp ( HEADER_S2U_OLD , VERSION_FROM_FILE , sizeof ( VERSION_FROM_FILE ) ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	m_pTemp = m_pRoot = NULL ;
	dwFileSize = GetFileSize ( hFile , 0 ) ;
	if ( dwFileSize <= sizeof ( HEADER_S2U_OLD ) )
	{
		CloseHandle ( hFile ) ;
		return ( true ) ;
	}

	dwFileSize -= sizeof ( HEADER_S2U_OLD ) ;
	m_pBuffer = ( BYTE* ) Allocate_Old ( dwFileSize ) ;
	if ( NULL == m_pBuffer )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( FALSE == ReadFile ( hFile , m_pBuffer , dwFileSize , &dwBytesRead , 0 ) )
	{
		Release_Old ( ( LPVOID & ) m_pBuffer ) ;
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( dwFileSize != dwBytesRead )
	{
		Release_Old ( ( LPVOID & ) m_pBuffer ) ;
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	CryptBuffer_Old ( m_pBuffer , dwFileSize ) ;

	dwBaseAddress = ( ULONG64 ) m_pBuffer ;
	dwBaseAddress -= sizeof ( VERSION_FROM_FILE ) ;
	pCurrentPtr = ( ULONG64* ) m_pBuffer ;

	m_pRoot = ( NODEOLD* ) pCurrentPtr ;
	while ( dwBytesProcessed < dwFileSize )
	{
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		pCurrentPtr++ ;
		pCurrentPtr++ ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;

		dwBytesProcessed += SIZE_OF_NODEOLD ;
		pString = (TCHAR*) pCurrentPtr ;
		while ( *pString )
		{
			pString++ ;
			dwBytesProcessed ++ ;
			dwBytesProcessed ++ ;
		}

		pString++ ;
		dwBytesProcessed ++ ;
		dwBytesProcessed ++ ;

		pCurrentPtr = (ULONG64*) pString ;
	}

	m_nBufferSize = dwFileSize ;
	m_bLoadedFromFile = true ;
	return ( true ) ;

ERROR_EXIT:
	m_pRoot = m_pTemp = NULL ;
	Release_Old ( ( LPVOID& ) m_pBuffer ) ;
	m_bLoadedFromFile = false ;
	m_nBufferSize = 0 ;
	DeleteFile ( szFullFileName ) ;
	AddLogEntry ( L"Error in loading: %s. File Deleted" , szFullFileName ) ;
	return ( false ) ;
}

bool CS2U_Old :: Save ( LPCTSTR szFileName, bool bEncryptContents )
{
	DWORD dwCurrentOffset = 0 ;
	ULONG64 dwLinkOffset = 0 ;
	ULONG64 dwNODEOLDOffset = 0 ;
	DWORD dwBytesWritten = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;

	if ( !MakeFullFilePath_Old ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ , 0 , CREATE_ALWAYS ,
						 FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , sizeof ( HEADER_S2U_OLD ) , 0 , FILE_BEGIN ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	m_bSaveError = false ;
	m_pTemp = m_pRoot ;

	while ( m_pTemp )
	{
		dwNODEOLDOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
		dwLinkOffset = dwNODEOLDOffset + sizeof ( NODEOLD ) ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		if ( ! WriteFile ( hFile , ((BYTE*)m_pTemp) + SIZE_OF_ONE_NODEOLD_ELEMENT , SIZE_OF_ONE_NODEOLD_ELEMENT * 4 , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwLinkOffset = m_pTemp -> pParent ? m_pTemp -> pParent -> dwHold : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwLinkOffset = ( _tcslen ( ( TCHAR* ) ( m_pTemp -> dwKey ) ) + 1 ) * sizeof ( TCHAR ) ;
		if ( ! WriteFile ( hFile , (BYTE*) ( m_pTemp -> dwKey ) , ( DWORD ) dwLinkOffset , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		m_pTemp -> dwHold = dwNODEOLDOffset ;
		dwLinkOffset = 0 ;

		if ( m_pTemp -> pLeft )
		{
			dwLinkOffset = dwNODEOLDOffset + ( SIZE_OF_ONE_NODEOLD_ELEMENT * 3 ) ;
			m_pTemp = m_pTemp -> pLeft ;
		}
		else if ( m_pTemp -> pRight )
		{
			dwLinkOffset = dwNODEOLDOffset + ( SIZE_OF_ONE_NODEOLD_ELEMENT * 4 ) ;
			m_pTemp = m_pTemp -> pRight ;
		}
		else
		{
			while ( m_pTemp )
			{
				if ( NULL == m_pTemp -> pParent )
				{
					m_pTemp = NULL ;
				}
				else if ( m_pTemp == m_pTemp -> pParent -> pRight )
				{
					m_pTemp = m_pTemp -> pParent ;
				}
				else if ( m_pTemp -> pParent -> pRight )
				{
					dwLinkOffset = m_pTemp -> pParent -> dwHold + ( SIZE_OF_ONE_NODEOLD_ELEMENT * 4 ) ;
					m_pTemp = m_pTemp -> pParent -> pRight ;
					break ;
				}
				else
				{
					m_pTemp = m_pTemp -> pParent ;
				}
			}
		}

		if ( dwLinkOffset )
		{
			dwCurrentOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
			SetFilePointer ( hFile , ( DWORD ) dwLinkOffset , 0 , FILE_BEGIN ) ;
			if ( ! WriteFile ( hFile , &dwCurrentOffset , sizeof ( dwCurrentOffset ) , &dwBytesWritten , 0 ) )
			{
				m_bSaveError = true ;
				break ;
			}

			SetFilePointer ( hFile , dwCurrentOffset , 0 , FILE_BEGIN ) ;
		}
	}

	if ( m_bSaveError )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		AddLogEntry ( L"Error in saving: %s. File Deleted" , szFullFileName ) ;
		return ( false ) ;
	}

	if ( bEncryptContents && ! CryptFile_OldData_Old ( hFile , sizeof ( HEADER_S2U_OLD ) ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , 0 , 0 , FILE_BEGIN ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	if ( FALSE == WriteFile ( hFile , HEADER_S2U_OLD , sizeof ( HEADER_S2U_OLD ) , &dwBytesWritten , 0 ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return ( true ) ;
}
