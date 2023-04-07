#include "pch.h"
#include "U2S_Old.h"

BYTE HEADER_U2S_OLD [ 24 ] = { "MAXDBVERSION00.00.00.01" } ;

CU2S_Old :: CU2S_Old ( bool bIsEmbedded ) : CBalBST_Old ( bIsEmbedded )
{
	m_bSaveError = false ;
	m_bLoadError = false ;
}

CU2S_Old :: ~CU2S_Old()
{
	RemoveAll() ;
}

COMPARE_RESULTOLD CU2S_Old :: Compare ( ULONG64 dwKey1 , ULONG64 dwKey2 )
{
	if ( dwKey1 < dwKey2 )
		return ( SMALLOLD ) ;
	else if ( dwKey1 > dwKey2 )
		return ( LARGEOLD ) ;
	else
		return ( EQUALOLD ) ;
}

void CU2S_Old :: FreeKey ( ULONG64 dwKey )
{
	return ;
}

void CU2S_Old :: FreeData ( ULONG64 dwData )
{
	if ( ( ( LPBYTE ) dwData < m_pBuffer ) || ( ( LPBYTE ) dwData >= m_pBuffer + m_nBufferSize ) )
		Release_Old ( ( LPVOID & ) dwData ) ;

	return ;
}

bool CU2S_Old :: AppendItemAscOrder ( DWORD dwKey , LPCTSTR szData )
{
	LPTSTR szHold = 0 ;

	szHold = DuplicateString_Old ( szData ) ;
	if ( NULL == szHold )
		return ( false ) ;

	if ( !AddNODEOLDAscOrder ( dwKey , ( ULONG64 ) szHold ) )
	{
		Release_Old ( ( LPVOID& ) szHold ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CU2S_Old :: AppendItem ( DWORD dwKey , LPCTSTR szData )
{
	LPTSTR szHold = 0 ;

	szHold = DuplicateString_Old ( szData ) ;
	if ( NULL == szHold )
		return ( false ) ;

	if ( !AddNODEOLD ( dwKey , ( ULONG64 ) szHold ) )
	{
		Release_Old ( ( LPVOID& ) szHold ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CU2S_Old :: DeleteItem ( DWORD dwKey )
{
	return ( DeleteNODEOLD ( dwKey ) ) ;
}

bool CU2S_Old :: SearchItem ( DWORD dwKey , LPTSTR * ppszData )
{
	ULONG64 dwData = 0 ;

	if ( ! FindNODEOLD ( dwKey , dwData ) )
		return ( false ) ;

	if ( ppszData ) *ppszData = (LPTSTR) dwData ;
	return ( true ) ;
}

bool CU2S_Old :: GetKey ( PVOID pVPtr , DWORD& dwKey )
{
	dwKey = ( DWORD ) ( ( PNODEOLD ) pVPtr ) -> dwKey ;
	return ( true ) ;
}

bool CU2S_Old :: GetData ( PVOID pVPtr , LPTSTR& pStr )
{
	pStr = ( LPTSTR& ) ( ( ( PNODEOLD ) pVPtr ) -> dwData ) ;
	return ( true ) ;
}

bool CU2S_Old :: Load ( LPCTSTR szFileName )
{
	ULONG64 * pCurrentPtr = 0 ;
	ULONG64 dwBaseAddress = 0 ;
	DWORD dwBytesProcessed = 0 ;
	DWORD dwFileSize = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	DWORD dwBytesRead = 0 ;
	TCHAR * pString = 0 ;
	BYTE VERSION_FROM_FILE [ sizeof ( HEADER_U2S_OLD ) ] = { 0 } ;
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

	if ( memcmp ( HEADER_U2S_OLD , VERSION_FROM_FILE , sizeof ( VERSION_FROM_FILE ) ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	m_pTemp = m_pRoot = NULL ;
	dwFileSize = GetFileSize ( hFile , 0 ) ;
	if ( dwFileSize <= sizeof ( HEADER_U2S_OLD ) )
	{
		CloseHandle ( hFile ) ;
		return ( true ) ;
	}

	dwFileSize -= sizeof ( HEADER_U2S_OLD ) ;
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
	m_pRoot = ( NODEOLD* ) m_pBuffer ;

	while ( dwBytesProcessed < dwFileSize )
	{
		pCurrentPtr++ ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		pCurrentPtr++ ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;

		dwBytesProcessed += SIZE_OF_NODEOLD ;
		pString = (TCHAR*) pCurrentPtr ;
		while ( *pString )
		{
			pString++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
		}

		pString++ ;
		dwBytesProcessed += sizeof ( TCHAR ) ;
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

bool CU2S_Old :: Save ( LPCTSTR szFileName, bool bEncryptContents )
{
	DWORD dwCurrentOffset = 0 ;
	ULONG64 dwLinkOffset = 0 ;
	DWORD dwNODEOLDOffset = 0 ;
	DWORD dwBytesWritten = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;

	if ( !MakeFullFilePath_Old ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ , 0 , CREATE_ALWAYS ,
						 FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , sizeof ( HEADER_U2S_OLD ) , 0 , FILE_BEGIN ) )
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
		if ( ! WriteFile ( hFile , m_pTemp , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		if ( ! WriteFile ( hFile , ((BYTE*)m_pTemp) + ( SIZE_OF_ONE_NODEOLD_ELEMENT * 2 ) , SIZE_OF_ONE_NODEOLD_ELEMENT * 3 , &dwBytesWritten , 0 ) )
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

		dwLinkOffset = ( _tcslen ( ( TCHAR* ) ( m_pTemp -> dwData ) ) + 1 ) * sizeof ( TCHAR ) ;
		if ( ! WriteFile ( hFile , (BYTE*) ( m_pTemp -> dwData ) , ( DWORD ) dwLinkOffset , &dwBytesWritten , 0 ) )
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

	if ( bEncryptContents && ! CryptFile_OldData_Old ( hFile , sizeof ( HEADER_U2S_OLD ) ) )
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

	if ( ! WriteFile ( hFile , HEADER_U2S_OLD , sizeof ( HEADER_U2S_OLD ) , &dwBytesWritten , 0 ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return ( true ) ;
}
