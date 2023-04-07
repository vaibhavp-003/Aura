#include "pch.h"
#include "SSS.h"

BYTE HEADER_SSS [ 24 ] = { "MAXDBVERSION00.00.00.08" } ;
BYTE HEADER_SSS_DATA [ 24 ] = { 0 } ;

CSSS::CSSS(bool bIsEmbedded, bool bIgnoreCase):CBalBST(bIsEmbedded)
{
	m_bSaveError = false ;
	m_bLoadError = false ;
	m_bIgnoreCase = bIgnoreCase;
}

CSSS :: ~CSSS()
{
	RemoveAll() ;
}

COMPARE_RESULT CSSS :: Compare ( ULONG64 dwKey1 , ULONG64 dwKey2 )
{
	LPTSTR f = (LPTSTR)dwKey1 ;
	LPTSTR s = (LPTSTR)dwKey2 ;
	int iResult = 0 ;

	if(m_bIgnoreCase)
	{
		iResult = _tcsicmp(f, s);
	}
	else
	{
		while ( *f && *s && *f == *s ) f++ , s++ ;
		iResult = *f - *s ;
	}

	if(iResult > 0)
	{
		return LARGE;
	}
	else if(iResult < 0)
	{
		return SMALL;
	}
	else
	{
		return EQUAL;
	}
}

void CSSS :: FreeKey ( ULONG64 dwKey )
{
	if ( ( ( LPBYTE ) dwKey < m_pBuffer ) || ( ( LPBYTE ) dwKey >= m_pBuffer + m_nBufferSize ) )
		Release ( ( LPVOID & ) dwKey ) ;
	return ;
}

void CSSS :: FreeData ( ULONG64 dwData )
{
	CS2S objS2S ( false ) ;
	objS2S . SetDataPtr ( ( PNODE ) dwData , m_pBuffer , m_nBufferSize ) ;
	objS2S . RemoveAll () ;
	return ;
}

bool CSSS :: AppendItemAscOrder ( LPCTSTR szKey , CS2S * pObjS2S )
{
	LPTSTR szHoldKey = NULL ;

	szHoldKey = DuplicateString ( szKey ) ;
	if ( NULL == szHoldKey )
		return ( false ) ;

	if ( !AddNodeAscOrder ( ( ULONG64 ) szHoldKey , ( ULONG64 ) pObjS2S -> GetDataPtr() ) )
	{
		Release ( ( LPVOID& ) szHoldKey ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CSSS :: AppendItem ( LPCTSTR szKey , CS2S * pObjS2S )
{
	LPTSTR szHoldKey = NULL ;

	szHoldKey = DuplicateString ( szKey ) ;
	if ( NULL == szHoldKey )
		return ( false ) ;

	if ( !AddNode ( ( ULONG64 ) szHoldKey , ( ULONG64 ) pObjS2S -> GetDataPtr() ) )
	{
		Release ( ( LPVOID&) szHoldKey ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CSSS :: DeleteItem ( LPCTSTR szKey )
{
	return ( DeleteNode ( ( ULONG64 ) szKey ) ) ;
}

bool CSSS :: SearchItem ( LPCTSTR szKey , CS2S& objS2S )
{
	ULONG64 dwData = 0 ;

	if ( ! FindNode ( ( ULONG64 ) szKey , dwData ) )
		return ( false ) ;

	objS2S . SetDataPtr ( ( NODE* ) dwData , m_pBuffer , m_nBufferSize ) ;
	return ( true ) ;
}

bool CSSS :: UpdateItem ( LPCTSTR szKey , CS2S& objS2S )
{
	if ( !m_pLastSearchResult || EQUAL != Compare ( ( ULONG64 ) szKey , m_pLastSearchResult -> dwKey ) )
	{
		ULONG64 dwData = 0 ;

		if ( !FindNode ( ( ULONG64 ) szKey , dwData ) )
			return ( false ) ;

		if ( !m_pLastSearchResult || EQUAL != Compare ( ( ULONG64 ) szKey , m_pLastSearchResult -> dwKey ) )
			return ( false ) ;
	}

	m_pLastSearchResult -> dwData = ( ULONG64 ) objS2S . GetDataPtr() ;
	return ( true ) ;
}

bool CSSS :: GetKey ( PVOID pVPtr , LPCTSTR& szKey )
{
	szKey = ( LPCTSTR & ) ( ( ( PNODE ) pVPtr ) -> dwKey ) ;
	return ( true ) ;
}

bool CSSS :: GetData ( PVOID pVPtr , CS2S& objS2S )
{
	objS2S . SetDataPtr ( ( PNODE ) ( ( ( PNODE ) pVPtr ) -> dwData ) , m_pBuffer , m_nBufferSize ) ;
	return ( true ) ;
}

bool CSSS :: Balance ()
{
	LPVOID Position = NULL ;

	CBalBST :: Balance() ;

	Position = GetFirst() ;
	while (  Position )
	{
		CS2S objS2S ( true ) ;
		GetData ( Position , objS2S ) ;
		objS2S . Balance() ;
		((PNODE)Position) -> dwData = ( ULONG64 ) objS2S . GetDataPtr() ;
		Position = GetNext ( Position ) ;
	}

	return ( true ) ;
}

bool CSSS :: DeleteObject ( CBalBST& objToDel )
{
	CSSS& _objToDel = (CSSS&)objToDel;
	LPVOID lpContext = 0;
	LPCTSTR szKey = 0;

	lpContext = _objToDel.GetFirst();
	while(lpContext)
	{
		_objToDel.GetKey(lpContext, szKey);

		if(szKey)
		{
			DeleteItem(szKey);
		}

		lpContext = _objToDel.GetNext(lpContext);
	}

	return true;
}

bool CSSS :: ReadS2S ( ULONG64*& pCurrentPtr , ULONG64 dwBaseAddress , DWORD dwFileSize )
{
	DWORD dwBytesProcessed = 0 ;
	DWORD dwDataSize = 0 ;
	TCHAR * pString = 0 ;

	dwDataSize = ( DWORD ) *pCurrentPtr ;
	pCurrentPtr = ( ULONG64* ) ( ( ( LPBYTE ) pCurrentPtr ) + 4 ) ;
	dwBytesProcessed += 4 ;

	while ( dwBytesProcessed < dwDataSize )
	{
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		pCurrentPtr++ ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;

		dwBytesProcessed += SIZE_OF_NODE ;
		pString = (TCHAR*) pCurrentPtr ;
		while ( *pString )
		{
			pString++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
		}

		pString++ ;
		dwBytesProcessed += sizeof ( TCHAR ) ;

		while ( *pString )
		{
			pString++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
		}

		pString++ ;
		dwBytesProcessed += sizeof ( TCHAR ) ;

		pCurrentPtr = (ULONG64*) pString ;
	}

	return ( true ) ;

ERROR_EXIT:

	m_bLoadError = true ;
	return ( false ) ;
}

bool CSSS :: Load ( LPCTSTR szFileName , bool bCheckVersion )
{
	ULONG64 * pCurrentPtr = 0 ;
	ULONG64 dwBaseAddress = 0 ;
	DWORD dwBytesProcessed = 0 ;
	DWORD dwFileSize = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	DWORD dwBytesRead = 0 ;
	DWORD dwEmbeddedDataSize = 0 ;
	BYTE VERSION_FROM_FILE [ sizeof ( HEADER_SSS ) ] = { 0 } ;
	TCHAR * pStr = NULL ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;
	BYTE byHeaderDataFromFile [ sizeof ( HEADER_SSS_DATA ) ] = { 0 } ;
	BYTE byHeaderDataCalculated [ sizeof ( HEADER_SSS_DATA ) ] = { 0 } ;

	if ( !MakeFullFilePath ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( FALSE == ReadFile ( hFile , VERSION_FROM_FILE , sizeof ( VERSION_FROM_FILE ) , &dwBytesRead , 0 ) )
		goto ERROR_EXIT ;

	if ( bCheckVersion && memcmp ( HEADER_SSS , VERSION_FROM_FILE , sizeof ( VERSION_FROM_FILE ) ) )
		goto ERROR_EXIT ;

	if ( FALSE == ReadFile ( hFile , byHeaderDataFromFile , sizeof ( byHeaderDataFromFile ) , &dwBytesRead , 0 ) )
		goto ERROR_EXIT ;

	if ( ! CreateHeaderData ( hFile , szFullFileName , byHeaderDataCalculated , sizeof ( byHeaderDataCalculated ) ) )
		goto ERROR_EXIT ;

	if ( memcmp ( byHeaderDataFromFile , byHeaderDataCalculated , sizeof ( byHeaderDataFromFile ) ) )
		goto ERROR_EXIT ;

	m_pTemp = m_pRoot = NULL ;
	dwFileSize = GetFileSize ( hFile , 0 ) ;
	if ( dwFileSize <= sizeof ( HEADER_SSS ) + sizeof ( HEADER_SSS_DATA ) )
		goto ERROR_EXIT ;

	dwFileSize -= sizeof ( HEADER_SSS ) + sizeof ( HEADER_SSS_DATA ) ;
	m_pBuffer = ( BYTE* ) Allocate ( dwFileSize ) ;
	if ( NULL == m_pBuffer )
		goto ERROR_EXIT ;

	if ( FALSE == ReadFile ( hFile , m_pBuffer , dwFileSize , &dwBytesRead , 0 ) )
		goto ERROR_EXIT ;

	if ( dwFileSize != dwBytesRead )
		goto ERROR_EXIT ;

	CloseHandle ( hFile ) ;
	hFile = NULL;
	CryptBuffer ( m_pBuffer , dwFileSize ) ;

	dwBaseAddress = ( ULONG64 ) m_pBuffer ;
	dwBaseAddress -= sizeof ( VERSION_FROM_FILE ) + sizeof ( HEADER_SSS_DATA ) ;
	pCurrentPtr = ( ULONG64* ) m_pBuffer ;
	m_pRoot = ( NODE* ) m_pBuffer ;
	m_bLoadError = false ;

	while ( dwBytesProcessed < dwFileSize )
	{
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		pCurrentPtr++ ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_pBuffer , dwFileSize ) ;

		dwBytesProcessed += SIZE_OF_NODE ;

		pStr = ( TCHAR* ) pCurrentPtr ;
		while ( *pStr )
		{
			pStr++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
		}

		pStr++ ;
		dwBytesProcessed += sizeof ( TCHAR ) ;
		pCurrentPtr = ( ULONG64 * ) pStr ;
		dwEmbeddedDataSize = ( DWORD ) *pCurrentPtr ;

		ReadS2S ( pCurrentPtr , dwBaseAddress , dwFileSize ) ;
		if ( m_bLoadError ) goto ERROR_EXIT ;

		dwBytesProcessed += dwEmbeddedDataSize ;
	}

	Balance();
	m_nBufferSize = dwFileSize ;
	m_bLoadedFromFile = true ;
	return ( true ) ;

ERROR_EXIT:
	if ( hFile != INVALID_HANDLE_VALUE && hFile != NULL ) CloseHandle ( hFile ) ;
	m_pRoot = m_pTemp = NULL ;
	if ( m_pBuffer ) Release ( ( LPVOID& ) m_pBuffer ) ;
	m_bLoadedFromFile = false ;
	m_nBufferSize = 0 ;
	//DeleteFile ( szFullFileName ) ;
	AddLogEntry ( L"Error in loading: %s. File Deleted" , szFullFileName ) ;
	return ( false ) ;
}

bool CSSS :: DumpS2S ( HANDLE hFile , ULONG64 dwData )
{
	DWORD dwCurrentOffset = 0 ;
	ULONG64 dwLinkOffset = 0 ;
	DWORD dwNodeOffset = 0 ;
	DWORD dwBytesWritten = 0 ;
	DWORD dwTotalBytesWritten = 0 ;
	DWORD dwTotalBytesOffset = 0 ;
	NODE * pNode = ( NODE * ) dwData ;

	dwTotalBytesOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
	WriteFile ( hFile , &dwTotalBytesWritten , 4 , &dwBytesWritten , 0 ) ;
	dwTotalBytesWritten += dwBytesWritten ;

	while ( pNode )
	{
		dwNodeOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
		dwLinkOffset = dwNodeOffset + sizeof ( NODE ) ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODE_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwTotalBytesWritten += dwBytesWritten ;
		dwLinkOffset = dwNodeOffset + sizeof ( NODE ) + ( ( _tcslen ( ( TCHAR* ) ( pNode -> dwKey ) ) + 1 ) * sizeof ( TCHAR ) ) ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODE_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwTotalBytesWritten += dwBytesWritten ;
		if ( ! WriteFile ( hFile , ((BYTE*)pNode) + ( SIZE_OF_ONE_NODE_ELEMENT * 2 ) , SIZE_OF_ONE_NODE_ELEMENT * 3 , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwTotalBytesWritten += dwBytesWritten ;
		dwLinkOffset = pNode -> pParent ? pNode -> pParent -> dwHold : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODE_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwTotalBytesWritten += dwBytesWritten ;
		dwLinkOffset = ( _tcslen ( ( TCHAR* ) ( pNode -> dwKey ) ) + 1 ) * sizeof ( TCHAR ) ;
		if ( ! WriteFile ( hFile , (BYTE*) ( pNode -> dwKey ) , ( DWORD ) dwLinkOffset , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwTotalBytesWritten += dwBytesWritten ;
		dwLinkOffset = ( _tcslen ( ( TCHAR* ) ( pNode -> dwData ) ) + 1 ) * sizeof ( TCHAR ) ;
		if ( ! WriteFile ( hFile , (BYTE*) ( pNode -> dwData ) , ( DWORD ) dwLinkOffset , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwTotalBytesWritten += dwBytesWritten ;
		pNode -> dwHold = dwNodeOffset ;
		dwLinkOffset = 0 ;

		if ( pNode -> pLeft )
		{
			dwLinkOffset = dwNodeOffset + ( SIZE_OF_ONE_NODE_ELEMENT * 3 ) ;
			pNode = pNode -> pLeft ;
		}
		else if ( pNode -> pRight )
		{
			dwLinkOffset = dwNodeOffset + ( SIZE_OF_ONE_NODE_ELEMENT * 4 ) ;
			pNode = pNode -> pRight ;
		}
		else
		{
			while ( pNode )
			{
				if ( NULL == pNode -> pParent )
				{
					pNode = NULL ;
				}
				else if ( pNode == pNode -> pParent -> pRight )
				{
					pNode = pNode -> pParent ;
				}
				else if ( pNode -> pParent -> pRight )
				{
					dwLinkOffset = pNode -> pParent -> dwHold + ( SIZE_OF_ONE_NODE_ELEMENT * 4 ) ;
					pNode = pNode -> pParent -> pRight ;
					break ;
				}
				else
				{
					pNode = pNode -> pParent ;
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
		return ( false ) ;

	dwCurrentOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
	SetFilePointer ( hFile , dwTotalBytesOffset , 0 , FILE_BEGIN ) ;
	if ( ! WriteFile ( hFile , &dwTotalBytesWritten , sizeof ( dwTotalBytesWritten ) , &dwBytesWritten , 0 ) )
	{
		m_bSaveError = true ;
		return ( false ) ;
	}

	SetFilePointer ( hFile , dwCurrentOffset , 0 , FILE_BEGIN ) ;
	return ( true ) ;
}

bool CSSS :: Save ( LPCTSTR szFileName, bool bEncryptContents )
{
	DWORD dwKeySize = 0 ;
	DWORD dwCurrentOffset = 0 ;
	ULONG64 dwLinkOffset = 0 ;
	DWORD dwNodeOffset = 0 ;
	DWORD dwBytesWritten = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;

	if ( !MakeFullFilePath ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ , 0 , CREATE_ALWAYS ,
						 FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , sizeof ( HEADER_SSS ) + sizeof ( HEADER_SSS_DATA ) , 0 , FILE_BEGIN ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	m_bSaveError = false ;
	m_pTemp = m_pRoot ;

	while ( m_pTemp )
	{
		dwNodeOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
		dwLinkOffset = dwNodeOffset + sizeof ( NODE ) ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODE_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwKeySize = ( DWORD ) ( _tcslen ( ( TCHAR* ) m_pTemp -> dwKey ) + 1 ) * sizeof ( TCHAR ) ;
		dwLinkOffset = dwLinkOffset + dwKeySize + 4 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODE_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		if ( ! WriteFile ( hFile , ((BYTE*)m_pTemp) + ( SIZE_OF_ONE_NODE_ELEMENT * 2 ) , SIZE_OF_ONE_NODE_ELEMENT * 3 , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		dwLinkOffset = m_pTemp -> pParent ? m_pTemp -> pParent -> dwHold : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODE_ELEMENT , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		if ( ! WriteFile ( hFile , ( LPVOID ) m_pTemp -> dwKey , dwKeySize , &dwBytesWritten , 0 ) )
		{
			m_bSaveError = true ;
			break ;
		}

		DumpS2S ( hFile , m_pTemp -> dwData ) ;
		if ( m_bSaveError )
			break ;

		m_pTemp -> dwHold = dwNodeOffset ;
		dwLinkOffset = 0 ;

		if ( m_pTemp -> pLeft )
		{
			dwLinkOffset = dwNodeOffset + ( SIZE_OF_ONE_NODE_ELEMENT * 3 ) ;
			m_pTemp = m_pTemp -> pLeft ;
		}
		else if ( m_pTemp -> pRight )
		{
			dwLinkOffset = dwNodeOffset + ( SIZE_OF_ONE_NODE_ELEMENT * 4 ) ;
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
					dwLinkOffset = m_pTemp -> pParent -> dwHold + ( SIZE_OF_ONE_NODE_ELEMENT * 4 ) ;
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
		//AddLogEntry ( L"Error in saving: %s. File Deleted" , szFullFileName ) ;
		return ( false ) ;
	}

	if ( bEncryptContents && ! CryptFileData ( hFile , sizeof ( HEADER_SSS ) + sizeof ( HEADER_SSS_DATA ) ) )
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

	if ( ! WriteFile ( hFile , HEADER_SSS , sizeof ( HEADER_SSS ) , &dwBytesWritten , 0 ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	if ( ! CreateHeaderData ( hFile , szFullFileName , HEADER_SSS_DATA , sizeof ( HEADER_SSS_DATA ) ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	if ( ! WriteFile ( hFile , HEADER_SSS_DATA , sizeof ( HEADER_SSS_DATA ) , &dwBytesWritten , 0 ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFullFileName ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return ( true ) ;
}
