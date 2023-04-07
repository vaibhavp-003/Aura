#include "pch.h"
#include "RemoveDB_Old.h"

BYTE HEADER_REMDB_OLD [ 24 ] = { "MAXDBVERSION00.00.00.01" } ;

CRemoveDB_Old :: CRemoveDB_Old () : m_pHead ( 0 ) , m_byBuffer ( 0 ) , m_nBufferSize ( 0 ) , m_bTreeModified ( false )
{
}

CRemoveDB_Old :: ~CRemoveDB_Old ()
{
	RemoveAll () ;
}

LPVOID CRemoveDB_Old :: GetNODEOLD ( const SYS_OBJ_Old& SystemObject )
{
	PSYS_OBJ_Old pNODEOLD = NULL ;

	pNODEOLD = ( PSYS_OBJ_Old ) Allocate_Old ( sizeof ( SYS_OBJ_Old ) ) ;
	if ( NULL == pNODEOLD )
		return ( NULL ) ;

	pNODEOLD -> szKey					= NULL ;
	pNODEOLD -> szValue				= NULL ;
	pNODEOLD -> byData					= NULL ;
	pNODEOLD -> byReplaceData			= NULL ;
	pNODEOLD -> szBackupFileName		= NULL ;
	pNODEOLD -> iIndex					= SystemObject . iIndex ;
	pNODEOLD -> dwType					= SystemObject . dwType ;
	pNODEOLD -> ulptrHive 				= SystemObject . ulptrHive ;
	pNODEOLD -> dwSpywareID			= SystemObject . dwSpywareID ;
	pNODEOLD -> dwRegDataSize			= SystemObject . dwRegDataSize ;
	pNODEOLD -> dwReplaceRegDataSize	= SystemObject . dwReplaceRegDataSize ;
	pNODEOLD -> wRegDataType			= SystemObject . wRegDataType ;
	pNODEOLD -> bDeleteThis			= FALSE ;
	pNODEOLD -> u64DateTime			= SystemObject . u64DateTime ;

	if ( NULL != SystemObject . szKey )
	{
		pNODEOLD -> szKey = DuplicateString_Old ( SystemObject . szKey ) ;
		if ( NULL == pNODEOLD -> szKey )
		{
			Release_Old ( ( LPVOID& ) pNODEOLD ) ;
			return ( NULL ) ;
		}
	}

	if ( NULL != SystemObject . szValue )
	{
		pNODEOLD -> szValue = DuplicateString_Old ( SystemObject . szValue ) ;
		if ( NULL == pNODEOLD -> szValue )
		{
			Release_Old ( ( LPVOID& ) pNODEOLD -> szKey ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD ) ;
			return ( NULL ) ;
		}
	}

	if ( NULL != SystemObject . byData )
	{
		pNODEOLD -> byData = ( LPBYTE ) Allocate_Old ( SystemObject . dwRegDataSize ) ;
		if ( NULL == pNODEOLD -> byData )
		{
			Release_Old ( ( LPVOID& ) pNODEOLD -> szValue ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD -> szKey ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD ) ;
			return ( NULL ) ;
		}

		memcpy ( pNODEOLD -> byData , SystemObject . byData , SystemObject . dwRegDataSize ) ;
	}

	if ( NULL != SystemObject . szBackupFileName )
	{
		pNODEOLD -> szBackupFileName = DuplicateString_Old ( SystemObject . szBackupFileName ) ;
		if ( NULL == pNODEOLD -> szBackupFileName )
		{
			Release_Old ( ( LPVOID& ) pNODEOLD -> byData ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD -> szValue ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD -> szKey ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD ) ;
			return ( NULL ) ;
		}
	}

	if ( NULL != SystemObject . byReplaceData )
	{
		pNODEOLD -> byReplaceData = DuplicateBuffer_Old ( SystemObject . byReplaceData , SystemObject . dwReplaceRegDataSize ) ;
		if ( NULL == pNODEOLD -> byReplaceData )
		{
			Release_Old ( ( LPVOID& ) pNODEOLD -> szBackupFileName ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD -> byData ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD -> szValue ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD -> szKey ) ;
			Release_Old ( ( LPVOID& ) pNODEOLD ) ;
			return ( NULL ) ;
		}
	}

	return ( pNODEOLD ) ;
}

bool CRemoveDB_Old :: Add ( SYS_OBJ_Old& SystemObject )
{
	PSYS_OBJ_Old pNODEOLD = NULL ;

	SystemObject . iIndex = m_pHead ? m_pHead -> iIndex + 1 : 0 ;
	pNODEOLD = ( PSYS_OBJ_Old ) GetNODEOLD ( SystemObject ) ;
	if ( NULL == pNODEOLD )
		return ( false ) ;

	pNODEOLD -> pNext = m_pHead ;
	m_pHead = pNODEOLD ;

	m_bTreeModified = true ;

	return ( true ) ;
}

bool CRemoveDB_Old :: DeleteData ( PSYS_OBJ_Old& pNODEOLD )
{
	if ( pNODEOLD -> szKey )
	{
		if ( ( LPBYTE ) pNODEOLD -> szKey < m_byBuffer || ( LPBYTE ) pNODEOLD -> szKey >= m_byBuffer + m_nBufferSize )
			Release_Old ( ( LPVOID& ) pNODEOLD -> szKey ) ;
	}

	if ( pNODEOLD -> szValue )
	{
		if ( ( LPBYTE ) pNODEOLD -> szValue < m_byBuffer || ( LPBYTE ) pNODEOLD -> szValue >= m_byBuffer + m_nBufferSize )
			Release_Old ( ( LPVOID& ) pNODEOLD -> szValue ) ;
	}

	if ( pNODEOLD -> byData )
	{
		if ( pNODEOLD -> byData < m_byBuffer || pNODEOLD -> byData >= m_byBuffer + m_nBufferSize )
			Release_Old ( ( LPVOID& ) pNODEOLD -> byData ) ;
	}

	if ( pNODEOLD -> byReplaceData )
	{
		if ( pNODEOLD -> byReplaceData < m_byBuffer || pNODEOLD -> byReplaceData >= m_byBuffer + m_nBufferSize )
			Release_Old ( ( LPVOID& ) pNODEOLD -> byReplaceData ) ;
	}
	
	//Memory Leak Fix
	if ( pNODEOLD -> szBackupFileName )
	{
		if ( ( LPBYTE ) pNODEOLD -> szBackupFileName < m_byBuffer ||( LPBYTE )  pNODEOLD -> szBackupFileName >= m_byBuffer + m_nBufferSize )
			Release_Old ( ( LPVOID& ) pNODEOLD -> szBackupFileName ) ;
	}

	if ( ( LPBYTE ) pNODEOLD < m_byBuffer || ( LPBYTE ) pNODEOLD >= m_byBuffer + m_nBufferSize )
		Release_Old ( ( LPVOID& ) pNODEOLD ) ;

	m_bTreeModified = true ;

	return ( true ) ;
}

bool CRemoveDB_Old :: Delete ( LONG iIndex )
{
	PSYS_OBJ_Old pParent = 0 , pNODEOLD = m_pHead ;

	while ( pNODEOLD )
	{
		if ( pNODEOLD -> iIndex == iIndex )
		{
			if ( pNODEOLD == m_pHead )
			{
				m_pHead = m_pHead -> pNext ;
				DeleteData ( pNODEOLD ) ;
				pNODEOLD = m_pHead ;
			}
			else
			{
				pParent -> pNext = pNODEOLD -> pNext ;
				DeleteData ( pNODEOLD ) ;
				pNODEOLD = pParent -> pNext ;
			}

			break ;
		}
		else
		{
			pParent = pNODEOLD ;
			pNODEOLD = pNODEOLD -> pNext ;
		}
	}

	return ( true ) ;
}

bool CRemoveDB_Old :: GetFirst ( SYS_OBJ_Old& SystemObject )
{
	if ( NULL == m_pHead )
		return ( false ) ;

	m_pCurr = m_pHead ;
	SystemObject . bDeleteThis = m_pCurr -> bDeleteThis ;
	SystemObject . dwType = m_pCurr -> dwType ;
	SystemObject . ulptrHive = m_pCurr -> ulptrHive ;
	SystemObject . dwSpywareID = m_pCurr -> dwSpywareID ;
	SystemObject . szBackupFileName = m_pCurr -> szBackupFileName ;
	SystemObject . szKey = m_pCurr -> szKey ;
	SystemObject . szValue = m_pCurr -> szValue ;
	SystemObject . byReplaceData = m_pCurr -> byReplaceData ;
	SystemObject . dwReplaceRegDataSize = m_pCurr -> dwReplaceRegDataSize ;
	SystemObject . byData = m_pCurr -> byData ;
	SystemObject . dwRegDataSize = m_pCurr -> dwRegDataSize ;
	SystemObject . wRegDataType = m_pCurr -> wRegDataType ;
	SystemObject . u64DateTime = m_pCurr -> u64DateTime ;
	SystemObject . iIndex = m_pCurr -> iIndex ;
	return ( true ) ;
}

bool CRemoveDB_Old :: GetNext ( SYS_OBJ_Old& SystemObject )
{
	if ( NULL == m_pCurr -> pNext )
		return ( false ) ;

	m_pCurr = m_pCurr -> pNext ;
	SystemObject . bDeleteThis = m_pCurr -> bDeleteThis ;
	SystemObject . dwType = m_pCurr -> dwType ;
	SystemObject . ulptrHive = m_pCurr -> ulptrHive ;
	SystemObject . dwSpywareID = m_pCurr -> dwSpywareID ;
	SystemObject . szBackupFileName = m_pCurr -> szBackupFileName ;
	SystemObject . szKey = m_pCurr -> szKey ;
	SystemObject . szValue = m_pCurr -> szValue ;
	SystemObject . byReplaceData = m_pCurr -> byReplaceData ;
	SystemObject . dwReplaceRegDataSize = m_pCurr -> dwReplaceRegDataSize ;
	SystemObject . byData = m_pCurr -> byData ;
	SystemObject . dwRegDataSize = m_pCurr -> dwRegDataSize ;
	SystemObject . wRegDataType = m_pCurr -> wRegDataType ;
	SystemObject . u64DateTime = m_pCurr -> u64DateTime ;
	SystemObject . iIndex = m_pCurr -> iIndex ;
	return ( true ) ;
}

bool CRemoveDB_Old :: Search ( SYS_OBJ_Old& SystemObject )
{
	bool bFound = false ;

	for ( PSYS_OBJ_Old pNODEOLD = m_pHead ; pNODEOLD ; pNODEOLD = pNODEOLD -> pNext )
	{
		if ( pNODEOLD -> iIndex == SystemObject . iIndex )
		{
			SystemObject . bDeleteThis = pNODEOLD -> bDeleteThis ;
			SystemObject . dwType = pNODEOLD -> dwType ;
			SystemObject . ulptrHive = pNODEOLD -> ulptrHive ;
			SystemObject . dwSpywareID = pNODEOLD -> dwSpywareID ;
			SystemObject . szBackupFileName = pNODEOLD -> szBackupFileName ;
			SystemObject . szKey = pNODEOLD -> szKey ;
			SystemObject . szValue = pNODEOLD -> szValue ;
			SystemObject . byReplaceData = pNODEOLD -> byReplaceData ;
			SystemObject . dwReplaceRegDataSize = pNODEOLD -> dwReplaceRegDataSize ;
			SystemObject . byData = pNODEOLD -> byData ;
			SystemObject . dwRegDataSize = pNODEOLD -> dwRegDataSize ;
			SystemObject . wRegDataType = pNODEOLD -> wRegDataType ;
			SystemObject . u64DateTime = pNODEOLD -> u64DateTime ;
			bFound = true ;
			break ;
		}
	}

	return ( bFound ) ;
}

UINT CRemoveDB_Old :: GetCount ()
{
	UINT nCount = 0 ;
	
	for ( PSYS_OBJ_Old pNODEOLD = m_pHead ; pNODEOLD ; pNODEOLD = pNODEOLD -> pNext )
		nCount++ ;

	return ( nCount ) ;
}

bool CRemoveDB_Old :: SetDeleteFlag ( LONG iIndex , bool bDeleteFlag )
{
	bool bSuccess = false ;

	for ( PSYS_OBJ_Old pNODEOLD = m_pHead ; pNODEOLD ; pNODEOLD = pNODEOLD -> pNext )
	{
		if ( iIndex == pNODEOLD -> iIndex )
		{
			pNODEOLD -> bDeleteThis = bDeleteFlag ;
			bSuccess = true ;
			break ;
		}
	}

	return ( bSuccess ) ;
}

bool CRemoveDB_Old :: DeleteAllMarkedEntries ()
{
	PSYS_OBJ_Old pParent = 0 , pNODEOLD = m_pHead ;

	while ( pNODEOLD )
	{
		if ( TRUE == pNODEOLD -> bDeleteThis )
		{
			if ( pNODEOLD == m_pHead )
			{
				m_pHead = m_pHead -> pNext ;
				DeleteData ( pNODEOLD ) ;
				pNODEOLD = m_pHead ;
			}
			else
			{
				pParent -> pNext = pNODEOLD -> pNext ;
				DeleteData ( pNODEOLD ) ;
				pNODEOLD = pParent -> pNext ;
			}
		}
		else
		{
			pParent = pNODEOLD ;
			pNODEOLD = pNODEOLD -> pNext ;
		}
	}

	return ( true ) ;
}

bool CRemoveDB_Old :: RemoveAll ()
{
	PSYS_OBJ_Old pNODEOLD = 0 ;

	while ( m_pHead )
	{
		pNODEOLD = m_pHead -> pNext ;
		DeleteData ( m_pHead ) ;
		m_pHead = pNODEOLD ;
	}

	if ( m_byBuffer )
	{
		Release_Old ( ( LPVOID& ) m_byBuffer ) ;
		m_nBufferSize = 0 ;
	}

	m_pHead = NULL ;
	return ( true ) ;
}

bool CRemoveDB_Old :: Load ( LPCTSTR szFileName )
{
	ULONG64 * pCurrentPtr = 0 ;
	ULONG64 dwBaseAddress = 0 ;
	DWORD dwBytesProcessed = 0 ;
	DWORD dwFileSize = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	DWORD dwBytesRead = 0 ;
	TCHAR * pString = 0 ;
	BYTE VERSION_FROM_FILE [ sizeof ( HEADER_REMDB_OLD ) ] = { 0 } ;
	PSYS_OBJ_Old pNODEOLD = NULL ;
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

	if ( memcmp ( HEADER_REMDB_OLD , VERSION_FROM_FILE , sizeof ( VERSION_FROM_FILE ) ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	dwFileSize = GetFileSize ( hFile , 0 ) ;
	if ( dwFileSize <= sizeof ( HEADER_REMDB_OLD ) )
	{
		CloseHandle ( hFile ) ;
		return ( true ) ;
	}

	dwFileSize -= sizeof ( HEADER_REMDB_OLD ) ;
	m_byBuffer = ( LPBYTE ) Allocate_Old ( dwFileSize ) ;
	if ( NULL == m_byBuffer )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( FALSE == ReadFile ( hFile , m_byBuffer , dwFileSize , &dwBytesRead , 0 ) )
	{
		Release_Old ( ( LPVOID & ) m_byBuffer ) ;
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( dwFileSize != dwBytesRead )
	{
		Release_Old ( ( LPVOID & ) m_byBuffer ) ;
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	CryptBuffer_Old ( m_byBuffer , dwFileSize ) ;

	dwBaseAddress = ( ULONG64 ) ( m_byBuffer - sizeof ( VERSION_FROM_FILE ) )  ;
	m_pHead = pNODEOLD = ( PSYS_OBJ_Old ) m_byBuffer ;
	pCurrentPtr = ( ULONG64* ) m_pHead ;

	while ( dwBytesProcessed < dwFileSize )
	{
		pCurrentPtr = ( ULONG64* ) ( ( ( LPBYTE ) pCurrentPtr ) + SIZE_OF_NON_POINTER_DATA_SYS_OBJ_Old ) ;

		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_byBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_byBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_byBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_byBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_byBuffer , dwFileSize ) ;
		CHECK_AND_MAKE_POINTER ( pCurrentPtr , dwBaseAddress , m_byBuffer , dwFileSize ) ;

		dwBytesProcessed += sizeof ( SYS_OBJ_Old ) ;

		if ( pNODEOLD -> szKey )
		{
			pString = ( LPTSTR ) pCurrentPtr ;
			while ( *pString )
			{
				pString++ ;
				dwBytesProcessed += sizeof ( TCHAR ) ;
			}

			pString++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
			pCurrentPtr = ( ULONG64* ) pString ;
		}

		if ( pNODEOLD -> szValue )
		{
			pString = ( LPTSTR ) pCurrentPtr ;
			while ( *pString )
			{
				pString++ ;
				dwBytesProcessed += sizeof ( TCHAR ) ;
			}

			pString++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
			pCurrentPtr = ( ULONG64* ) pString ;
		}

		if ( pNODEOLD -> byData )
		{
			pCurrentPtr = ( ULONG64* ) ( ( ( LPBYTE ) pCurrentPtr ) + pNODEOLD -> dwRegDataSize ) ;
			dwBytesProcessed += pNODEOLD -> dwRegDataSize ;
		}

		if ( pNODEOLD -> byReplaceData )
		{
			pCurrentPtr = ( ULONG64* ) ( ( ( LPBYTE ) pCurrentPtr ) + pNODEOLD -> dwReplaceRegDataSize ) ;
			dwBytesProcessed += pNODEOLD -> dwReplaceRegDataSize ;
		}

		if ( pNODEOLD -> szBackupFileName )
		{
			pString = ( LPTSTR ) pCurrentPtr ;
			while ( *pString )
			{
				pString++ ;
				dwBytesProcessed += sizeof ( TCHAR ) ;
			}

			pString++ ;
			dwBytesProcessed += sizeof ( TCHAR ) ;
			pCurrentPtr = ( ULONG64* ) pString ;
		}

		pNODEOLD = pNODEOLD -> pNext ? pNODEOLD -> pNext : pNODEOLD ;
	}

	m_nBufferSize = dwFileSize ;
	return ( true ) ;

ERROR_EXIT:
	m_pHead = pNODEOLD = NULL ;
	Release_Old ( ( LPVOID& ) m_byBuffer ) ;
	m_nBufferSize = dwFileSize = 0 ;
	DeleteFile ( szFullFileName ) ;
	AddLogEntry ( L"Error in loading: %s. File Deleted" , szFullFileName ) ;
	return ( false ) ;
}

bool CRemoveDB_Old :: Save ( LPCTSTR szFileName )
{
	DWORD dwGlobalIndex = 0 ;
	DWORD dwKeySize = 0 ;
	DWORD dwValueSize = 0 ;
	DWORD dwDataSize = 0 ;
	DWORD dwReplaceDataSize = 0 ;
	DWORD dwBackupFileNameSize = 0 ;
	ULONG64 dwLinkOffset = 0 ;
	DWORD dwNODEOLDOffset = 0 ;
	DWORD dwBytesWritten = 0 ;
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;
	bool bSaveError = false ;

	DeleteAllMarkedEntries() ;

	if ( !m_bTreeModified )
		return true ;

	if ( !MakeFullFilePath_Old ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ , 0 , CREATE_ALWAYS ,
						 FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , sizeof ( HEADER_REMDB_OLD ) , 0 , FILE_BEGIN ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFileName ) ;
		return ( false ) ;
	}

	dwGlobalIndex = GetCount() ;

	for ( PSYS_OBJ_Old pNODEOLD = m_pHead ; pNODEOLD ; pNODEOLD = pNODEOLD -> pNext )
	{
		pNODEOLD -> iIndex = --dwGlobalIndex ;
		dwKeySize = pNODEOLD -> szKey ? ( DWORD ) ( _tcslen ( pNODEOLD -> szKey ) + 1 ) * sizeof ( TCHAR ) : 0 ;
		dwValueSize = pNODEOLD -> szValue ? ( DWORD ) ( _tcslen ( pNODEOLD -> szValue ) + 1 ) * sizeof ( TCHAR ) : 0 ;
		dwDataSize = pNODEOLD -> byData ? pNODEOLD -> dwRegDataSize : 0 ;
		dwReplaceDataSize = pNODEOLD -> byReplaceData ? pNODEOLD -> dwReplaceRegDataSize : 0 ;
		dwBackupFileNameSize = pNODEOLD -> szBackupFileName ? ( DWORD ) ( _tcslen ( pNODEOLD -> szBackupFileName ) + 1 ) * sizeof ( TCHAR ) : 0 ;

		dwNODEOLDOffset = SetFilePointer ( hFile , 0 , 0 , FILE_CURRENT ) ;
		if ( ! WriteFile ( hFile , ( ( LPBYTE ) pNODEOLD ) , SIZE_OF_NON_POINTER_DATA_SYS_OBJ_Old , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		dwLinkOffset = pNODEOLD -> szKey ? dwNODEOLDOffset + sizeof ( SYS_OBJ_Old ) : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		dwLinkOffset = pNODEOLD -> szValue ? dwNODEOLDOffset + sizeof ( SYS_OBJ_Old ) + dwKeySize : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		dwLinkOffset = pNODEOLD -> byData ? dwNODEOLDOffset + sizeof ( SYS_OBJ_Old ) + dwKeySize + dwValueSize : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		dwLinkOffset = pNODEOLD -> byReplaceData ? dwNODEOLDOffset + sizeof ( SYS_OBJ_Old ) + dwKeySize + dwValueSize + dwDataSize : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		dwLinkOffset = pNODEOLD -> szBackupFileName ? dwNODEOLDOffset + sizeof ( SYS_OBJ_Old ) + dwKeySize + dwValueSize + dwDataSize + dwReplaceDataSize : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		dwLinkOffset = pNODEOLD -> pNext ? dwNODEOLDOffset + sizeof ( SYS_OBJ_Old ) + dwKeySize + dwValueSize + dwDataSize + dwReplaceDataSize + dwBackupFileNameSize : 0 ;
		if ( ! WriteFile ( hFile , &dwLinkOffset , SIZE_OF_ONE_NODEOLD_ELEMENT , &dwBytesWritten , 0 ) )
		{
			bSaveError = true ;
			break ;
		}

		if ( dwKeySize ) WriteFile ( hFile , pNODEOLD -> szKey , dwKeySize , &dwBytesWritten , 0 ) ;
		if ( dwValueSize ) WriteFile ( hFile , pNODEOLD -> szValue , dwValueSize , &dwBytesWritten , 0 ) ;
		if ( dwDataSize ) WriteFile ( hFile , pNODEOLD -> byData , dwDataSize , &dwBytesWritten , 0 ) ;
		if ( dwReplaceDataSize ) WriteFile ( hFile , pNODEOLD -> byReplaceData , dwReplaceDataSize , &dwBytesWritten , 0 ) ;
		if ( dwBackupFileNameSize ) WriteFile ( hFile , pNODEOLD -> szBackupFileName , dwBackupFileNameSize , &dwBytesWritten , 0 ) ;
	}

	if ( bSaveError )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFileName ) ;
		AddLogEntry ( L"Error in saving: %s. File Deleted" , szFileName ) ;
		return ( false ) ;
	}

	if ( ! CryptFile_OldData_Old ( hFile , sizeof ( HEADER_REMDB_OLD ) ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFileName ) ;
		return ( false ) ;
	}

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , 0 , 0 , FILE_BEGIN ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFileName ) ;
		return ( false ) ;
	}

	if ( ! WriteFile ( hFile , HEADER_REMDB_OLD , sizeof ( HEADER_REMDB_OLD ) , &dwBytesWritten , 0 ) )
	{
		CloseHandle ( hFile ) ;
		DeleteFile ( szFileName ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return ( true ) ;
}