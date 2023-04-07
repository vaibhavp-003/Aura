#include "pch.h"
#include "BalBST_Old.h"

#define SWAP(x,y)		((x)!=(y)?((x)^=(y)^=(x)^=(y)):0)

CBalBST_Old :: CBalBST_Old ( bool bIsEmbedded ) : m_bIsEmbedded ( bIsEmbedded )
{
	DestroyData();
}

CBalBST_Old :: ~CBalBST_Old()
{
}

void CBalBST_Old :: DestroyData()
{
	m_pRoot = m_pTemp = m_pLastSearchResult = m_pLinearTail = NULL ;
	m_bLoadedFromFile = m_bTreeBalanced = false ;
	m_pBuffer = NULL ;
	m_nBufferSize = 0 ;
	m_dwCount = 0 ;
}

NODEOLD* CBalBST_Old :: GetNODEOLD ( ULONG64 dwKey , ULONG64 dwData )
{
	NODEOLD* pTemp = (NODEOLD*) Allocate_Old ( sizeof NODEOLD ) ;
	if ( NULL == pTemp ) return ( pTemp ) ;
	pTemp -> dwHold = 0 ;
	pTemp -> dwData = dwData ;
	pTemp -> dwKey = dwKey ;
	pTemp -> pLeft = pTemp -> pParent = pTemp -> pRight = NULL ;
	return ( pTemp ) ;
}

bool CBalBST_Old :: AddNODEOLD ( ULONG64 dwKey , ULONG64 dwData )
{
	bool bSuccess = true ;

	m_bTreeBalanced = false ;

	if ( NULL == m_pRoot )
	{
		m_pRoot = GetNODEOLD ( dwKey , dwData ) ;
		if ( NULL == m_pRoot )
			bSuccess = false ;
	}
	else
	{
		COMPARE_RESULTOLD CompResult = EQUALOLD ;
		m_pTemp = m_pRoot ;

		while ( m_pTemp )
		{
			CompResult = Compare ( m_pTemp -> dwKey , dwKey ) ;

			if ( CompResult == LARGEOLD )
			{
				if ( NULL == m_pTemp -> pLeft )
				{
					m_pTemp -> pLeft = GetNODEOLD ( dwKey , dwData ) ;
					if ( NULL == m_pTemp -> pLeft )
						bSuccess = false ;
					else
						m_pTemp -> pLeft -> pParent = m_pTemp ;

					break ;
				}
				else
				{
					m_pTemp = m_pTemp -> pLeft ;
				}
			}
			else if ( CompResult == SMALLOLD )
			{
				if ( NULL == m_pTemp -> pRight )
				{
					m_pTemp -> pRight = GetNODEOLD ( dwKey , dwData ) ;
					if ( NULL == m_pTemp -> pRight )
						bSuccess = false ;
					else
						m_pTemp -> pRight -> pParent = m_pTemp ;

					break ;
				}
				else
				{
					m_pTemp = m_pTemp -> pRight ;
				}
			}
			else
			{
				bSuccess = false ;
				break ;
			}
		}
	}

	if ( bSuccess ) m_dwCount++ ;
	return ( bSuccess ) ;
}

bool CBalBST_Old :: AddNODEOLDAscOrder ( ULONG64 dwKey , ULONG64 dwData )
{
	bool bSuccess = true ;

	m_bTreeBalanced = false ;

	if ( NULL == m_pRoot )
	{
		m_pRoot = GetNODEOLD ( dwKey , dwData ) ;
		if ( NULL == m_pRoot )
			bSuccess = false ;
		else
			m_pLinearTail = m_pRoot ;
	}
	else
	{
		m_pLinearTail -> pRight = GetNODEOLD ( dwKey , dwData ) ;
		if ( NULL == m_pLinearTail -> pRight )
		{
			bSuccess = false ;
		}
		else
		{
			m_pLinearTail -> pRight -> pParent = m_pLinearTail ;
			m_pLinearTail = m_pLinearTail -> pRight ;
		}
	}

	if ( bSuccess ) m_dwCount++ ;
	return ( bSuccess ) ;
}

bool CBalBST_Old :: DeleteNODEOLD ( ULONG64 dwKey )
{
	NODEOLD PseudoRoot = { 0 } ;
	PNODEOLD pNODEOLDToReplaceWith = 0 ;
	PNODEOLD pNODEOLDToDelete = 0 ;
	ULONG64 dwData = 0 ;

	m_bTreeBalanced = false ;
	if ( ( NULL == m_pLastSearchResult ) || ( m_pLastSearchResult -> dwKey != dwKey ) )
	{
		if ( ! FindNODEOLD ( dwKey , dwData ) )
			return ( false ) ;
	}

	pNODEOLDToDelete = m_pLastSearchResult ;

	PseudoRoot . pRight = m_pRoot ;
	m_pRoot -> pParent = &PseudoRoot ;

	if ( pNODEOLDToDelete -> pLeft && pNODEOLDToDelete -> pRight )
	{
		pNODEOLDToReplaceWith = pNODEOLDToDelete -> pLeft ;
		while ( pNODEOLDToReplaceWith -> pRight )
			pNODEOLDToReplaceWith = pNODEOLDToReplaceWith -> pRight ;

		if ( pNODEOLDToReplaceWith -> pLeft )
			pNODEOLDToReplaceWith -> pLeft -> pParent = pNODEOLDToReplaceWith -> pParent ;

		if ( pNODEOLDToReplaceWith -> pParent -> pLeft == pNODEOLDToReplaceWith )
			pNODEOLDToReplaceWith -> pParent -> pLeft = pNODEOLDToReplaceWith -> pLeft ;
		else
			pNODEOLDToReplaceWith -> pParent -> pRight = pNODEOLDToReplaceWith -> pLeft ;

		pNODEOLDToReplaceWith -> pLeft = pNODEOLDToDelete -> pLeft ;
		pNODEOLDToReplaceWith -> pRight = pNODEOLDToDelete -> pRight ;
		if ( pNODEOLDToReplaceWith -> pLeft ) pNODEOLDToReplaceWith -> pLeft -> pParent = pNODEOLDToReplaceWith ;
		if ( pNODEOLDToReplaceWith -> pRight ) pNODEOLDToReplaceWith -> pRight -> pParent = pNODEOLDToReplaceWith ;
		pNODEOLDToReplaceWith -> pParent = pNODEOLDToDelete -> pParent ;

		if ( pNODEOLDToDelete -> pParent -> pLeft == pNODEOLDToDelete )
			pNODEOLDToDelete -> pParent -> pLeft = pNODEOLDToReplaceWith ;
		else
			pNODEOLDToDelete -> pParent -> pRight = pNODEOLDToReplaceWith ;
	}
	else if ( pNODEOLDToDelete -> pRight )
	{
		pNODEOLDToDelete -> pRight -> pParent = pNODEOLDToDelete -> pParent ;
		if ( pNODEOLDToDelete -> pParent -> pLeft == pNODEOLDToDelete )
			pNODEOLDToDelete -> pParent -> pLeft = pNODEOLDToDelete -> pRight ;
		else
			pNODEOLDToDelete -> pParent -> pRight = pNODEOLDToDelete -> pRight ;
	}
	else if ( pNODEOLDToDelete -> pLeft )
	{
		pNODEOLDToDelete -> pLeft -> pParent = pNODEOLDToDelete -> pParent ;
		if ( pNODEOLDToDelete -> pParent -> pLeft == pNODEOLDToDelete )
			pNODEOLDToDelete -> pParent -> pLeft = pNODEOLDToDelete -> pLeft ;
		else
			pNODEOLDToDelete -> pParent -> pRight = pNODEOLDToDelete -> pLeft ;
	}
	else
	{
		if ( pNODEOLDToDelete -> pParent -> pLeft == pNODEOLDToDelete )
			pNODEOLDToDelete -> pParent -> pLeft = NULL ;
		else
			pNODEOLDToDelete -> pParent -> pRight = NULL ;
	}

	m_pRoot = PseudoRoot . pRight ;
	if ( m_pRoot ) m_pRoot -> pParent = NULL ;

	FreeData ( pNODEOLDToDelete -> dwData ) ;
	FreeKey ( pNODEOLDToDelete -> dwKey ) ;

	if ( ( ( LPBYTE ) pNODEOLDToDelete < m_pBuffer ) || ( ( LPBYTE ) pNODEOLDToDelete >= m_pBuffer + m_nBufferSize ) )
		Release_Old ( ( LPVOID& ) pNODEOLDToDelete ) ;

	m_dwCount-- ;
	m_pLastSearchResult = NULL ;
	return ( true ) ;
}

bool CBalBST_Old :: RemoveAll ()
{
	DWORD dwCount = 0 ;
	NODEOLD* pHold = NULL ;

	if ( m_bIsEmbedded )
	{
		DestroyData() ;
		return ( true ) ;
	}

	m_bTreeBalanced = false ;
	m_pTemp = m_pRoot ;

	while ( m_pTemp )
	{
		if ( m_pTemp -> pLeft )
		{
			m_pTemp = m_pTemp -> pLeft ;
		}
		else if ( m_pTemp -> pRight )
		{
			m_pTemp = m_pTemp -> pRight ;
		}
		else
		{
			if ( m_pTemp -> pParent )
			{
				if ( m_pTemp == m_pTemp -> pParent -> pLeft )
					m_pTemp -> pParent -> pLeft = NULL ;
				else
					m_pTemp -> pParent -> pRight = NULL ;
			}

			FreeKey ( m_pTemp -> dwKey ) ;
			FreeData ( m_pTemp -> dwData ) ;
			pHold = m_pTemp -> pParent ;

			if ( ( ( LPBYTE ) m_pTemp < m_pBuffer ) || ( ( LPBYTE ) m_pTemp >= m_pBuffer + m_nBufferSize ) )
				Release_Old ( ( LPVOID & ) m_pTemp ) ;

			m_pTemp = pHold ;
		}
	}

	if ( m_bLoadedFromFile )
		Release_Old ( ( LPVOID& ) m_pBuffer ) ;

	DestroyData() ;
	return ( true ) ;
}

DWORD CBalBST_Old :: GetCount()
{
	if ( m_dwCount ) return m_dwCount ;

	for ( m_pTemp = m_pRoot ; m_pTemp != NULL ; )
	{
		m_dwCount++ ;

		if ( m_pTemp -> pLeft )
		{
			m_pTemp = m_pTemp -> pLeft ;
		}
		else if ( m_pTemp -> pRight )
		{
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
					m_pTemp = m_pTemp -> pParent -> pRight ;
					break ;
				}
				else
				{
					m_pTemp = m_pTemp -> pParent ;
				}
			}
		}
	}

	return ( m_dwCount ) ;
}

LPVOID CBalBST_Old :: GetFirst()
{
	return ( m_pRoot ) ;
}

LPVOID CBalBST_Old :: GetNext ( LPVOID pPrev )
{
	NODEOLD * pNODEOLD = (NODEOLD*) pPrev ;

	if ( pNODEOLD -> pLeft )
	{
		pNODEOLD = pNODEOLD -> pLeft ;
	}
	else if ( pNODEOLD -> pRight )
	{
		pNODEOLD = pNODEOLD -> pRight ;
	}
	else
	{
		while ( pNODEOLD )
		{
			if ( NULL == pNODEOLD -> pParent )
			{
				pNODEOLD = NULL ;
			}
			else if ( pNODEOLD == pNODEOLD -> pParent -> pRight )
			{
				pNODEOLD = pNODEOLD -> pParent ;
			}
			else if ( pNODEOLD -> pParent -> pRight )
			{
				pNODEOLD = pNODEOLD -> pParent -> pRight ;
				break ;
			}
			else
			{
				pNODEOLD = pNODEOLD -> pParent ;
			}
		}
	}

	return ( pNODEOLD ) ;
}

int CBalBST_Old :: FullSize ( int size )
{
	int Rtn = 1 ;
	while ( Rtn <= size ) Rtn = Rtn + Rtn + 1 ;
	return Rtn / 2 ;
}

void CBalBST_Old :: Compress ( NODEOLD* pRoot , int count )
{
	NODEOLD* scanner = pRoot ;

	for ( int j = 0 ; j < count ; j++ )
	{
		NODEOLD* child = scanner -> pRight ;
		scanner -> pRight = child -> pRight ;
		scanner = scanner -> pRight ;
		child -> pRight = scanner -> pLeft ;
		scanner -> pLeft = child ;
	}
}

void CBalBST_Old :: ConvertVineToTree ( NODEOLD* pRoot , int size )
{
	int full_count = FullSize ( size ) ;
	Compress ( pRoot , size - full_count ) ;
	for ( size = full_count ; size > 1 ; size /= 2 )
		Compress ( pRoot , size / 2 ) ;
}

void CBalBST_Old :: ConvertTreeToVine ( NODEOLD* pRoot , int &size )
{
	NODEOLD* vineTail = 0 ;
	NODEOLD* remainder = 0 ;
	NODEOLD* tempPtr = 0 ;

	vineTail = pRoot;
	remainder = vineTail -> pRight ;
	size = 0 ;

	while ( remainder != NULL )
	{
		if ( remainder -> pLeft == NULL )
		{
			vineTail = remainder ;
			remainder = remainder -> pRight ;
			size++ ;
		}
		else
		{
			tempPtr = remainder -> pLeft ;
			remainder -> pLeft = tempPtr -> pRight ;
			tempPtr -> pRight = remainder ;
			remainder = tempPtr ;
			vineTail -> pRight = tempPtr ;
		}
	}
}

void CBalBST_Old :: AdjustParents ( NODEOLD * pRoot )
{
	m_pTemp = pRoot ;
	while ( m_pTemp )
	{
		if ( m_pTemp -> pLeft )
		{
			m_pTemp -> pLeft -> pParent = m_pTemp ;
			m_pTemp = m_pTemp -> pLeft ;
		}
		else if ( m_pTemp -> pRight )
		{
			m_pTemp -> pRight -> pParent = m_pTemp ;
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
					m_pTemp -> pParent -> pRight -> pParent = m_pTemp -> pParent ;
					m_pTemp = m_pTemp -> pParent -> pRight ;
					break ;
				}
				else
				{
					m_pTemp = m_pTemp -> pParent ;
				}
			}
		}
	}
}

bool CBalBST_Old :: Balance()
{
	int iCount = 0 ;
	NODEOLD Pseudo_Root = { 0 , 0 , 0 , 0 , m_pRoot , 0 } ;

	ConvertTreeToVine ( &Pseudo_Root , iCount ) ;
	ConvertVineToTree ( &Pseudo_Root , iCount ) ;
	m_pRoot = Pseudo_Root . pRight ;
	if ( m_pRoot ) m_pRoot -> pParent = NULL ;
	AdjustParents ( m_pRoot ) ;
	m_bTreeBalanced = true ;
	return ( true ) ;
}

bool CBalBST_Old :: FindNODEOLD ( ULONG64 dwKey , ULONG64& dwData )
{
	bool bFound = false ;
	COMPARE_RESULTOLD CompResult = EQUALOLD ;

	m_pLastSearchResult = NULL ;
	m_pTemp = m_pRoot ;
	while ( m_pTemp )
	{
		CompResult = Compare ( dwKey , m_pTemp -> dwKey ) ;
		if ( SMALLOLD == CompResult )
		{
			m_pTemp = m_pTemp -> pLeft ;
		}
		else if ( LARGEOLD == CompResult )
		{
			m_pTemp = m_pTemp -> pRight ;
		}
		else
		{
			m_pLastSearchResult = m_pTemp ;
			dwData = m_pTemp -> dwData ;
			bFound = true ;
			break ;
		}
	}

	return ( bFound ) ;
}

PNODEOLD CBalBST_Old :: GetDataPtr ()
{
	return ( m_pRoot ) ;
}

bool CBalBST_Old :: SetDataPtr ( PNODEOLD pNODEOLD , LPBYTE pbyBuffer , DWORD nBufferSize )
{
	m_pRoot = pNODEOLD ;
	m_pBuffer = pbyBuffer ;
	m_nBufferSize = nBufferSize ;
	return ( true ) ;
}

LPVOID Allocate_Old ( DWORD dwSize )
{
	return ( HeapAlloc ( GetProcessHeap() , HEAP_ZERO_MEMORY , dwSize ) ) ;
}

void Release_Old ( LPVOID& pVPtr )
{
	HeapFree ( GetProcessHeap() , 0 , pVPtr ) ;
	pVPtr = NULL ;
}

LPBYTE DuplicateBuffer_Old ( LPBYTE pbyBuffer , DWORD nBufferSize )
{
	LPBYTE pHold = NULL ;

	if ( NULL == pbyBuffer )
		return ( NULL ) ;

	pHold = ( LPBYTE ) Allocate_Old ( nBufferSize ) ;
	if ( NULL == pHold )
		return ( NULL ) ;

	memcpy ( pHold , pbyBuffer , nBufferSize ) ;
	return ( pHold ) ;
}

LPTSTR DuplicateString_Old ( LPCTSTR szString )
{
	DWORD iStrSize = 0 ;
	LPTSTR szNewString = NULL ;

	if ( NULL == szString )
		return ( NULL ) ;

	iStrSize = ( DWORD ) _tcslen ( szString ) + 1 ;
	szNewString = ( LPTSTR ) Allocate_Old ( iStrSize * sizeof ( TCHAR ) ) ;
	if ( NULL == szNewString )
		return ( NULL ) ;

	_tcscpy_s ( szNewString , iStrSize , szString ) ;
	return ( szNewString ) ;
}

LPSTR DuplicateString_OldA ( LPCSTR szString )
{
	DWORD iStrSize = 0 ;
	LPSTR szNewString = NULL ;

	if ( NULL == szString )
		return ( NULL ) ;

	iStrSize = ( DWORD ) strlen ( szString ) + 1 ;
	szNewString = ( LPSTR ) Allocate_Old ( iStrSize ) ;
	if ( NULL == szNewString )
		return ( NULL ) ;

	strcpy_s ( szNewString , iStrSize , szString ) ;
	return ( szNewString ) ;
}

bool MakeFullFilePath_Old ( LPCTSTR szFileName , LPTSTR szFullFileName , DWORD dwFullFileNameSize )
{
	if ( NULL == szFileName )
		return ( false ) ;

	UINT iFileNameLen = 0 ;
	LPCTSTR szPtr = szFileName ;
	
	while ( *szPtr && *szPtr != _T('\\') ) szPtr++ ;

	if ( *szPtr )
	{
		while ( *szPtr ) szPtr++ ;
		iFileNameLen = ( UINT ) ( szPtr - szFileName ) ;

		if ( iFileNameLen >= dwFullFileNameSize )
			return ( false ) ;

		_tcscpy_s ( szFullFileName , dwFullFileNameSize , szFileName ) ;
	}
	else
	{
		TCHAR szPath [ MAX_PATH ] = { 0 } ;

		iFileNameLen = ( UINT ) ( szPtr - szFileName ) ;
		if ( 0 == iFileNameLen )
			return ( false ) ;

		if ( 0 == GetModuleFileName ( NULL , szPath , _countof ( szPath ) ) )
			return ( false ) ;

		if ( _tcsrchr ( szPath , _T('\\') ) )
			*_tcsrchr ( szPath , _T('\\') ) = 0 ;

		if ( iFileNameLen + _tcslen ( szPath ) + 6 >= dwFullFileNameSize )
			return ( false ) ;

		_tcscpy_s ( szFullFileName , dwFullFileNameSize , szPath ) ;
		_tcscat_s ( szFullFileName , dwFullFileNameSize , _T ( "\\Data\\" ) ) ;
		_tcscat_s ( szFullFileName , dwFullFileNameSize , szFileName ) ;
	}

	return ( true ) ;
}

void CryptBlock_Old ( DWORD * Data , DWORD dwDataSize )
{
	const unsigned short MAX_BOX_ITEMS = 0x100 ;
	DWORD Sbox1 [ MAX_BOX_ITEMS ] = { 0 } ;
	DWORD Sbox2 [ MAX_BOX_ITEMS ] = { 0 } ;
    DWORD i = 0 , j = 0 , x = 0 , temp = 0 ;
	static const DWORD OurUnSecuredKey[] = { 0xFFAAFFAA , 0xAAFCAAFC , 0xA37EA37E , 0xB34EB34E ,
											 0xFFFFFFFF , 0x3BE73BE7 , 0xCBA9CBA9 , 0x23C123C1 ,
											 0x2E6C2E6C , 0x13CB13CB , 0x64E764E7 , 0x34D234D2 ,
											 0xFF6C2E6C , 0x13FF13CB , 0x64E7FFE7 , 0x34D234FF } ;

	// initialize Sbox1 with defined numbers
	for ( i = 0 ; i < _countof ( Sbox1 ) ; i++ )
        Sbox1 [ i ] = 0xFFFFFFFF / ( i + 1 ) ;

	// initialize Sbox2 with our key
    for ( i = 0 ; i < _countof ( Sbox2 ) ; i++ )
        Sbox2 [ i ] = OurUnSecuredKey [ i % _countof ( OurUnSecuredKey ) ] ;

	// scramble Sbox1 by Sbox2
    for ( i = 0 ; i < _countof ( Sbox1 ) ; i++ )
    {
        j = ( j + Sbox1 [ i ] + Sbox2 [ i ] ) % _countof ( Sbox1 ) ;

		if ( Sbox1 [ i ] != Sbox1 [ j ] )
		{
			Sbox1 [ i ] = Sbox1 [ i ] ^ Sbox1 [ j ] ;
			Sbox1 [ j ] = Sbox1 [ i ] ^ Sbox1 [ j ] ;
			Sbox1 [ i ] = Sbox1 [ i ] ^ Sbox1 [ j ] ;
		}
    }

    for ( i = j = x = 0 ; x < dwDataSize ; x++ )
    {
        //increment i
        i = ( i + 1U ) % _countof ( Sbox1 ) ;

        //increment j
        j = ( j + Sbox1 [ i ] ) % _countof ( Sbox1 ) ;

        //Scramble Sbox1 further so encryption routine will
        //will repeat itself at great interval
		if ( Sbox1 [ i ] != Sbox1 [ j ] )
		{
			Sbox1 [ i ] = Sbox1 [ i ] ^ Sbox1 [ j ] ;
			Sbox1 [ j ] = Sbox1 [ i ] ^ Sbox1 [ j ] ;
			Sbox1 [ i ] = Sbox1 [ i ] ^ Sbox1 [ j ] ;
		}

        //Get ready to create pseudo random  byte for encryption key
        temp = ( Sbox1 [ i ] + Sbox1 [ j ] ) %  _countof ( Sbox1 ) ;

        //get the random byte
        temp = Sbox1 [ temp ] ;

        //xor with the data and done
        Data [ x ] = Data [ x ] ^ temp ;
    }

	return ;
}

bool CryptBuffer_Old ( LPBYTE pbyBuffer , DWORD dwBufferSize )
{
	DWORD dwBlockData = 0 ;
	DWORD dwRemainingData = 0 ;

	dwRemainingData = dwBufferSize % 4 ;
	dwBlockData = dwBufferSize - dwRemainingData ;

	CryptBlock_Old ( ( LPDWORD ) pbyBuffer , dwBlockData / 4 ) ;
	for ( DWORD dwIndex = 0 ; dwIndex < dwRemainingData ; dwIndex++ )
		pbyBuffer [ dwBlockData + dwIndex ] ^= 141 ;

	return ( true ) ;
}

bool CryptFile_OldData_Old ( HANDLE hFile , DWORD dwStartOffset )
{
	LPBYTE pbyBuffer = 0 ;
	DWORD dwBufferSize = 0 , dwBytesRead = 0 ;

	dwBufferSize = GetFileSize ( hFile , 0 ) ;
	if ( dwStartOffset >= dwBufferSize )
		return ( false ) ;

	dwBufferSize -= dwStartOffset ;
	pbyBuffer = ( LPBYTE ) Allocate_Old ( dwBufferSize ) ;
	if ( NULL == pbyBuffer )
		return ( false ) ;

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , dwStartOffset , 0 , FILE_BEGIN ) )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	if ( ! ReadFile ( hFile , pbyBuffer , dwBufferSize , &dwBytesRead , 0 ) )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	if ( dwBufferSize != dwBytesRead )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	if ( ! CryptBuffer_Old ( pbyBuffer , dwBufferSize ) )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	if ( INVALID_SET_FILE_POINTER == SetFilePointer ( hFile , dwStartOffset , 0 , FILE_BEGIN ) )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	if ( ! WriteFile ( hFile , pbyBuffer , dwBufferSize , &dwBytesRead , 0 ) )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	if ( dwBufferSize != dwBytesRead )
	{
		Release_Old ( ( LPVOID& ) pbyBuffer ) ;
		return ( false ) ;
	}

	Release_Old ( ( LPVOID& ) pbyBuffer) ;
	return ( true ) ;
}

bool CryptFile_Old ( LPCTSTR szFileName , const short iMAX_HEADER_SIZE )
{
	HANDLE hFile = INVALID_HANDLE_VALUE ;
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;

	if ( ! MakeFullFilePath_Old ( szFileName , szFullFileName , _countof ( szFullFileName ) ) )
		return ( false ) ;

	hFile = CreateFile ( szFullFileName , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ , 0 , OPEN_EXISTING ,
						 FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( ! CryptFile_OldData_Old ( hFile , iMAX_HEADER_SIZE ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return ( true ) ;
}
