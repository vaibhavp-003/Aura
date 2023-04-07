#pragma once

typedef enum { EQUALOLD , SMALLOLD , LARGEOLD } COMPARE_RESULTOLD ;

LPVOID Allocate_Old ( DWORD dwSize ) ;
void Release_Old ( LPVOID& pVPtr ) ;
LPBYTE DuplicateBuffer_Old ( LPBYTE pbyBuffer , DWORD nBufferSize ) ;
LPTSTR DuplicateString_Old ( LPCTSTR szString ) ;
LPSTR DuplicateString_OldA ( LPCSTR szString ) ;
bool MakeFullFilePath_Old ( LPCTSTR szFileName , LPTSTR szFullFileName , DWORD dwFullFileNameSize ) ;
void CryptBlock_Old ( DWORD * Data , DWORD dwDataSize ) ;
bool CryptBuffer_Old ( LPBYTE pbyBuffer , DWORD dwBufferSize ) ;
bool CryptFile_OldData_Old ( HANDLE hFile , DWORD dwStartOffset = 0 ) ;
bool CryptFile_Old ( LPCTSTR szFileName , const short iMAX_HEADER_SIZE = 24 ) ;

#define CHECK_AND_MAKE_POINTER(pointer,base,start,size)										\
do																							\
{																							\
	if ( (*(pointer)) )																		\
	{																						\
		(*(pointer)) += base ;																\
		if ( ((LPBYTE)(*(pointer))) < (start) || ((LPBYTE)(*(pointer))) >= ((start)+(size)))\
			goto ERROR_EXIT ;																\
	}																						\
	(pointer)++ ;																			\
}while(0);																					\

#pragma pack(1)
typedef struct _tagNODEOLD
{
/*	ULONG64			dwKey ;
	ULONG64			dwData ;
	ULONG64			dwHold ;
	struct _tagNODEOLD*	pLeft ;
	struct _tagNODEOLD*	pRight ;
	struct _tagNODEOLD*	pParent ;*/
	ULONG64				dwKey ;
	ULONG64				dwData ;
	ULONG64				dwHold ;
	union
	{
		struct _tagNODEOLD*	pLeft ;
		ULONG64				ulLeftPad ;
	} ;

	union
	{
		struct _tagNODEOLD*	pRight ;
		ULONG64				ulRightPad ;
	} ;

	union
	{
		struct _tagNODEOLD*	pParent ;
		ULONG64				ulParentPad ;
	};

} NODEOLD, *PNODEOLD ;
#pragma pack()

#define SIZE_OF_NODEOLD					sizeof(NODEOLD)
//#define SIZE_OF_ONE_NODEOLD_ELEMENT		sizeof(ULONG64)

#define SIZE_OF_ONE_NODEOLD_ELEMENT		sizeof(ULONG64)

class CBalBST_Old
{

public:

	CBalBST_Old ( bool	bIsEmbedded ) ;
	virtual ~CBalBST_Old() ;
	PNODEOLD GetDataPtr () ;
	bool SetDataPtr ( PNODEOLD pNODEOLD , LPBYTE pbyBuffer , DWORD nBufferSize ) ;
	LPVOID GetFirst () ;
	LPVOID GetNext ( LPVOID pPrev ) ;
	DWORD GetCount () ;

	virtual bool Balance () ;
	virtual bool RemoveAll () ;
	virtual bool Load ( LPCTSTR szFileName ) = 0;
	virtual bool Save ( LPCTSTR szFileName, bool bEncryptContents = true ) = 0;
	virtual bool AppendObject ( CBalBST_Old& objToAdd ) = 0 ;
	virtual bool DeleteObject ( CBalBST_Old& objToDel ) = 0 ;

protected:

	NODEOLD*				m_pRoot ;
	NODEOLD*				m_pTemp ;
	bool				m_bLoadedFromFile ;
	BYTE*				m_pBuffer ;
	DWORD				m_nBufferSize ;
	NODEOLD*				m_pLastSearchResult ;
	bool				m_bLoadError ;
	bool				m_bSaveError ;

	bool AddNODEOLD ( ULONG64 dwKey , ULONG64 dwData ) ;
	bool AddNODEOLDAscOrder ( ULONG64 dwKey , ULONG64 dwData ) ;
	bool DeleteNODEOLD ( ULONG64 dwKey ) ;
	bool FindNODEOLD ( ULONG64 dwKey , ULONG64& dwData ) ;
	inline void DestroyData() ;

private:

	NODEOLD*				m_pLinearTail ;
	bool				m_bTreeBalanced ;
	bool				m_bIsEmbedded ;
	DWORD				m_dwCount ;

	virtual COMPARE_RESULTOLD Compare ( ULONG64 dwKey1 , ULONG64 dwKey2 ) = 0 ;
	virtual void FreeKey ( ULONG64 dwKey ) = 0 ;
	virtual void FreeData ( ULONG64 dwData ) = 0 ;

	NODEOLD* GetNODEOLD ( ULONG64 dwKey , ULONG64 dwData ) ;
	void ConvertTreeToVine ( NODEOLD* pRoot , int &size ) ;
	void ConvertVineToTree ( NODEOLD* pRoot , int size ) ;
	void Compress ( NODEOLD* pRoot , int count ) ;
	int FullSize ( int size ) ;
	void AdjustParents ( NODEOLD * pRoot ) ;
};
