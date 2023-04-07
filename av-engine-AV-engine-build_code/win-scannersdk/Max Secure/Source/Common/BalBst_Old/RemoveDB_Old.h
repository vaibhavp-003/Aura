#pragma once
#include "BalBST_Old.h"
#pragma pack(1)
typedef struct _tagSystemObject_Old
{
	LONG						iIndex ;
	UINT64						u64DateTime ;
	DWORD						dwType ;
	ULONG64						ulptrHive ;
	DWORD						dwRegDataSize ;
	DWORD						dwReplaceRegDataSize ;
	WORD						wRegDataType ;
	BYTE						bDeleteThis ;
	DWORD						dwSpywareID ;

	union
	{
		LPTSTR					szKey ;
		ULONG64					KeyPad ;
	} ;

	union
	{
		LPTSTR					szValue ;
		ULONG64					ValuePad ;
	};

	union
	{
		LPBYTE					byData ;
		ULONG64					DataPad ;
	};

	union
	{
		LPBYTE					byReplaceData ;
		ULONG64					ReplaceDataPad ;
	};

	union
	{
		LPTSTR					szBackupFileName ;
		ULONG64					backupFileNamePad ;
	};

	union
	{
		struct _tagSystemObject_Old*	pNext ;
		ULONG64						NextPad ;
	};

} SYS_OBJ_Old , *PSYS_OBJ_Old ;
#pragma pack()

#define SIZE_OF_NON_POINTER_DATA_SYS_OBJ_Old	(sizeof(SYS_OBJ_Old)-(sizeof(ULONG64)*6))

class CRemoveDB_Old
{

public:

	CRemoveDB_Old () ;
	virtual ~CRemoveDB_Old () ;

	bool Add ( SYS_OBJ_Old& SystemObject ) ;
	bool Delete ( LONG iIndex ) ;
	bool GetFirst ( SYS_OBJ_Old& SystemObject ) ;
	bool GetNext ( SYS_OBJ_Old& SystemObject ) ;
	bool SetDeleteFlag ( LONG iIndex , bool bDeleteFlag ) ;
	bool DeleteAllMarkedEntries () ;
	bool Search ( SYS_OBJ_Old& SystemObject ) ;
	bool RemoveAll () ;
	bool Save ( LPCTSTR szFileName ) ;
	bool Load ( LPCTSTR szFileName ) ;
	UINT GetCount () ;

protected:

	PSYS_OBJ_Old	m_pHead ;
	PSYS_OBJ_Old	m_pCurr ;
	LPBYTE		m_byBuffer ;
	DWORD		m_nBufferSize ;

private:

	bool m_bTreeModified ;
	bool DeleteData ( PSYS_OBJ_Old& pNODEOLD ) ;
	LPVOID GetNODEOLD ( const SYS_OBJ_Old& SystemObject ) ;
};
