#pragma once
#include "BalBST_Old.h"

class CU2S_Old : public CBalBST_Old
{
public:

	CU2S_Old ( bool bIsEmbedded ) ;
	virtual ~CU2S_Old() ;

	bool AppendItemAscOrder ( DWORD dwKey , LPCTSTR szData ) ;
	bool AppendItem ( DWORD dwKey , LPCTSTR szData ) ;
	bool DeleteItem ( DWORD dwKey ) ;
	bool SearchItem ( DWORD dwKey , LPTSTR * ppszData ) ;
	bool Load ( LPCTSTR szFullFileName ) ;
	bool Save ( LPCTSTR szFullFileName, bool bEncryptContents = true ) ;
	bool GetKey ( PVOID pVPtr , DWORD& dwKey ) ;
	bool GetData ( PVOID pVPtr , LPTSTR& pStr ) ;
	bool AppendObject ( CBalBST_Old& objBBBSt ) 
	{
		return true;
	}
	bool DeleteObject ( CBalBST_Old& objBBBSt )
	{
		return true;
	}

private:

	virtual COMPARE_RESULTOLD Compare ( ULONG64 dwKey1 , ULONG64 dwKey2 ) ;
	virtual void FreeKey ( ULONG64 dwKey ) ;
	virtual void FreeData ( ULONG64 dwData ) ;
};
