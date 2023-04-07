#pragma once
#include "BalBST_Old.h"

class CS2U_Old : public CBalBST_Old
{
public:

	CS2U_Old ( bool bIsEmbedded ) ;
	virtual ~CS2U_Old() ;

	bool AppendItemAscOrder ( LPCTSTR szKey , DWORD dwData ) ;
	bool AppendItem ( LPCTSTR szKey , DWORD dwData ) ;
	bool DeleteItem ( LPCTSTR szKey ) ;
	bool SearchItem ( LPCTSTR szKey , DWORD * pulData ) ;
	bool Load ( LPCTSTR szFullFileName ) ;
	bool Save ( LPCTSTR szFullFileName, bool bEncryptContents = true ) ;
	bool GetKey ( PVOID pVPtr , LPTSTR& pStr ) ;
	bool GetData ( PVOID pVPtr , DWORD& dwData ) ;
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
