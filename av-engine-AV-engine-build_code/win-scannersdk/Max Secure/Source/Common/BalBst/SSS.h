#pragma once
#include "S2S.h"

class CSSS : public CBalBST
{
public:

	CSSS(bool bIsEmbedded, bool bIgnoreCase = false);
	virtual ~CSSS() ;

	bool AppendItemAscOrder(LPCTSTR szKey, CS2S * pObjS2S);
	bool AppendItem(LPCTSTR szKey, CS2S * pObjS2S);
	bool DeleteItem(LPCTSTR szKey);
	bool SearchItem(LPCTSTR szKey, CS2S& objS2S);
	bool UpdateItem(LPCTSTR szKey, CS2S& objS2S);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, LPCTSTR& szKey);
	bool GetData(PVOID pVPtr, CS2S& objS2S);
	bool Balance();
	bool AppendObject(CBalBST& objSSS)
	{
		return true;
	}
	bool DeleteObject(CBalBST& objToDel);

private:

	bool m_bIgnoreCase;

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);

	bool DumpS2S(HANDLE hFile, ULONG64 dwData);
	bool ReadS2S(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
};
