#pragma once
#include "BalBST.h"
#include "PtrStack.h"

class CBSArray
{
public:

	CBSArray(DWORD dwKeySize, DWORD dwDataSize, int iNumberSize = 0);
	virtual ~CBSArray();

	bool SearchItem(LPVOID lpKey, LPVOID& lpData);
	bool AppendItem(LPVOID lpKey, LPVOID lpData);
	bool UpdateItem(LPVOID lpKey, LPVOID lpData);
	bool DeleteItem(LPVOID lpKey);
	bool AppendItemAscOrder(LPVOID lpKey, LPVOID lpData);

	LPVOID GetFirst();
	LPVOID GetNext(LPVOID lpContext);
	bool GetKey(LPVOID lpContext, LPVOID& lpKey);
	bool GetData(LPVOID lpContext, LPVOID& lpData);
	DWORD GetCount();
	void Balance();
	LPBYTE GetAt(DWORD dwIndex);
	bool SetAt(DWORD dwIndex, LPVOID lpKey, LPVOID lpData);
	bool InsertAt(DWORD dwIndex, LPVOID lpKey, LPVOID lpData);

	bool RemoveAll();
	bool IsModified();
	bool AppendObject(CBSArray& objToAdd);
	bool DeleteObject(CBSArray& objToDel);
	bool SetModified(bool bModified = true);
	bool SearchObject(CBSArray& objToSearch, bool bAllPresent = true);

	bool Load(LPCTSTR szFileName, bool bCheckVersion = true, bool bEncryptData = true);
	bool Save(LPCTSTR szFileName, bool bCheckVersion = true, bool bEncryptData = true);

private:

	bool		m_bByte;
	bool		m_bWord;
	bool		m_bDWord;
	bool		m_bQWord;
	bool		m_bModified;
	bool		m_bObjectMerging;
	DWORD		m_dwKeySize;
	DWORD		m_dwDataSize;
	DWORD		m_dwItemSize;
	DWORD		m_dwMaxMemory;
	DWORD		m_dwPageSize;
	DWORD		m_dwPageCount;
	LPBYTE		m_lpArray;
	DWORD		m_dwArrayMaxSize;
	DWORD		m_dwArrayUseSize;
	DWORD		m_dwLastSearchIndex;
	LPBYTE		m_lpLastSearchResult;
	CPtrStack	m_objPages;

	bool AddMemPage();
	bool AddRequiredMemPages(DWORD dwMemSize);
	COMPARE_RESULT Compare(LPVOID lpKey1, LPVOID lpKey2);
	DWORD LocateInsertPosition(LPVOID lpKey, DWORD dwStart, DWORD dwEnd, DWORD dwHop);
};
