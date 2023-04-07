#pragma once
#include "BalBST.h"
#include "MaxQSort.h"
#include "MaxSmallPESig.h"

const int iNEW_SIG_SIZE = 6;
const int iSMALLELEMENT_SIZE = 10;							//sizeof(unsigned char[6]) + sizeof(DWORD)
const int iNEW_MAX_TEMP_FILE_SIZE = 300 * 1024 * 1024;		//size of temp file while creating database

#pragma pack(1)
typedef struct _tagSmallElement
{
	unsigned char	szPESig[0x06];
	DWORD			dwSpyID;
}SMALLELMNT, *LPSMALLELMNT;

#pragma pack()

typedef struct _tagSmallSignaturePage
{
	LPVOID		lpPagePtr;
	DWORD		dwUseSigs;
	DWORD		dwMaxSigs;
	DWORD		dwPageOff;
	DWORD		dwPageLen;
	ULONG64		ulFrstSig;
	ULONG64		ulLastSig;
}SMALLSIGPAGE, *LPSMALLSIGPAGE;


class CMaxNewPESig
{
	bool			m_bMapReadOnly;
	TCHAR			m_szTempFilePath[MAX_PATH];
	DWORD			m_dwFileSize;
	DWORD			m_dwPgTblArrCnt;
	DWORD			m_dwMaxPageSize;
	DWORD			m_dwPgTblCurIdx;
	DWORD			m_dwCurIdxInPage;
	LPSMALLSIGPAGE	m_pPgTbl;
	HANDLE			m_hFile, m_hMapping;
	HANDLE			m_hHeapHadle;
	CMaxQSort		m_NewSigs[0x10];
	DWORD			m_dwCurDBIndex;				
	unsigned char	*m_pHeapBuffer;
	DWORD			m_dwCurReadPos;


	bool	MakeMapFileObj(bool *pbErrorOpenFile = 0x00);
	bool	MakePageTable();
	bool	MapPageOfTable(DWORD iPage);
	bool	FreePageTable();
	bool	MakeSigIndex();
	bool	Get(ULONG64* pSig, DWORD* pSpyID);

	int		BalancePageMemory(DWORD	dwPageIndex,DWORD *dwNewSize);
	int		GetNewMemoryPage();
	int		MergeInCurPage(DWORD dwPageIndex, DWORD *dwNewSize);
	int		AppendInCurPage(DWORD dwPageIndex, DWORD *dwNewSize);
	int		CreateNewMergePage(DWORD dwPageIndex, DWORD *dwNewSize);
	
	
public:
	CMaxNewPESig(int iMemToUseInMB = 4);
	~CMaxNewPESig(void);

	
	bool		m_bModified;
	bool		m_bDelEntry;

	bool	IsModified();
	int		GetPageIndex(ULONG64 pSig);
	bool	RemoveAll(bool bRemoveTree = true);
	bool	SetTempPath(LPCTSTR szTempPath);
	bool	GetFirst(PULONG64 pSig, LPDWORD pSpyID);
	bool	GetNext(PULONG64 pSig, LPDWORD pSpyID);
	
	
	bool	Load(LPCTSTR szFileName, bool bCheckVersion = true, bool bEncryptData = true, bool * pbDeleteIfFail = NULL);
	bool	SearchSig(PULONG64 pSig, LPDWORD pSpyID);
	bool	SearchSigEx(PULONG64 pSig, LPDWORD pSpyID);
	bool	Save(LPCTSTR szFileName, bool bCheckVersion = true, bool bEncryptData = true);
	bool	InsertItem(unsigned char *pszSig, DWORD dwSpyID, bool bAdd, int iPageIndex = -1);
	bool	GetItem(unsigned char *pszSig, DWORD *pdwSpyID, bool *pbAdd, int *piPageIndex);
	int		GetNextInsertionIndex();

	DWORD	GetSigBuff4Insertion(unsigned char *pszBuff,DWORD	dwBuffSize);

};
