#pragma once
#include <stdio.h>
#include "MaxSmallPESig.h"


struct QSORTNODE;

#pragma pack(1)
struct QSORTNODE
{
	ULONG64			ulSig;
	DWORD			dwSpyID;
	unsigned char	szPESig[0x06];
	//int			lInsertionIndex;
	//bool			bDel;
	QSORTNODE		*pNext;
};
#pragma pack()

class CMaxQSort
{
	QSORTNODE	*m_pRoot;
	QSORTNODE	*m_pCurPos;
	QSORTNODE	*m_pEnd;

	QSORTNODE	*QSORTAllocNode();
	bool		FreeQueueMem();	
	bool		m_bStarted;
	
	HANDLE			m_hHeapHadle;
	unsigned char	*m_pHeapBuffer;
	DWORD			m_dwCurHeapIndex;
	int				GetNewMemoryPage(int iMemToUseInMB);
	int				ExtendMemoryPage(int iSz2ExtendInMB);
	DWORD			m_dwMemPageSize;

public:

	bool		m_bLog;

	CMaxQSort(int iMemToUseInMB = 0x01);
	~CMaxQSort(void);

	bool	InsertItem(unsigned char *pszSig, DWORD dwSpyID, bool bAdd, int iPageIndex = -1);
	bool	SetIndex(unsigned char *pszSig,DWORD dwIndex);	
	int		GetNextInsertionIndex();
	bool	GetItem(unsigned char *pszSig, DWORD *pdwSpyID, bool *pbAdd, int *piPageIndex);	
	int		GetQueueCnt();
};
