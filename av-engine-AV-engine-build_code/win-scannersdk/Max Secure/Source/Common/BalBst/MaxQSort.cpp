#include "pch.h"
#include "MaxQSort.h"

CMaxQSort::CMaxQSort(int iMemToUseInMB)
{
	m_pRoot = NULL;
	m_pCurPos = NULL;
	m_bStarted = false;
	m_pEnd = NULL;
	m_bLog = false;
	m_dwCurHeapIndex = 0x00;
	m_pHeapBuffer = NULL;
	m_hHeapHadle = NULL;

	m_dwMemPageSize = iMemToUseInMB;
}

CMaxQSort::~CMaxQSort(void)
{
	FreeQueueMem();

	m_pHeapBuffer = NULL;
	m_hHeapHadle = NULL;

	m_pRoot = NULL;
	m_pCurPos = NULL;
	m_bStarted = false;
	m_pEnd = NULL;
	m_bLog = false;
	m_dwCurHeapIndex = 0x00;
}

int	CMaxQSort::ExtendMemoryPage(int iSz2ExtendInMB)
{
	int				iReturn = 0x00;
	unsigned char	*pTempHeapPtr = NULL;

	pTempHeapPtr = m_pHeapBuffer;

	m_dwMemPageSize += iSz2ExtendInMB;

	m_pHeapBuffer = (unsigned char *)HeapReAlloc(m_hHeapHadle,HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY,(LPVOID)m_pHeapBuffer, (m_dwMemPageSize * 1024 * 1024));
	if (NULL == m_pHeapBuffer)
	{
		m_pHeapBuffer = pTempHeapPtr;
		return iReturn;
	}

	return 0x01;
}

QSORTNODE *CMaxQSort::QSORTAllocNode()
{
	QSORTNODE	*pTemp = NULL;

	if (m_hHeapHadle == NULL || m_pHeapBuffer == NULL)
	{
		GetNewMemoryPage(m_dwMemPageSize);
	}
	
	if (m_dwCurHeapIndex >= (m_dwMemPageSize * 1024 *1024))
	{
		if(ExtendMemoryPage(0x03) == 0x00)
		{
			return NULL;
		}
	}

	pTemp = (QSORTNODE *)&m_pHeapBuffer[m_dwCurHeapIndex];
	m_dwCurHeapIndex+=sizeof(QSORTNODE);

	if (pTemp)
	{
		memset(pTemp,0x00,sizeof(QSORTNODE));
		return pTemp;
	}

	return NULL;
}

bool CMaxQSort::InsertItem(unsigned char *pszSig, DWORD dwSpyID, bool bAdd, int iPageIndex)
{
	bool			bResult	= false;
	ULONG64			ulSig2Insert = 0x00, ulPageIndex = 0x00;
	QSORTNODE		*pNewNode = NULL;
	QSORTNODE		*pTemp = NULL;
	CMaxSmallPESig	objSmallSig;

	if (pszSig == NULL)
	{
		return bResult;
	}

	objSmallSig.GetUlongFromSz(pszSig,&ulSig2Insert);
	if (iPageIndex > 0x00)
	{
		ulPageIndex = iPageIndex * 0x0010000000000000;
		ulSig2Insert = ulPageIndex + ulSig2Insert;
	}
	
	if (m_pRoot == NULL)
	{
		//1 : Queue is Empty. 
		m_pRoot = QSORTAllocNode();
		

		if (m_pRoot == NULL)
		{
			return bResult;
		}
		m_pRoot->ulSig = ulSig2Insert;
		memcpy(&m_pRoot->szPESig[0x00],pszSig,0x06);
		m_pRoot->dwSpyID = dwSpyID;
		m_pRoot->pNext = NULL;

		m_pEnd = m_pRoot;

		return true;
	}
	else
	{
		pNewNode = QSORTAllocNode();
		if (pNewNode == NULL)
		{
			return bResult;
		}
		pNewNode->ulSig = ulSig2Insert;
		pNewNode->dwSpyID = dwSpyID;
		memcpy(&pNewNode->szPESig[0x00],pszSig,0x06);
		pNewNode->pNext = NULL;
		
		
		if (m_pEnd)
		{
			if (m_pEnd->ulSig < pNewNode->ulSig)
			{
				m_pEnd->pNext = pNewNode;
				m_pEnd = pNewNode;
				return true;
			}
		}

		
		//2 : New Element is less than Root Element then shifting New Element to ROOT.
		if (m_pRoot->ulSig > pNewNode->ulSig)
		{
			pNewNode->pNext = m_pRoot;
			m_pRoot = pNewNode;
			return true;
		}

		//3 : Only one existing element in Queue.
		if (m_pRoot->pNext == NULL)
		{
			m_pRoot->pNext = pNewNode;
			m_pEnd = pNewNode;
			return true;
		}

		pTemp = NULL;
		pTemp = m_pRoot;
		while(pTemp)
		{
			//4 : Reached till end.
			if (pTemp->pNext == NULL)
			{
				pTemp->pNext = pNewNode;
				m_pEnd = pNewNode;
				return true;
			}
			//5 : In-between condition.
			if (pTemp->ulSig < ulSig2Insert && pTemp->pNext->ulSig > ulSig2Insert)
			{
				pNewNode->pNext = pTemp->pNext;
				pTemp->pNext = pNewNode;
				return true;
			}
			else if (pTemp->ulSig == ulSig2Insert)
			{
				pTemp->dwSpyID = dwSpyID;
				return true;
			}
			if (pTemp->pNext == NULL)
			{
				break;
			}
			pTemp = pTemp->pNext;
		}
	}
	
	return bResult;
}

bool CMaxQSort::FreeQueueMem()
{
	bool		bResult = false;

	if (m_pHeapBuffer != NULL)
	{
		HeapFree(m_hHeapHadle,0x00,m_pHeapBuffer);
		m_pHeapBuffer = NULL;
	}
	if (m_hHeapHadle != NULL)
	{
		HeapDestroy(m_hHeapHadle);
		m_hHeapHadle = NULL;
	}

	/*
	QSORTNODE	*pTemp = NULL, *pNewStart = NULL;
	
	if (m_pRoot == NULL)
	{
		return false;
	}

	pTemp = m_pRoot;
	while(pTemp)
	{
		pNewStart = pTemp->pNext;
		free(pTemp);
		pTemp = NULL;
		
		if (pNewStart == NULL)
		{
			break;
		}
		pTemp = pNewStart;
	}
	*/
	return true;
}

bool CMaxQSort::SetIndex(unsigned char *pszSig, DWORD dwIndex)
{
	/*
	bool		bResult = false;
	ULONG64		ulSig2Insert = 0x00;
	QSORTNODE	*pTemp = NULL;

	if(pszSig == NULL || m_pRoot == NULL)
	{
		return bResult;
	}
		
	CMaxSmallPESig	objSmallSig;

	objSmallSig.GetUlongFromSz(pszSig,&ulSig2Insert);
		
	pTemp = m_pRoot;
	while(pTemp)
	{
		if (pTemp->ulSig == ulSig2Insert)
		{
			pTemp->lInsertionIndex = dwIndex;
			break;
		}
		pTemp = pTemp->pNext;
		if (pTemp == NULL)
		{
			break;
		}
	}
	*/
	return true;
}

int	CMaxQSort::GetNextInsertionIndex()
{
	int64_t		dwRetValue = -1;

	if (m_pCurPos == NULL && m_bStarted == false)
	{
		m_pCurPos = m_pRoot;
		m_bStarted = true;
	}

	if (m_pCurPos != NULL)
	{
		dwRetValue = m_pCurPos->ulSig / 0x0010000000000000;
	}
	return (int)dwRetValue;
}

bool CMaxQSort::GetItem(unsigned char *pszSig, DWORD *pdwSpyID, bool *pbAdd, int *piPageIndex)
{
	unsigned char szDummy[0x06] = {0x00};	

	if (m_pCurPos == NULL && m_bStarted == false)
	{
		m_pCurPos = m_pRoot;
		m_bStarted = true;
	}

	if (m_pCurPos != NULL)
	{
		if (pszSig)
		{
			memcpy(pszSig,&m_pCurPos->szPESig[0x00],0x06);
		}
		if (pdwSpyID) *pdwSpyID = m_pCurPos->dwSpyID;
		if (pbAdd) *pbAdd = true;
		if (piPageIndex) *piPageIndex = (int)(m_pCurPos->ulSig / 0x0010000000000000); 
		m_pCurPos = m_pCurPos->pNext;
	}
	else
	{
		return false;
	}

	return true;
}

int	CMaxQSort::GetQueueCnt()
{
	int			iReturnValue = 0x00;
	QSORTNODE	*pTemp = NULL;

	pTemp = m_pRoot;
	while(pTemp != NULL)
	{
		iReturnValue++;
		pTemp = pTemp->pNext;
	}

	return iReturnValue;
}

int	CMaxQSort::GetNewMemoryPage(int iMemToUseInMB)
{
	int		iReturn = 0x00;

	if (NULL == m_hHeapHadle)
	{
		m_hHeapHadle = HeapCreate(0x00, iMemToUseInMB * 1024 * 1024,0x00);
		if (m_hHeapHadle == NULL)
		{
			return iReturn;
		}
		int		iHEAP_LFH = 0x02;
		HeapSetInformation(m_hHeapHadle,HeapCompatibilityInformation,&iHEAP_LFH,sizeof(iHEAP_LFH));
	}

	if (m_pHeapBuffer == NULL)
	{
		m_pHeapBuffer = (unsigned char *)HeapAlloc(m_hHeapHadle,HEAP_ZERO_MEMORY,(iMemToUseInMB * 1024 * 1024));
		if (NULL == m_pHeapBuffer)
		{
			return iReturn;
		}
		iReturn = 0x01;
	}
	else
	{
		iReturn = 0x01;
	}

	return iReturn;
}