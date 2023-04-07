
/*======================================================================================
FILE             : BalBSTOpt.cpp
ABSTRACT         : balanced binary search tree base class definition
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 1/16/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "BalBSTOpt.h"

/*--------------------------------------------------------------------------------------
Function       : CBalBSTOpt
In Parameters  : bool bIsEmbedded
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CBalBSTOpt::CBalBSTOpt(bool bIsEmbedded): m_bIsEmbedded(bIsEmbedded)
{
	m_iThreadsCount = -1;
	DestroyData();
}

/*--------------------------------------------------------------------------------------
Function       : ~CBalBSTOpt
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CBalBSTOpt::~CBalBSTOpt()
{
}

/*--------------------------------------------------------------------------------------
Function       : Lock
In Parameters  : 
Out Parameters : 
Description    : acquire exclusive access of object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::Lock()
{
	while(InterlockedIncrement(&m_iThreadsCount))
	{
		Sleep(1);
		InterlockedDecrement(&m_iThreadsCount);
	}
}

/*--------------------------------------------------------------------------------------
Function       : Unlock
In Parameters  : 
Out Parameters : 
Description    : relinquish exclusive access of object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::Unlock()
{
	while(-1 != InterlockedDecrement(&m_iThreadsCount))
	{
		Sleep(1);
	}
}

/*--------------------------------------------------------------------------------------
Function       : DestroyData
In Parameters  : 
Out Parameters : void 
Description    : reset the class object to nulls
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::DestroyData()
{
	m_pBuffer = NULL;
	m_dwCount = m_nBufferSize = 0;
	m_bLoadedFromFile = m_bTreeBalanced = m_bIsModified = false;
	m_pRoot = m_pTemp = m_pLastSearchResult = m_pLastSearchResultParent = m_pLinearTail = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : GetNode
In Parameters  : SIZE_T nKey, SIZE_T nData, 
Out Parameters : PNODEOPT 
Description    : get one node with intialised data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
PNODEOPT CBalBSTOpt::GetNode(SIZE_T nKey, SIZE_T nData)
{
	PNODEOPT pTemp = (PNODEOPT)Allocate(sizeof NODEOPT);
	if(NULL == pTemp)
	{
		return NULL;
	}

	pTemp->nData = nData;
	pTemp->nKey = nKey;
	pTemp->pLeft = pTemp->pRight = NULL;
	return pTemp;
}

/*--------------------------------------------------------------------------------------
Function       : AddNode
In Parameters  : SIZE_T nKey, SIZE_T nData
Out Parameters : bool 
Description    : add a node to tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::AddNode(SIZE_T nKey, SIZE_T nData)
{
	PNODEOPT* ppNewNodeLocation = NULL;
	COMPARE_RESULT CompResult = EQUAL;

	ppNewNodeLocation = m_pRoot ? ppNewNodeLocation : &m_pRoot;
	for(m_pTemp = m_pRoot; m_pTemp && !ppNewNodeLocation ; )
	{
		CompResult = Compare(m_pTemp->nKey, nKey);
		if(CompResult == LARGE)
		{
			if(m_pTemp->pLeft)
			{
				m_pTemp = m_pTemp->pLeft;
			}
			else
			{
				ppNewNodeLocation = &m_pTemp->pLeft;
			}
		}
		else if(CompResult == SMALL)
		{
			if(m_pTemp->pRight)
			{
				m_pTemp = m_pTemp->pRight;
			}
			else
			{
				ppNewNodeLocation = &m_pTemp->pRight;
			}
		}
		else
		{
			m_pTemp = NULL;
		}
	}

	if(NULL == ppNewNodeLocation)
	{
		return false;
	}

	*ppNewNodeLocation = GetNode(nKey, nData);
	if(NULL == *ppNewNodeLocation)
	{
		return false;
	}

	m_dwCount++;
	m_bIsModified = true;
	m_bTreeBalanced = false;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AddNodeAscOrder
In Parameters  : SIZE_T nKey, SIZE_T nData, 
Out Parameters : bool 
Description    : add a node in ascending order
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::AddNodeAscOrder(SIZE_T nKey, SIZE_T nData)
{
	PNODEOPT pNewNode = NULL;

	pNewNode = GetNode(nKey, nData);
	if(NULL == pNewNode)
	{
		return false;
	}

	if(NULL == m_pRoot)
	{
		m_pRoot = pNewNode;
		m_pLinearTail = pNewNode;
	}
	else
	{
		m_pLinearTail->pRight = pNewNode;
		m_pLinearTail = m_pLinearTail->pRight;
	}

	m_dwCount++;
	m_bIsModified = true;
	m_bTreeBalanced = false;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteNode
In Parameters  : SIZE_T nKey, 
Out Parameters : bool 
Description    : delete a node and restructure the tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::DeleteNode(SIZE_T nKey)
{
	SIZE_T nData = 0;
	NODEOPT PseudoRoot ={0};
	PNODEOPT pNodeToDelete = 0, pNodeToDeleteParent = 0, pNodeToReplaceWith = 0, pNodeToReplaceWithParent = 0;

	if((NULL == m_pLastSearchResult) ||(m_pLastSearchResult->nKey != nKey))
	{
		if(!FindNode(nKey, nData))
		{
			return false;
		}
	}

	pNodeToDelete = m_pLastSearchResult;
	pNodeToDeleteParent = m_pLastSearchResultParent;
	PseudoRoot.pRight = m_pRoot;

	if(pNodeToDelete == m_pRoot)
	{
		pNodeToDeleteParent = &PseudoRoot;
	}

	if(pNodeToDelete->pLeft && pNodeToDelete->pRight)
	{
		pNodeToReplaceWithParent = pNodeToDelete;
		pNodeToReplaceWith = pNodeToDelete->pLeft;
		while(pNodeToReplaceWith->pRight)
		{
			pNodeToReplaceWithParent = pNodeToReplaceWith;
			pNodeToReplaceWith = pNodeToReplaceWith->pRight;
		}

		if(pNodeToReplaceWithParent->pLeft == pNodeToReplaceWith)
		{
			pNodeToReplaceWithParent->pLeft = pNodeToReplaceWith->pLeft;
		}
		else if(pNodeToReplaceWithParent->pRight == pNodeToReplaceWith)
		{
			pNodeToReplaceWithParent->pRight = pNodeToReplaceWith->pLeft;
		}

		pNodeToReplaceWith->pLeft = pNodeToDelete->pLeft;
		pNodeToReplaceWith->pRight = pNodeToDelete->pRight;

		if(pNodeToDeleteParent->pLeft == pNodeToDelete)
		{
			pNodeToDeleteParent->pLeft = pNodeToReplaceWith;
		}
		else if(pNodeToDeleteParent->pRight == pNodeToDelete)
		{
			pNodeToDeleteParent->pRight = pNodeToReplaceWith;
		}
	}
	else
	{
		m_pTemp = pNodeToDelete->pLeft?pNodeToDelete->pLeft:pNodeToDelete->pRight?pNodeToDelete->pRight:NULL;
		if(pNodeToDeleteParent->pLeft == pNodeToDelete)
		{
			pNodeToDeleteParent->pLeft = m_pTemp;
		}
		else
		{
			pNodeToDeleteParent->pRight = m_pTemp;
		}
	}

	m_pRoot = PseudoRoot.pRight;
	FreeData(pNodeToDelete->nData);
	FreeKey(pNodeToDelete->nKey);

	if(((LPBYTE)pNodeToDelete < m_pBuffer) ||((LPBYTE)pNodeToDelete >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)pNodeToDelete);
	}

	if(m_dwCount)
	{
		m_dwCount--;
	}

	m_bIsModified = true;
	m_bTreeBalanced = false;
	m_pLastSearchResult = NULL;
	m_pLastSearchResultParent = NULL;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : RemoveAll
In Parameters  : 
Out Parameters : bool RemoveAll 
Description    : this frees all the memory and sets the tree object to null
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::RemoveAll()
{
	PNODEOPT pHold = NULL;
	CPtrStack objStack;

	if(m_bIsEmbedded)
	{
		DestroyData();
		return (true);
	}

	m_pTemp = m_pRoot;
	while(m_bIsModified && (m_pTemp || !objStack.IsEmpty()))
	{
		if(m_pTemp->pLeft)
		{
			objStack.Push(m_pTemp);
			m_pTemp = m_pTemp->pLeft;
		}
		else if(m_pTemp->pRight)
		{
			objStack.Push(m_pTemp);
			m_pTemp = m_pTemp->pRight;
		}
		else
		{
			pHold = (PNODEOPT)objStack.Pop();
			if(pHold)
			{
				if(pHold->pLeft == m_pTemp)
				{
					pHold->pLeft = NULL;
				}
				else if(pHold->pRight == m_pTemp)
				{
					pHold->pRight = NULL;
				}
			}

			FreeKey(m_pTemp->nKey);
			FreeData(m_pTemp->nData);
			if(((LPBYTE)m_pTemp < m_pBuffer) ||((LPBYTE)m_pTemp >= m_pBuffer + m_nBufferSize))
			{
				Release((LPVOID&)m_pTemp);
			}

			m_pTemp = pHold;
		}
	}

	if(m_bLoadedFromFile)
	{
		VRelease(m_pBuffer);
		m_pBuffer = NULL;
	}

	DestroyData();
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetCount
In Parameters  : 
Out Parameters : DWORD 
Description    : traverse and count the nodes in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CBalBSTOpt::GetCount()
{
	CPtrStack objPtrStack;

	/*if(m_dwCount)
	{
		return m_dwCount;
	}*/

	m_dwCount = 0;
	m_pTemp = m_pRoot;
	while(NULL != m_pTemp || !objPtrStack.IsEmpty())
	{
		if(m_pTemp)
		{
			objPtrStack.Push(m_pTemp);
			m_pTemp = m_pTemp->pLeft;
		}
		else
		{
			m_dwCount++;
			m_pTemp = (PNODEOPT)objPtrStack.Pop();
			m_pTemp = m_pTemp->pRight;
		}
	}

	return (m_dwCount);
}

/*--------------------------------------------------------------------------------------
Function       : GetFirst
In Parameters  : 
Out Parameters : LPVOID 
Description    : get the root pointer
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CBalBSTOpt::GetFirst()
{
	return (m_pRoot);
}

/*--------------------------------------------------------------------------------------
Function       : GetNext
In Parameters  : LPVOID pPrev, 
Out Parameters : LPVOID 
Description    : get next preorder node, used in tree traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CBalBSTOpt::GetNext(LPVOID pPrev)
{
	PNODEOPT pNode = (PNODEOPT)pPrev;

	if(pNode == m_pRoot)
	{
		m_objStack.RemoveAll();
	}
	else
	{
		pNode = pNode->pRight;
	}

	while(NULL != pNode || !m_objStack.IsEmpty())
	{
		if(pNode)
		{
			m_objStack.Push(pNode);
			pNode = pNode->pLeft;
		}
		else
		{
			pNode = (PNODEOPT)m_objStack.Pop();

			if(pNode != m_pRoot)
			{
				break;
			}

			pNode = pNode->pRight;
		}
	}

	return pNode;
}

/*--------------------------------------------------------------------------------------
Function       : FullSize
In Parameters  : int size, 
Out Parameters : int 
Description    : calculate the size to compress when converting to tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CBalBSTOpt::FullSize(int size)
{
	int Rtn = 1;

	while(Rtn <= size)
	{
		Rtn = Rtn + Rtn + 1;
	}

	return Rtn / 2;
}

/*--------------------------------------------------------------------------------------
Function       : Compress
In Parameters  : PNODEOPT pRoot, int count, 
Out Parameters : void 
Description    : rotate and balance the tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::Compress(PNODEOPT pRoot, int count)
{
	PNODEOPT scanner = pRoot;

	for(int j = 0; j < count; j++)
	{
		PNODEOPT child = scanner->pRight;
		scanner->pRight = child->pRight;
		scanner = scanner->pRight;
		child->pRight = scanner->pLeft;
		scanner->pLeft = child;
	}
}

/*--------------------------------------------------------------------------------------
Function       : ConvertVineToTree
In Parameters  : PNODEOPT pRoot, int size, 
Out Parameters : void 
Description    : make the tree of vine, used in balancing
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::ConvertVineToTree(PNODEOPT pRoot, int size)
{
	int full_count = FullSize(size);
	Compress(pRoot, size - full_count);
	for(size = full_count; size > 1; size /= 2)
	{
		Compress(pRoot, size / 2);
	}
}

/*--------------------------------------------------------------------------------------
Function       : ConvertTreeToVine
In Parameters  : PNODEOPT pRoot, int &size, 
Out Parameters : void 
Description    : make the vine of tree, used in balancing
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::ConvertTreeToVine(PNODEOPT pRoot, int &size)
{
	PNODEOPT vineTail = 0;
	PNODEOPT remainder = 0;
	PNODEOPT tempPtr = 0;

	vineTail = pRoot;
	remainder = vineTail->pRight;
	size = 0;

	while(remainder != NULL)
	{
		if(remainder->pLeft == NULL)
		{
			vineTail = remainder;
			remainder = remainder->pRight;
			size++;
		}
		else
		{
			tempPtr = remainder->pLeft;
			remainder->pLeft = tempPtr->pRight;
			tempPtr->pRight = remainder;
			remainder = tempPtr;
			vineTail->pRight = tempPtr;
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : bool 
Description    : balance the tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::Balance()
{
	int iCount = 0;
	NODEOPT Pseudo_Root = {0};

	Pseudo_Root.pRight = m_pRoot;
	ConvertTreeToVine(&Pseudo_Root, iCount);
	ConvertVineToTree(&Pseudo_Root, iCount);
	m_pRoot = Pseudo_Root.pRight;

	m_bTreeBalanced = true;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : FindNode
In Parameters  : SIZE_T nKey, SIZE_T& nData, 
Out Parameters : bool 
Description    : search for a node in tree by key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::FindNode(SIZE_T nKey, SIZE_T& nData)
{
	bool bFound = false;
	COMPARE_RESULT CompResult = EQUAL;

	m_pLastSearchResultParent = NULL;
	m_pLastSearchResult = NULL;
	m_pTemp = m_pRoot;
	while(m_pTemp)
	{
		CompResult = Compare(nKey, m_pTemp->nKey);
		if(SMALL == CompResult)
		{
			m_pLastSearchResultParent = m_pTemp;
			m_pTemp = m_pTemp->pLeft;
		}
		else if(LARGE == CompResult)
		{
			m_pLastSearchResultParent = m_pTemp;
			m_pTemp = m_pTemp->pRight;
		}
		else
		{
			m_pLastSearchResult = m_pTemp;
			nData = m_pTemp->nData;
			bFound = true;
			break;
		}
	}

	m_pLastSearchResultParent = m_pLastSearchResult ? m_pLastSearchResultParent : NULL;
	return (bFound);
}

/*--------------------------------------------------------------------------------------
Function       : GetDataPtr
In Parameters  : 
Out Parameters : PNODEOPT
Description    : get pointer to internal tree root
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
PNODEOPT CBalBSTOpt::GetDataPtr()
{
	return (m_pRoot);
}

/*--------------------------------------------------------------------------------------
Function       : SetDataPtr
In Parameters  : PNODEOPT pNode, LPBYTE pbyBuffer, DWORD nBufferSize, 
Out Parameters : bool 
Description    : set the data pointers and values
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::SetDataPtr(PNODEOPT pNode, LPBYTE pbyBuffer, DWORD nBufferSize)
{
	m_pRoot = pNode;
	m_pBuffer = pbyBuffer;
	m_nBufferSize = nBufferSize;
	m_bIsModified = true;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : IsModified
In Parameters  : 
Out Parameters : bool 
Description    : return true if object modified else false
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::IsModified()
{
	return m_bIsModified;
}

/*--------------------------------------------------------------------------------------
Function       : SetModified
In Parameters  : 
Out Parameters : void
Description    : sets the object modified flag true
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBalBSTOpt::SetModified(bool bModified)
{
	m_bIsModified = bModified;
}

/*--------------------------------------------------------------------------------------
Function       : SearchObject
In Parameters  : CBalBSTOpt& objToSearch, bool bAllPresent
Out Parameters : bool 
Description    : when 'bAllPresent' is true the function searches to see that all entries
				 in 'objToSearch' are present in 'this' object. when 'bAllPresent' is false
				 the function searches to see that all entries in 'objToSearch' are absent
				 in 'this' object.
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBalBSTOpt::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetHighest
In Parameters  : 
Out Parameters : LPVOID
Description    : return highest node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CBalBSTOpt::GetHighest()
{
	PNODEOPT pNode = m_pRoot;

	m_objStack.RemoveAll();
	while(pNode || !m_objStack.IsEmpty())
	{
		if(pNode)
		{
			m_objStack.Push(pNode);
			pNode = pNode->pRight;
		}
		else
		{
			pNode = (PNODEOPT)m_objStack.Pop();
			break;
		}
	}

	return pNode;
}

/*--------------------------------------------------------------------------------------
Function       : GetHighestNext
In Parameters  : 
Out Parameters : LPVOID
Description    : return next highest node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CBalBSTOpt::GetHighestNext(LPVOID pContext)
{
	PNODEOPT pNode = (PNODEOPT)pContext;

	pNode = pNode->pLeft;
	while(pNode || !m_objStack.IsEmpty())
	{
		if(pNode)
		{
			m_objStack.Push(pNode);
			pNode = pNode->pRight;
		}
		else
		{
			pNode = (PNODEOPT)m_objStack.Pop();
			break;
		}
	}

	return pNode;
}

/*--------------------------------------------------------------------------------------
Function       : GetLowest
In Parameters  : 
Out Parameters : LPVOID
Description    : return lowest node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CBalBSTOpt::GetLowest()
{
	PNODEOPT pNode = m_pRoot;

	m_objStack.RemoveAll();
	while(pNode || !m_objStack.IsEmpty())
	{
		if(pNode)
		{
			m_objStack.Push(pNode);
			pNode = pNode->pLeft;
		}
		else
		{
			pNode = (PNODEOPT)m_objStack.Pop();
			break;
		}
	}

	return pNode;
}

/*--------------------------------------------------------------------------------------
Function       : GetLowestNext
In Parameters  : 
Out Parameters : LPVOID
Description    : return next lowest node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CBalBSTOpt::GetLowestNext(LPVOID pContext)
{
	PNODEOPT pNode = (PNODEOPT)pContext;

	pNode = pNode->pRight;
	while(pNode || !m_objStack.IsEmpty())
	{
		if(pNode)
		{
			m_objStack.Push(pNode);
			pNode = pNode->pLeft;
		}
		else
		{
			pNode = (PNODEOPT)m_objStack.Pop();
			break;
		}
	}

	return pNode;
}
