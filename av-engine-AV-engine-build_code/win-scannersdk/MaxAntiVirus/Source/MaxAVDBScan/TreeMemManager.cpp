/*======================================================================================
   FILE				: TreeMemManager.cpp
   ABSTRACT			: Supportive class Scan Tree Manager
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module Allocates and manages tree memory using pagging. 
   VERSION HISTORY	: 
=====================================================================================*/
#include "TreeMemManager.h"

/*-------------------------------------------------------------------------------------
	Function		: CTreeMemManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CTreeMemManager::CTreeMemManager(void)
{
	m_dwPoolCnt = 0x00;
	m_hMemHeap	= NULL;
	m_dwAllocUnit = 0x4000;//32 Kb

	m_pTreeMemPool = NULL;
	m_hMemHeap = NULL;
	m_hMemHeap = HeapCreate(0x00,0x8000,0x00); //Heap Memory of 32 Kb : Growable
	if (m_hMemHeap != NULL)
	{
		ULONG	HeapFragValue = 2;
		HeapSetInformation(m_hMemHeap,HeapCompatibilityInformation,&HeapFragValue,sizeof(HeapFragValue));
	}

}

/*-------------------------------------------------------------------------------------
	Function		: ~CTreeMemManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CTreeMemManager::~CTreeMemManager(void)
{
	if (m_hMemHeap != NULL)
	{
		HeapDestroy(m_hMemHeap);
		m_hMemHeap = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CreateNewMemoryPool
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Creates Memory pool from heap memory (linear memory pools)
--------------------------------------------------------------------------------------*/
BOOL CTreeMemManager::CreateNewMemoryPool()
{
	if (m_dwPoolCnt == 0x00)
	{
		m_pTreeMemPool = (MEMORY_POOL **)malloc((m_dwPoolCnt + 0x01) * sizeof(MEMORY_POOL *));
		m_pTreeMemPool[m_dwPoolCnt]  = (MEMORY_POOL *)malloc(sizeof(MEMORY_POOL));
		memset(m_pTreeMemPool[m_dwPoolCnt],0x00,sizeof(MEMORY_POOL));
	}
	else
	{
		m_pTreeMemPool = (MEMORY_POOL **)realloc(m_pTreeMemPool,(m_dwPoolCnt + 0x01) * sizeof(MEMORY_POOL *));
		m_pTreeMemPool[m_dwPoolCnt]  = (MEMORY_POOL *)malloc(sizeof(MEMORY_POOL));
		memset(m_pTreeMemPool[m_dwPoolCnt],0x00,sizeof(MEMORY_POOL));
	}
	
	m_pTreeMemPool[m_dwPoolCnt]->m_pBaseMemPtr = HeapAlloc(m_hMemHeap,HEAP_ZERO_MEMORY,m_dwAllocUnit);
	m_pTreeMemPool[m_dwPoolCnt]->m_pCurMemPtr = (char *)m_pTreeMemPool[m_dwPoolCnt]->m_pBaseMemPtr;
	m_pTreeMemPool[m_dwPoolCnt]->m_dwAllocationSize = 0x00;

	m_dwPoolCnt++;

	return TRUE; 
}

/*-------------------------------------------------------------------------------------
	Function		: AllocateMemory
	In Parameters	: DWORD dwSize
	Out Parameters	: Pointer to the allocated memory
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Allocated memory from Memory pool
--------------------------------------------------------------------------------------*/
LPVOID CTreeMemManager::AllocateMemory(DWORD dwSize)
{
	LPVOID	lpNewMemLocation = NULL;

	if (m_dwPoolCnt == 0x00)
	{
		CreateNewMemoryPool();
	}
	else if ((m_pTreeMemPool[m_dwPoolCnt - 0x01]->m_dwAllocationSize + dwSize) > m_dwAllocUnit)
	{
		CreateNewMemoryPool();
	}

	lpNewMemLocation = (LPVOID)m_pTreeMemPool[m_dwPoolCnt - 0x01]->m_pCurMemPtr;
	m_pTreeMemPool[m_dwPoolCnt - 0x01]->m_pCurMemPtr += dwSize;
	m_pTreeMemPool[m_dwPoolCnt - 0x01]->m_dwAllocationSize += dwSize;

	return lpNewMemLocation;
}

/*-------------------------------------------------------------------------------------
	Function		: ReleaseMemory
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destruct the alloacted memory
--------------------------------------------------------------------------------------*/
int	 CTreeMemManager::ReleaseMemory()
{
	int		i = 0x00;

	if (m_dwPoolCnt > 0x00)
	{
		for (i = m_dwPoolCnt - 0x01; i >= 0x00; i--)
		{
			if (m_hMemHeap != NULL && m_pTreeMemPool[i]->m_pBaseMemPtr != NULL)
			{
				HeapFree(m_hMemHeap,HEAP_ZERO_MEMORY,(LPVOID)m_pTreeMemPool[i]->m_pBaseMemPtr);
				free(m_pTreeMemPool[i]);
			}
		}
	}
	m_dwPoolCnt = 0x00;

	if (m_pTreeMemPool)
	{
		free(m_pTreeMemPool);
		m_pTreeMemPool = NULL;
	}

	return 0x00;
}