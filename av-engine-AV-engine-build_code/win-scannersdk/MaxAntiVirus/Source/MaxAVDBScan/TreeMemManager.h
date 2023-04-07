/*======================================================================================
FILE				: TreeMemManager.h
ABSTRACT			: Definition of module : Aho-corasick Tree's memory structure
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: 
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar + Rupali
=====================================================================================*/
#pragma once
#include	"MaxPEFile.h"	

typedef struct _MEMORY_POOL
{
	LPVOID		m_pBaseMemPtr;
	char		*m_pCurMemPtr;
	DWORD		m_dwAllocationSize;
}MEMORY_POOL, * LPMEMORY_POOL;

class CTreeMemManager
{
	MEMORY_POOL		**m_pTreeMemPool;
	DWORD			m_dwPoolCnt; //1 Base
	HANDLE			m_hMemHeap;
	DWORD			m_dwAllocUnit;	

	BOOL			CreateNewMemoryPool();

public:
	CTreeMemManager(void);
	~CTreeMemManager(void);

	LPVOID	AllocateMemory(DWORD dwSize);
	int		ReleaseMemory();
};
