
/*======================================================================================
FILE             : PtrStack.cpp
ABSTRACT         : class definition for stack of pointers
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
CREATION DATE    : 28/Jan/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "PtrStack.h"

/*--------------------------------------------------------------------------------------
Function       : CPtrStack
In Parameters  : 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CPtrStack::CPtrStack()
{
	m_pTop = m_pCurrent = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CPtrStack
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CPtrStack::~CPtrStack()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : Push
In Parameters  : LPVOID lpv
Out Parameters : bool
Description    : push one item on stack
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CPtrStack::Push(LPVOID lpv)
{
	LPSTACK_OF_PTRS pNew = NULL;

	pNew = (LPSTACK_OF_PTRS) Allocate(sizeof(STACK_OF_PTRS));
	if(!pNew)
	{
		return false;
	}

	pNew->lpPtr = lpv;
	pNew->pNext = m_pTop;
	m_pTop = pNew;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Pop
In Parameters  : LPVOID lpv
Out Parameters : bool
Description    : pop one item from stack
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CPtrStack::Pop()
{
	LPVOID lpv = NULL;

	if(m_pTop)
	{
		LPSTACK_OF_PTRS pHold = m_pTop;
		lpv = m_pTop->lpPtr;
		m_pTop = m_pTop->pNext;
		Release((LPVOID&)pHold);
	}

	return lpv;
}

/*--------------------------------------------------------------------------------------
Function       : GetTop
In Parameters  : 
Out Parameters : LPSTACK_OF_PTRS
Description    : topmost pointer
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPSTACK_OF_PTRS CPtrStack::GetTop()
{
	m_pCurrent = m_pTop;
	return m_pCurrent;
}

/*--------------------------------------------------------------------------------------
Function       : GetNext
In Parameters  : 
Out Parameters : LPSTACK_OF_PTRS
Description    : get next pointer
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPSTACK_OF_PTRS CPtrStack::GetNext()
{
	m_pCurrent = m_pCurrent? m_pCurrent->pNext: m_pCurrent;
	return m_pCurrent;
}

/*--------------------------------------------------------------------------------------
Function       : IsEmpty
In Parameters  : 
Out Parameters : bool
Description    : return true if stack is empty else false
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CPtrStack::IsEmpty()
{
	return m_pTop == NULL;
}

/*--------------------------------------------------------------------------------------
Function       : IsEmpty
In Parameters  : 
Out Parameters : bool
Description    : cleanup all stack occupied memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CPtrStack::RemoveAll()
{
	LPSTACK_OF_PTRS pHold = m_pTop;

	while(m_pTop)
	{
		pHold = m_pTop -> pNext;
		Release((LPVOID&)m_pTop);
		m_pTop = pHold;
	}
}

