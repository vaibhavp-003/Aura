
/*======================================================================================
FILE             : PtrStack.h
ABSTRACT         : class declaration for stack of pointers
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

#pragma once

LPVOID Allocate(DWORD dwSize);
void Release(LPVOID& pVPtr);

typedef struct _tagPtrStack
{
	LPVOID lpPtr;
	struct _tagPtrStack* pNext;
}STACK_OF_PTRS, *LPSTACK_OF_PTRS;

class CPtrStack
{
public:
	CPtrStack();
	~CPtrStack();

	bool Push(LPVOID lpv);
	LPVOID Pop();
	bool IsEmpty();
	void RemoveAll();

	LPSTACK_OF_PTRS GetTop();
	LPSTACK_OF_PTRS GetNext();

private:

	LPSTACK_OF_PTRS		m_pTop, m_pCurrent;
};
