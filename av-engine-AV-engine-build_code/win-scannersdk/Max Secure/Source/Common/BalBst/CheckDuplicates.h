
/*======================================================================================
FILE             : CheckDuplicates.h
ABSTRACT         : declares tree class to handle duplicates
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
				  
CREATION DATE    : 6/30/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once

typedef struct _tagULong64
{
	ULONG64 Data;
	struct _tagULong64 * Left;
	struct _tagULong64 * Right;
} U64DATA, *PU64DATA;

class CCheckDuplicates
{

public:

	CCheckDuplicates();
	virtual ~CCheckDuplicates();
	void RemoveAll();
	bool Add(ULONG64 nNumber);
	bool Search(ULONG64 nNumber);


private:

	PU64DATA m_pRoot;
	PU64DATA* m_ppAddHere;

	PU64DATA GetNode(ULONG64 nNumber);
	void Remove(PU64DATA pNode);
};
