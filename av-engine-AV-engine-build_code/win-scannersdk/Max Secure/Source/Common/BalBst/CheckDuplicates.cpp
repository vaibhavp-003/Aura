
/*======================================================================================
FILE             : CheckDuplicates.cpp
ABSTRACT         : defines tree class to handle duplicates
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

#include "pch.h"
#include "CheckDuplicates.h"

/*--------------------------------------------------------------------------------------
Function       : CCheckDuplicates
In Parameters  :
Out Parameters : CCheckDuplicates
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CCheckDuplicates::CCheckDuplicates()
{
	m_pRoot = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : ~CCheckDuplicates
In Parameters  :
Out Parameters : CCheckDuplicates
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CCheckDuplicates::~CCheckDuplicates()
{
	Remove(m_pRoot);
	m_pRoot = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : RemoveAll
In Parameters  :
Out Parameters : void
Description    : release all nodes and empty tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CCheckDuplicates::RemoveAll()
{
	Remove(m_pRoot);
	m_pRoot = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : GetNode
In Parameters  : ULONG64 nNumber, 
Out Parameters : PU64DATA 
Description    : allocate memory and initialise a new node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
PU64DATA CCheckDuplicates::GetNode(ULONG64 nNumber)
{
	PU64DATA pHold = 0;

	pHold = new U64DATA;
	if(pHold)
	{
		pHold->Data = nNumber;
		pHold->Left = pHold->Right = NULL;
	}

	return (pHold);
}

/*--------------------------------------------------------------------------------------
Function       : Add
In Parameters  : ULONG64 nNumber
Out Parameters : bool 
Description    : add a node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CCheckDuplicates::Add(ULONG64 nNumber)
{
	if(Search(nNumber))
	{
		return (false);
	}

	*m_ppAddHere = GetNode(nNumber);
	if(!*m_ppAddHere)
	{
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Remove
In Parameters  : PU64DATA pNode, 
Out Parameters : void 
Description    : relase all nodes
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CCheckDuplicates::Remove(PU64DATA pNode)
{
	if(!pNode)
	{
		return;
	}

	if(pNode->Left)
	{
		Remove(pNode->Left);
	}

	if(pNode->Right)
	{
		Remove(pNode->Right);
	}

	delete pNode;
}

/*--------------------------------------------------------------------------------------
Function       : Search
In Parameters  : ULONG64 nNumber, 
Out Parameters : bool 
Description    : search and return true if found else false
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CCheckDuplicates::Search(ULONG64 nNumber)
{
	bool bFound = false;
	PU64DATA m_pLastNodeVisited = 0;

	if(!m_pRoot)
	{
		m_ppAddHere = &m_pRoot;
		return (bFound);
	}

	m_pLastNodeVisited = m_pRoot;
	while(m_pLastNodeVisited)
	{
		if(m_pLastNodeVisited->Data < nNumber)
		{
			if(!m_pLastNodeVisited->Right)
			{
				m_ppAddHere = &m_pLastNodeVisited->Right;
				break;
			}

			m_pLastNodeVisited = m_pLastNodeVisited->Right;
		}
		else if(m_pLastNodeVisited->Data > nNumber)
		{
			if(!m_pLastNodeVisited->Left)
			{
				m_ppAddHere = &m_pLastNodeVisited->Left;
				break;
			}

			m_pLastNodeVisited = m_pLastNodeVisited->Left;
		}
		else
		{
			bFound = true;
			break;
		}
	}

	return (bFound);
}
