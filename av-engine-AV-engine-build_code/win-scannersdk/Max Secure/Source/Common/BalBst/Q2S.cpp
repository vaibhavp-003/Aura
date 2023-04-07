
/*======================================================================================
FILE             : Q2S.cpp
ABSTRACT         : tree class to handle database type of quad word(u64) -> string
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
				  
CREATION DATE    : 2/3/2011
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "Q2S.h"

BYTE HEADER_Q2S[24]			= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_Q2S_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CQ2S
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CQ2S::CQ2S(bool bIsEmbedded): CBalBSTOpt(bIsEmbedded)
{
	m_bSaveError = false;
	m_bLoadError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CQ2S
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CQ2S::~CQ2S()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : Compare
In Parameters  : ULONG64 dwKey1, ULONG64 dwKey2, 
Out Parameters : COMPARE_RESULT 
Description    : compare two key and return small, large or equal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
COMPARE_RESULT CQ2S::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	QWORD ulKey1 = *((QWORD*)(nKey1));
	QWORD ulKey2 = *((QWORD*)(nKey2));

	if(ulKey1 < ulKey2)
	{
		return SMALL;
	}
	else if(ulKey1 > ulKey2)
	{
		return LARGE;
	}
	else
	{
		return EQUAL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeKey
In Parameters  : SIZE_T nKey
Out Parameters : void 
Description    : free key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CQ2S::FreeKey(SIZE_T nKey)
{
	if ((((LPBYTE)nKey) < m_pBuffer) || (((LPBYTE)nKey) >= (m_pBuffer + m_nBufferSize)))
	{
		Release((LPVOID&)nKey);
	}

	return;
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : SIZE_T nData
Out Parameters : void 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CQ2S::FreeData(SIZE_T nData)
{
	if(((LPBYTE)nData < m_pBuffer) ||((LPBYTE)nData >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID &)nData);
	}

	return;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : QWORD ulKey, LPCTSTR szData, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::AppendItemAscOrder(QWORD ulKey, LPCTSTR szData)
{
	LPTSTR szHold = 0;
	SIZE_T pKey = 0;

	pKey = (SIZE_T)DuplicateBuffer((LPBYTE)&ulKey, sizeof(ulKey));
	if(NULL == pKey)
	{
		return false;
	}

	szHold = DuplicateString(szData);
	if(NULL == szHold)
	{
		Release((LPVOID&)pKey);
		return false;
	}

	if(!AddNodeAscOrder(pKey, (SIZE_T)szHold))
	{
		Release((LPVOID&)pKey);
		Release((LPVOID&)szHold);
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : QWORD ulKey, LPCTSTR szData, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::AppendItem(QWORD ulKey, LPCTSTR szData)
{
	LPTSTR szHold = 0;
	SIZE_T pKey = 0;

	pKey = (SIZE_T)DuplicateBuffer((LPBYTE)&ulKey, sizeof(ulKey));
	if(NULL == pKey)
	{
		return false;
	}

	szHold = DuplicateString(szData);
	if(NULL == szHold)
	{
		Release((LPVOID&)pKey);
		return false;
	}

	if(!AddNode(pKey, (SIZE_T)szHold))
	{
		Release((LPVOID&)pKey);
		Release((LPVOID&)szHold);
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteItem
In Parameters  : QWORD ulKey
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::DeleteItem(QWORD ulKey)
{
	return DeleteNode((SIZE_T)&ulKey);
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : QWORD ulKey, LPTSTR& szData, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::SearchItem(QWORD ulKey, LPTSTR& szData)
{
	SIZE_T dwData = 0;

	if(!FindNode((SIZE_T)&ulKey, dwData))
	{
		return false;
	}

	if(szData)
	{
		szData = (LPTSTR)dwData;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, QWORD& ulKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::GetKey(PVOID pVPtr, QWORD& ulKey)
{
	ulKey = *((QWORD*)((PNODEOPT)pVPtr) -> nKey);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, LPTSTR& szData, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::GetData(PVOID pVPtr, LPTSTR& szData)
{
	szData = (LPTSTR&)(((PNODEOPT)pVPtr) -> nData);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CQ2S::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	return true;
}
