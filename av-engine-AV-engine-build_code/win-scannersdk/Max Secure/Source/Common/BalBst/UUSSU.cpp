
/*======================================================================================
FILE             : UUSSU.cpp
ABSTRACT         : define 4 level tree class to handle database type of 
					ulong -> ulong -> string -> string -> ulong
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
				  
CREATION DATE    : 6/10/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "UUSSU.h"

BYTE HEADER_UUSSU[24]		= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_UUSSU_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CUUSSU
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CUUSSU::CUUSSU(bool bIsEmbedded): CBalBST(bIsEmbedded)
{
	m_bLoadError = false;
	m_bSaveError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CUUSSU
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CUUSSU::~CUUSSU()
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
COMPARE_RESULT CUUSSU::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
{
	if(dwKey1 < dwKey2)
	{
		return (SMALL);
	}
	else if(dwKey1 > dwKey2)
	{
		return (LARGE);
	}
	else
	{
		return (EQUAL);
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeKey
In Parameters  : ULONG64 dwKey, 
Out Parameters : void 
Description    : release key memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CUUSSU::FreeKey(ULONG64 dwKey)
{
	return;
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : ULONG64 dwData, 
Out Parameters : void 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CUUSSU::FreeData(ULONG64 dwData)
{
	CU2OS2O objU2OS2O(false);
	objU2OS2O.SetDataPtr((PNODE)dwData, m_pBuffer, m_nBufferSize);
	objU2OS2O.RemoveAll ();
	return;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : DWORD dwKey, CU2OS2O * pU2OS2O, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::AppendItemAscOrder(DWORD dwKey, CU2OS2O * pU2OS2O)
{
	return (AddNodeAscOrder(dwKey,(ULONG64)pU2OS2O->GetDataPtr()));
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : DWORD dwKey, CU2OS2O * pU2OS2O, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::AppendItem(DWORD dwKey, CU2OS2O * pU2OS2O)
{
	return (AddNode(dwKey,(ULONG64)pU2OS2O->GetDataPtr()));
}

/*--------------------------------------------------------------------------------------
Function       : DeleteItem
In Parameters  : DWORD dwKey, 
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::DeleteItem(DWORD dwKey)
{
	return (DeleteNode((ULONG64)dwKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : DWORD dwKey, CU2OS2O& objU2OS2O, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::SearchItem(DWORD dwKey, CU2OS2O& objU2OS2O)
{
	ULONG64 dwData = 0;

	if(!FindNode(dwKey, dwData))
	{
		return (false);
	}

	objU2OS2O.SetDataPtr((PNODE)dwData, m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateItem
In Parameters  : DWORD dwKey, CU2OS2O& objU2OS2O, 
Out Parameters : bool 
Description    : overwrite the data of the given key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::UpdateItem(DWORD dwKey, CU2OS2O& objU2OS2O)
{
	if(!m_pLastSearchResult || m_pLastSearchResult->dwKey !=(ULONG64)dwKey)
	{
		ULONG64 dwData = 0;

		if(!FindNode((ULONG64)dwKey, dwData))
		{
			return (false);
		}

		if(!m_pLastSearchResult || m_pLastSearchResult->dwKey !=(ULONG64)dwKey)
		{
			return (false);
		}
	}

	m_pLastSearchResult->dwData =(ULONG64)objU2OS2O.GetDataPtr();
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, DWORD& dwKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::GetKey(PVOID pVPtr, DWORD& dwKey)
{
	dwKey =(DWORD)((PNODE)pVPtr) -> dwKey;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, CU2OS2O& objU2OS2O, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::GetData(PVOID pVPtr, CU2OS2O& objU2OS2O)
{
	objU2OS2O.SetDataPtr((PNODE)(((PNODE)pVPtr) -> dwData), m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : bool 
Description    : balance all level trees
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::Balance()
{
	LPVOID Position = NULL;

	CBalBST::Balance();

	Position = GetFirst();
	while(Position)
	{
		CU2OS2O objU2OS2O(true);
		GetData(Position, objU2OS2O);
		objU2OS2O.Balance();
		((PNODE)Position) -> dwData =(ULONG64)objU2OS2O.GetDataPtr();
		Position = GetNext(Position);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : MakeDuplicate
In Parameters  : CS2U& objS2UDst, CS2U& objS2USrc, 
Out Parameters : bool 
Description    : make a new copy of CS2U object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::MakeDuplicate(CS2U& objS2UDst, CS2U& objS2USrc)
{
	LPVOID lpContext = 0;
	LPTSTR szKey = NULL;
	DWORD dwData = 0;

	lpContext = objS2USrc.GetFirst();
	while(lpContext)
	{
		objS2USrc.GetKey(lpContext, szKey);
		objS2USrc.GetData(lpContext, dwData);

		objS2UDst.AppendItem(szKey, dwData);

		lpContext = objS2USrc.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : MakeDuplicate
In Parameters  : CS2OS2U& objS2OS2UDst, CS2OS2U& objS2OS2USrc, 
Out Parameters : bool 
Description    : make a new copy of CS2OS2U object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::MakeDuplicate(CS2OS2U& objS2OS2UDst, CS2OS2U& objS2OS2USrc)
{
	LPVOID lpContext = 0;
	LPCTSTR szKey = NULL;
	CS2U objS2U(true);
	CS2U objS2UDup(true);

	lpContext = objS2OS2USrc.GetFirst();
	while(lpContext)
	{
		szKey = NULL;
		objS2U.RemoveAll();
		objS2UDup.RemoveAll();

		objS2OS2USrc.GetKey(lpContext, szKey);
		objS2OS2USrc.GetData(lpContext, objS2U);

		if(MakeDuplicate(objS2UDup, objS2U))
		{
			objS2OS2UDst.AppendItem(szKey, &objS2UDup);
		}

		lpContext = objS2OS2USrc.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : MakeDuplicate
In Parameters  : CU2OS2O& objU2OS2ODst, CU2OS2O& objU2OS2OSrc, 
Out Parameters : bool 
Description    : make a new copy of this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::MakeDuplicate(CU2OS2O& objU2OS2ODst, CU2OS2O& objU2OS2OSrc)
{
	LPVOID lpContext = NULL;
	DWORD dwKey = 0;
	CS2OS2U objS2OS2U(true);
	CS2OS2U objS2OS2UDup(true);

	lpContext = objU2OS2OSrc.GetFirst();
	while(lpContext)
	{
		dwKey = 0;
		objS2OS2U.RemoveAll();
		objS2OS2UDup.RemoveAll();

		objU2OS2OSrc.GetKey(lpContext, dwKey);
		objU2OS2OSrc.GetData(lpContext, objS2OS2U);

		if(MakeDuplicate(objS2OS2UDup, objS2OS2U))
		{
			objU2OS2ODst.AppendItem(dwKey, &objS2OS2UDup);
		}

		lpContext = objU2OS2OSrc.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBST& objToAdd, 
Out Parameters : bool 
Description    : merge an object to this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::AppendObject(CBalBST& objToAdd)
{
	DWORD dwTempL1Key = 0, dwTempL2Key = 0;
	LPCTSTR szTempL3Key = NULL;
	LPTSTR szTempL4Key = NULL;
	LPVOID lpTempL1 = NULL, lpTempL2 = NULL, lpTempL3 = NULL, lpTempL4 = NULL;

	DWORD dwTempDWORD = 0;
	CS2U objTempS2U(true), objMainS2U(true);
	CS2OS2U objTempS2OS2U(true), objMainS2OS2U(true);
	CU2OS2O objTempU2OS2O(true), objMainU2OS2O(true);
	CUUSSU& objTempUUSSU =(CUUSSU&)objToAdd;

	lpTempL1 = objTempUUSSU.GetFirst();
	while(lpTempL1)
	{
		dwTempL1Key = 0;
		objMainU2OS2O.RemoveAll();
		objTempU2OS2O.RemoveAll();

		objTempUUSSU.GetKey(lpTempL1, dwTempL1Key);
		objTempUUSSU.GetData(lpTempL1, objTempU2OS2O);

		if(SearchItem(dwTempL1Key, objMainU2OS2O))
		{
			lpTempL2 = objTempU2OS2O.GetFirst();
			while(lpTempL2)
			{
				dwTempL2Key = 0;
				objMainS2OS2U.RemoveAll();
				objTempS2OS2U.RemoveAll();

				objTempU2OS2O.GetKey(lpTempL2, dwTempL2Key);
				objTempU2OS2O.GetData(lpTempL2, objTempS2OS2U);

				if(objMainU2OS2O.SearchItem(dwTempL2Key, objMainS2OS2U))
				{
					lpTempL3 = objTempS2OS2U.GetFirst();
					while(lpTempL3)
					{
						szTempL3Key = NULL;
						objTempS2U.RemoveAll();
						objMainS2U.RemoveAll();

						objTempS2OS2U.GetKey(lpTempL3, szTempL3Key);
						objTempS2OS2U.GetData(lpTempL3, objTempS2U);

						if(objMainS2OS2U.SearchItem(szTempL3Key, objMainS2U))
						{
							lpTempL4 = objTempS2U.GetFirst();
							while(lpTempL4)
							{
								szTempL4Key = NULL;
								dwTempDWORD = 0;

								objTempS2U.GetKey(lpTempL4, szTempL4Key);
								objTempS2U.GetData(lpTempL4, dwTempDWORD);

								if(objMainS2U.AppendItem(szTempL4Key, dwTempDWORD))
								{
									SetModified();
								}

								lpTempL4 = objTempS2U.GetNext(lpTempL4);
							}
						}
						else
						{
							CS2U objTempS2UDup(true);
							if(MakeDuplicate(objTempS2UDup, objTempS2U))
							{
								if(objMainS2OS2U.AppendItem(szTempL3Key, &objTempS2UDup))
								{
									SetModified();
								}
							}
						}

						lpTempL3 = objTempS2OS2U.GetNext(lpTempL3);
					}
				}
				else
				{
					CS2OS2U objTempS2OS2UDup(true);
					if(MakeDuplicate(objTempS2OS2UDup, objTempS2OS2U))
					{
						if(objMainU2OS2O.AppendItem(dwTempL2Key, &objTempS2OS2UDup))
						{
							SetModified();
						}
					}
				}

				lpTempL2 = objMainU2OS2O.GetNext(lpTempL2);
			}
		}
		else
		{
			CU2OS2O objTempU2OS2ODup(true);
			if(MakeDuplicate(objTempU2OS2ODup, objTempU2OS2O))
			{			
				if(AppendItem(dwTempL1Key, &objTempU2OS2ODup))
				{
					SetModified();
				}
			}
		}

		lpTempL1 = objTempUUSSU.GetNext(lpTempL1);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& objToDel, 
Out Parameters : bool 
Description    : delete an object from this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::DeleteObject(CBalBST& objToDel)
{
	DWORD dwTempL1Key = 0, dwTempL2Key = 0;
	LPCTSTR szTempL3Key = NULL;
	LPTSTR szTempL4Key = NULL;
	LPVOID lpTempL1 = NULL, lpTempL2 = NULL, lpTempL3 = NULL, lpTempL4 = NULL;

	CS2U objTempS2U(true), objMainS2U(true);
	CS2OS2U objTempS2OS2U(true), objMainS2OS2U(true);
	CU2OS2O objTempU2OS2O(true), objMainU2OS2O(true);
	CUUSSU& objTempUUSSU =(CUUSSU&)objToDel;

	lpTempL1 = objTempUUSSU.GetFirst();
	while(lpTempL1)
	{
		dwTempL1Key = 0;
		objTempUUSSU.GetKey(lpTempL1, dwTempL1Key);

		objMainU2OS2O.RemoveAll();
		if(SearchItem(dwTempL1Key, objMainU2OS2O))
		{
			objTempU2OS2O.RemoveAll();
			objTempUUSSU.GetData(lpTempL1, objTempU2OS2O);

			lpTempL2 = objTempU2OS2O.GetFirst();
			while(lpTempL2)
			{
				dwTempL2Key = 0;
				objTempU2OS2O.GetKey(lpTempL2, dwTempL2Key);

				objMainS2OS2U.RemoveAll();
				if(objMainU2OS2O.SearchItem(dwTempL2Key, objMainS2OS2U))
				{
					objTempS2OS2U.RemoveAll();
					objTempU2OS2O.GetData(lpTempL2, objTempS2OS2U);

					lpTempL3 = objTempS2OS2U.GetFirst();
					while(lpTempL3)
					{
						szTempL3Key = NULL;
						objTempS2OS2U.GetKey(lpTempL3, szTempL3Key);

						objMainS2U.RemoveAll();
						if(objMainS2OS2U.SearchItem(szTempL3Key, objMainS2U))
						{
							objTempS2U.RemoveAll();
							objTempS2OS2U.GetData(lpTempL3, objTempS2U);

							lpTempL4 = objTempS2U.GetFirst();
							while(lpTempL4)
							{
								szTempL4Key = NULL;
								objTempS2U.GetKey(lpTempL4, szTempL4Key);
								if(objMainS2U.DeleteItem(szTempL4Key))
								{
									SetModified();
								}

								lpTempL4 = objTempS2U.GetNext(lpTempL4);
							}

							objMainS2OS2U.UpdateItem(szTempL3Key, objMainS2U);
							if(!objMainS2U.GetFirst())
							{
								if(objMainS2OS2U.DeleteItem(szTempL3Key))
								{
									SetModified();
								}
							}
						}

						lpTempL3 = objTempS2OS2U.GetNext(lpTempL3);
					}

					objMainU2OS2O.UpdateItem(dwTempL2Key, objMainS2OS2U);
					if(!objMainS2OS2U.GetFirst())
					{
						if(objMainU2OS2O.DeleteItem(dwTempL2Key))
						{
							SetModified();
						}
					}
				}

				lpTempL2 = objTempU2OS2O.GetNext(lpTempL2);
			}

			UpdateItem(dwTempL1Key, objMainU2OS2O);
			if(!objMainU2OS2O.GetFirst())
			{
				if(DeleteItem(dwTempL1Key))
				{
					SetModified();
				}
			}
		}

		lpTempL1 = objTempUUSSU.GetNext(lpTempL1);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : SearchObject
In Parameters  : CBalBST& objToSearch, bool bAllPresent
Out Parameters : bool
Description    : search all entries in 'objToSearch'
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::SearchObject(CBalBST& objToSearch, bool bAllPresent)
{
	LPTSTR lpKey4 = NULL;
	LPCTSTR lpKey3 = NULL;
	bool bSuccess = true, bFound = false;
	DWORD dwKey1 = 0, dwKey2 = 0, dwData = 0;
	CS2U objSearch4(true), objThis4(true);
	CS2OS2U objSearch3(true), objThis3(true);
	CU2OS2O objSearch2(true), objThis2(true);
	CUUSSU& objSearch1 = (CUUSSU&)objToSearch;
	LPVOID lpContext1 = NULL, lpContext2 = NULL, lpContext3 = NULL, lpContext4 = NULL;

	lpContext1 = objSearch1.GetFirst();
	while(bSuccess && lpContext1)
	{
		objSearch1.GetKey(lpContext1, dwKey1);
		objSearch1.GetData(lpContext1, objSearch2);

		if(SearchItem(dwKey1, objThis2))
		{
			lpContext2 = objSearch2.GetFirst();
			while(bSuccess && lpContext2)
			{
				objSearch2.GetKey(lpContext2, dwKey2);
				objSearch2.GetData(lpContext2, objSearch3);

				if(objThis2.SearchItem(dwKey2, objThis3))
				{
					lpContext3 = objSearch3.GetFirst();
					while(bSuccess && lpContext3)
					{
						objSearch3.GetKey(lpContext3, lpKey3);
						objSearch3.GetData(lpContext3, objSearch4);

						if(objThis3.SearchItem(lpKey3, objThis4))
						{
							lpContext4 = objSearch4.GetFirst();
							while(bSuccess && lpContext4)
							{
								objSearch4.GetKey(lpContext4, lpKey4);

								bFound = objThis4.SearchItem(lpKey4, &dwData);
								if((bFound && !bAllPresent) || (!bFound && bAllPresent))
								{
									bSuccess = false;
								}

								lpContext4 = objSearch4.GetNext(lpContext4);
							}
						}
						else
						{
							bSuccess = bAllPresent?false:bSuccess;
						}

						lpContext3 = objSearch3.GetNext(lpContext3);
					}
				}
				else
				{
					bSuccess = bAllPresent?false:bSuccess;
				}

				lpContext2 = objSearch2.GetNext(lpContext2);
			}
		}
		else
		{
			bSuccess = bAllPresent?false:bSuccess;
		}

		lpContext1 = objSearch1.GetNext(lpContext1);
	}

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : ReadS2U
In Parameters  : ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize, 
Out Parameters : DWORD 
Description    : read s2u node from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CUUSSU::ReadS2U(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize)
{
	DWORD dwBytesProcessed = 0;
	DWORD dwDataSize = 0;
	TCHAR * pString = 0;

	dwDataSize =(DWORD)*pCurrentPtr;
	pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + 4);
	dwBytesProcessed += 4;

	while(dwBytesProcessed < dwDataSize)
	{
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += SIZE_OF_NODE;
		pString = (TCHAR*)pCurrentPtr;
		while(*pString)
		{
			pString++;
			dwBytesProcessed += sizeof(TCHAR);
		}

		pString++;
		dwBytesProcessed += sizeof(TCHAR);

		pCurrentPtr = (ULONG64*)pString;
	}

	return (dwDataSize);

ERROR_EXIT:

	m_bLoadError = true;
	return (0);
}

/*--------------------------------------------------------------------------------------
Function       : ReadS2O
In Parameters  : ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize, 
Out Parameters : DWORD 
Description    : read s2o node from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CUUSSU::ReadS2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize)
{
	DWORD dwBytesProcessed = 0;
	DWORD dwDataSize = 0;
	TCHAR * pStr = NULL;

	dwDataSize =(DWORD)*pCurrentPtr;
	pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + 4);
	dwBytesProcessed += 4;

	while(dwBytesProcessed < dwDataSize)
	{
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += sizeof(*pCurrentPtr)* 6;

		pStr =(TCHAR*)pCurrentPtr;
		while(*pStr)
		{
			pStr++;
			dwBytesProcessed += sizeof(TCHAR);
		}

		pStr++;
		dwBytesProcessed += sizeof(TCHAR);
		pCurrentPtr =(ULONG64*)pStr;
		dwBytesProcessed += ReadS2U(pCurrentPtr, dwBaseAddress, dwFileSize);
		if(m_bLoadError)
		{
			goto ERROR_EXIT;
		}
	}

	return (dwBytesProcessed);

ERROR_EXIT:

	m_bLoadError = true;
	return (0);
}

/*--------------------------------------------------------------------------------------
Function       : ReadU2O
In Parameters  : ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize, 
Out Parameters : DWORD 
Description    : read u2o node from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CUUSSU::ReadU2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize)
{
	DWORD dwEmbeddedDataSize = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwDataSize = 0;

	dwDataSize =(DWORD)*pCurrentPtr;
	pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + 4);
	dwBytesProcessed += 4;

	while(dwBytesProcessed < dwDataSize)
	{
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += SIZE_OF_NODE;

		dwEmbeddedDataSize =(DWORD)*pCurrentPtr;

		ReadS2O(pCurrentPtr, dwBaseAddress, dwFileSize);
		if(m_bLoadError)
		{
			goto ERROR_EXIT;
		}

		dwBytesProcessed += dwEmbeddedDataSize;
	}

	return (dwBytesProcessed);

ERROR_EXIT:

	m_bLoadError = true;
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	DWORD dwEmbeddedDataSize = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_UUSSU)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_UUSSU_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_UUSSU_DATA)] ={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(FALSE == ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_UUSSU, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderDataCalculated, sizeof(byHeaderDataCalculated)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		goto ERROR_EXIT;
	}

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_UUSSU) + sizeof(HEADER_UUSSU_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_UUSSU) + sizeof(HEADER_UUSSU_DATA);
	m_pBuffer =(BYTE*)Allocate(dwFileSize);
	if(NULL == m_pBuffer)
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, m_pBuffer, dwFileSize, &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(dwFileSize != dwBytesRead)
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	hFile = NULL;
	CryptBuffer(m_pBuffer, dwFileSize);

	dwBaseAddress =(ULONG64)m_pBuffer;
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_UUSSU_DATA);
	pCurrentPtr =(ULONG64*)m_pBuffer;
	m_pRoot =(NODE*)m_pBuffer;
	m_bLoadError = false;

	while(dwBytesProcessed < dwFileSize)
	{
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += SIZE_OF_NODE;

		dwEmbeddedDataSize =(DWORD)*pCurrentPtr;

		ReadU2O(pCurrentPtr, dwBaseAddress, dwFileSize);
		if(m_bLoadError)
		{
			goto ERROR_EXIT;
		}

		dwBytesProcessed += dwEmbeddedDataSize;
	}

	Balance();
	m_nBufferSize = dwFileSize;
	m_bLoadedFromFile = true;
	return (true);

ERROR_EXIT:
	if(hFile != INVALID_HANDLE_VALUE && hFile != NULL)
	{
		CloseHandle(hFile);
	}

	m_pRoot = m_pTemp = NULL;
	if(m_pBuffer)
	{
		Release((LPVOID&)m_pBuffer);
	}

	m_bLoadedFromFile = false;
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : DumpS2U
In Parameters  : HANDLE hFile, ULONG64 dwData, 
Out Parameters : DWORD 
Description    : write s2u node to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CUUSSU::DumpS2U(HANDLE hFile, ULONG64 dwData)
{
	ULONG64 dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	DWORD dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwTotalBytesWritten = 0;
	DWORD dwTotalBytesOffset = 0;
	NODE * pNode =(NODE *)dwData;

	dwTotalBytesOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	WriteFile(hFile, &dwTotalBytesWritten, 4, &dwBytesWritten, 0);
	dwTotalBytesWritten += dwBytesWritten;

	while(pNode)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		dwLinkOffset = dwNodeOffset + sizeof(NODE);
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile, ((BYTE*)pNode) + SIZE_OF_ONE_NODE_ELEMENT, SIZE_OF_ONE_NODE_ELEMENT * 4, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset = pNode->pParent ? pNode->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset =(_tcslen((TCHAR*)(pNode->dwKey)) + 1)* sizeof(TCHAR);
		if(!WriteFile(hFile, (LPVOID)pNode->dwKey,(DWORD)dwLinkOffset, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		pNode->dwHold = dwNodeOffset;
		dwLinkOffset = 0;

		if(pNode->pLeft)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 3);
			pNode = pNode->pLeft;
		}
		else if(pNode->pRight)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 4);
			pNode = pNode->pRight;
		}
		else
		{
			while(pNode)
			{
				if(NULL == pNode->pParent)
				{
					pNode = NULL;
				}
				else if(pNode == pNode->pParent->pRight)
				{
					pNode = pNode->pParent;
				}
				else if(pNode->pParent->pRight)
				{
					dwLinkOffset = pNode->pParent->dwHold +(SIZE_OF_ONE_NODE_ELEMENT * 4);
					pNode = pNode->pParent->pRight;
					break;
				}
				else
				{
					pNode = pNode->pParent;
				}
			}
		}

		if(dwLinkOffset)
		{
			dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
			SetFilePointer(hFile,(DWORD)dwLinkOffset, 0, FILE_BEGIN);
			if(!WriteFile(hFile, &dwCurrentOffset, sizeof(dwCurrentOffset), &dwBytesWritten, 0))
			{
				m_bLoadError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bLoadError)
	{
		return (0);
	}

	dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	SetFilePointer(hFile, dwTotalBytesOffset, 0, FILE_BEGIN);
	if(!WriteFile(hFile, &dwTotalBytesWritten, sizeof(dwTotalBytesWritten), &dwBytesWritten, 0))
	{
		m_bLoadError = true;
		return (0);
	}

	SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
	return (dwTotalBytesWritten);
}

/*--------------------------------------------------------------------------------------
Function       : DumpS2O
In Parameters  : HANDLE hFile, ULONG64 dwData, 
Out Parameters : DWORD 
Description    : write s2o node to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CUUSSU::DumpS2O(HANDLE hFile, ULONG64 dwData)
{
	DWORD dwDataSize = 0;
	ULONG64 dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	DWORD dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwTotalBytesWritten = 0;
	DWORD dwTotalBytesOffset = 0;
	NODE * pNode =(NODE *)dwData;

	dwTotalBytesOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	WriteFile(hFile, &dwTotalBytesWritten, 4, &dwBytesWritten, 0);
	dwTotalBytesWritten += dwBytesWritten;

	while(pNode)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		dwLinkOffset = dwNodeOffset + sizeof(NODE);
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwDataSize =(DWORD)(_tcslen((TCHAR*)pNode->dwKey) + 1)* sizeof(TCHAR);
		dwLinkOffset = dwNodeOffset + sizeof(NODE) + dwDataSize + 4;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile, ((BYTE*)pNode) +(SIZE_OF_ONE_NODE_ELEMENT * 2), SIZE_OF_ONE_NODE_ELEMENT * 3, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset = pNode->pParent ? pNode->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile,(TCHAR *)pNode->dwKey, dwDataSize, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;

		dwTotalBytesWritten += DumpS2U(hFile, pNode->dwData);
		if(m_bLoadError)
		{
			break;
		}

		pNode->dwHold = dwNodeOffset;
		dwLinkOffset = 0;

		if(pNode->pLeft)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 3);
			pNode = pNode->pLeft;
		}
		else if(pNode->pRight)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 4);
			pNode = pNode->pRight;
		}
		else
		{
			while(pNode)
			{
				if(NULL == pNode->pParent)
				{
					pNode = NULL;
				}
				else if(pNode == pNode->pParent->pRight)
				{
					pNode = pNode->pParent;
				}
				else if(pNode->pParent->pRight)
				{
					dwLinkOffset = pNode->pParent->dwHold +(SIZE_OF_ONE_NODE_ELEMENT * 4);
					pNode = pNode->pParent->pRight;
					break;
				}
				else
				{
					pNode = pNode->pParent;
				}
			}
		}

		if(dwLinkOffset)
		{
			dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
			SetFilePointer(hFile,(DWORD)dwLinkOffset, 0, FILE_BEGIN);
			if(!WriteFile(hFile, &dwCurrentOffset, sizeof(dwCurrentOffset), &dwBytesWritten, 0))
			{
				m_bLoadError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bLoadError)
	{
		return (0);
	}

	dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	SetFilePointer(hFile, dwTotalBytesOffset, 0, FILE_BEGIN);
	if(!WriteFile(hFile, &dwTotalBytesWritten, sizeof(dwTotalBytesWritten), &dwBytesWritten, 0))
	{
		m_bLoadError = true;
		return (0);
	}

	SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
	return (dwTotalBytesWritten);
}

/*--------------------------------------------------------------------------------------
Function       : DumpU2O
In Parameters  : HANDLE hFile, ULONG64 dwData, 
Out Parameters : DWORD 
Description    : write u2o node to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CUUSSU::DumpU2O(HANDLE hFile, ULONG64 dwData)
{
	ULONG64 dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	DWORD dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwTotalBytesWritten = 0;
	DWORD dwTotalBytesOffset = 0;
	NODE * pNode =(NODE *)dwData;

	dwTotalBytesOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	WriteFile(hFile, &dwTotalBytesWritten, 4, &dwBytesWritten, 0);
	dwTotalBytesWritten += dwBytesWritten;

	while(pNode)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		dwLinkOffset = dwNodeOffset + sizeof(NODE) + 4;
		if(!WriteFile(hFile, pNode, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile, ((LPBYTE)pNode) +(SIZE_OF_ONE_NODE_ELEMENT * 2), SIZE_OF_ONE_NODE_ELEMENT * 3, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset = pNode->pParent ? pNode->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;

		dwTotalBytesWritten += DumpS2O(hFile, pNode->dwData);
		if(m_bLoadError)
		{
			break;
		}

		pNode->dwHold = dwNodeOffset;
		dwLinkOffset = 0;

		if(pNode->pLeft)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 3);
			pNode = pNode->pLeft;
		}
		else if(pNode->pRight)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 4);
			pNode = pNode->pRight;
		}
		else
		{
			while(pNode)
			{
				if(NULL == pNode->pParent)
				{
					pNode = NULL;
				}
				else if(pNode == pNode->pParent->pRight)
				{
					pNode = pNode->pParent;
				}
				else if(pNode->pParent->pRight)
				{
					dwLinkOffset = pNode->pParent->dwHold +(SIZE_OF_ONE_NODE_ELEMENT * 4);
					pNode = pNode->pParent->pRight;
					break;
				}
				else
				{
					pNode = pNode->pParent;
				}
			}
		}

		if(dwLinkOffset)
		{
			dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
			SetFilePointer(hFile,(DWORD)dwLinkOffset, 0, FILE_BEGIN);
			if(!WriteFile(hFile, &dwCurrentOffset, sizeof(dwCurrentOffset), &dwBytesWritten, 0))
			{
				m_bLoadError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bLoadError)
	{
		return (0);
	}

	dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	SetFilePointer(hFile, dwTotalBytesOffset, 0, FILE_BEGIN);
	if(!WriteFile(hFile, &dwTotalBytesWritten, sizeof(dwTotalBytesWritten), &dwBytesWritten, 0))
	{
		m_bLoadError = true;
		return (0);
	}

	SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
	return (dwTotalBytesWritten);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUUSSU::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	ULONG64 dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	ULONG64 dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH]={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_UUSSU) + sizeof(HEADER_UUSSU_DATA), 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	m_bSaveError = false;
	m_pTemp = m_pRoot;

	while(m_pTemp)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		dwLinkOffset = dwNodeOffset + sizeof(NODE) + 4;
		if(!WriteFile(hFile, m_pTemp, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		if(!WriteFile(hFile, ((LPBYTE)m_pTemp) +(SIZE_OF_ONE_NODE_ELEMENT * 2), SIZE_OF_ONE_NODE_ELEMENT * 3, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		dwLinkOffset = m_pTemp->pParent ? m_pTemp->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		DumpU2O(hFile, m_pTemp->dwData);
		if(m_bSaveError)
		{
			break;
		}

		m_pTemp->dwHold = dwNodeOffset;
		dwLinkOffset = 0;

		if(m_pTemp->pLeft)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 3);
			m_pTemp = m_pTemp->pLeft;
		}
		else if(m_pTemp->pRight)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 4);
			m_pTemp = m_pTemp->pRight;
		}
		else
		{
			while(m_pTemp)
			{
				if(NULL == m_pTemp->pParent)
				{
					m_pTemp = NULL;
				}
				else if(m_pTemp == m_pTemp->pParent->pRight)
				{
					m_pTemp = m_pTemp->pParent;
				}
				else if(m_pTemp->pParent->pRight)
				{
					dwLinkOffset = m_pTemp->pParent->dwHold +(SIZE_OF_ONE_NODE_ELEMENT * 4);
					m_pTemp = m_pTemp->pParent->pRight;
					break;
				}
				else
				{
					m_pTemp = m_pTemp->pParent;
				}
			}
		}

		if(dwLinkOffset)
		{
			dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
			SetFilePointer(hFile,(DWORD)dwLinkOffset, 0, FILE_BEGIN);
			if(!WriteFile(hFile, &dwCurrentOffset, sizeof(dwCurrentOffset), &dwBytesWritten, 0))
			{
				m_bSaveError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bSaveError)
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		AddLogEntry(L"Error in saving: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_UUSSU) + sizeof(HEADER_UUSSU_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, HEADER_UUSSU, sizeof(HEADER_UUSSU), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_UUSSU_DATA, sizeof(HEADER_UUSSU_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, HEADER_UUSSU_DATA, sizeof(HEADER_UUSSU_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
