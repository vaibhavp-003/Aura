
/*======================================================================================
FILE             : FileInfo.cpp
ABSTRACT         : defines class to store file information
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
				  
CREATION DATE    : 3/Feb/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "stdafx.h"
#include "FileInfo.h"

BYTE HEADER_FILEINFO[24] = {"MAXDBVERSION00.00.00.08"};

CFileInfo::CFileInfo()
{
	m_byBuffer = NULL;
	m_cbBuffer = 0;
	m_nNodesCount = 0;
	m_pHead = m_pTemp = m_pTraverse = NULL;
}

CFileInfo::~CFileInfo()
{
	RemoveAll();
}

void CFileInfo::RemoveAll()
{
	while(m_pHead)
	{
		m_pTemp = m_pHead->pNext;

		if(m_pHead->szCompanyName)
		{
			if((LPBYTE)m_pHead->szCompanyName < m_byBuffer ||(LPBYTE)m_pHead->szCompanyName >= m_byBuffer + m_cbBuffer)
			{
				Release((LPVOID&)m_pHead->szCompanyName);
			}
		}

		if(m_pHead->szDescription)
		{
			if((LPBYTE)m_pHead->szDescription < m_byBuffer ||(LPBYTE)m_pHead->szDescription >= m_byBuffer + m_cbBuffer)
			{
				Release((LPVOID&)m_pHead->szDescription);
			}
		}

		if(m_pHead->szFullFilePath)
		{
			if((LPBYTE)m_pHead->szFullFilePath < m_byBuffer ||(LPBYTE)m_pHead->szFullFilePath >= m_byBuffer + m_cbBuffer)
			{
				Release((LPVOID&)m_pHead->szFullFilePath);
			}
		}

		if(m_pHead->szProductName)
		{
			if((LPBYTE)m_pHead->szProductName < m_byBuffer ||(LPBYTE)m_pHead->szProductName >= m_byBuffer + m_cbBuffer)
			{
				Release((LPVOID&)m_pHead->szProductName);
			}
		}

		if(m_pHead->szVersionNo)
		{
			if((LPBYTE)m_pHead->szVersionNo < m_byBuffer ||(LPBYTE)m_pHead->szVersionNo >= m_byBuffer + m_cbBuffer)
			{
				Release((LPVOID&)m_pHead->szVersionNo);
			}
		}

		if((LPBYTE)m_pHead < m_byBuffer ||(LPBYTE)m_pHead >= m_byBuffer + m_cbBuffer)
		{
			Release((LPVOID&)m_pHead);
		}

		m_pHead = m_pTemp;
	}

	if(m_byBuffer)
	{
		Release((LPVOID&)m_byBuffer);
	}

	m_byBuffer = NULL;
	m_cbBuffer = 0;
	m_nNodesCount = 0;
	m_pHead = m_pTemp = m_pTraverse = NULL;
}

LPFILE_INFO CFileInfo::GetNode(LPFILE_INFO lpFileInfo)
{
	m_pTemp = (LPFILE_INFO)Allocate(sizeof(FILE_INFO));
	if(NULL == m_pTemp)
	{
		return NULL;
	}

	m_pTemp->ulFilesize = lpFileInfo->ulFilesize;
	m_pTemp->ulPriSig48 = lpFileInfo->ulPriSig48;
	m_pTemp->ulPriSig64 = lpFileInfo->ulPriSig64;
	m_pTemp->ulPriSig = lpFileInfo->ulPriSig;
	m_pTemp->ulSecSig = lpFileInfo->ulSecSig;
	m_pTemp->ulMD5Sig = lpFileInfo->ulMD5Sig;
	m_pTemp->ulMD5Sig15MB = lpFileInfo->ulMD5Sig15MB;
	memcpy(m_pTemp->byMD5Sig, lpFileInfo->byMD5Sig, sizeof(m_pTemp->byMD5Sig));

	m_pTemp->bIsPacked = lpFileInfo->bIsPacked;
	m_pTemp->bUnPackSuccess = lpFileInfo->bUnPackSuccess;
	m_pTemp->bPESigSuccess = lpFileInfo->bPESigSuccess;
	m_pTemp->bHasDigitalSignature = lpFileInfo->bHasDigitalSignature;
	m_pTemp->byTopLevelPacker = lpFileInfo->byTopLevelPacker;
	m_pTemp->byNoOfUnpacks = lpFileInfo->byNoOfUnpacks;

	m_pTemp->szCompanyName = DuplicateString(lpFileInfo->szCompanyName);
	m_pTemp->szVersionNo = DuplicateString(lpFileInfo->szVersionNo);
	m_pTemp->szProductName = DuplicateString(lpFileInfo->szProductName);
	m_pTemp->szDescription = DuplicateString(lpFileInfo->szDescription);
	m_pTemp->szFullFilePath = DuplicateString(lpFileInfo->szFullFilePath);

	if((!m_pTemp->szCompanyName && lpFileInfo->szCompanyName) ||
	   (!m_pTemp->szVersionNo && lpFileInfo->szVersionNo)	  ||
	   (!m_pTemp->szProductName && lpFileInfo->szProductName) ||
	   (!m_pTemp->szDescription && lpFileInfo->szDescription) ||
	   (!m_pTemp->szFullFilePath)
	   )
	{
		if(m_pTemp->szCompanyName)
		{
			Release((LPVOID&)m_pTemp->szCompanyName);
		}

		if(m_pTemp->szVersionNo)
		{
			Release((LPVOID&)m_pTemp->szVersionNo);
		}

		if(m_pTemp->szProductName)
		{
			Release((LPVOID&)m_pTemp->szProductName);
		}
		
		if(m_pTemp->szDescription)
		{
			Release((LPVOID&)m_pTemp->szDescription);
		}

		if(m_pTemp->szFullFilePath)
		{
			Release((LPVOID&)m_pTemp->szFullFilePath);
		}

		Release((LPVOID&)m_pTemp);
		return NULL;
	}

	return m_pTemp;
}

bool CFileInfo::Add(LPFILE_INFO lpFileInfo)
{
	m_pTemp = GetNode(lpFileInfo);
	if(NULL == m_pTemp)
	{
		return false;
	}

	m_nNodesCount++;
	m_pTemp->pNext = m_pHead;
	m_pHead = m_pTemp;
	return true;
}

bool CFileInfo::GetFirst(LPFILE_INFO& lpFileInfo)
{
	if(NULL == m_pHead)
	{
		return false;
	}

	m_pTraverse = m_pHead;
	lpFileInfo = m_pHead;
	return true;
}

bool CFileInfo::GetNext(LPFILE_INFO& lpFileInfo)
{
	if(NULL == m_pTraverse->pNext)
	{
		return false;
	}

	m_pTraverse = m_pTraverse->pNext;
	lpFileInfo = m_pTraverse;
	return true;
}

UINT CFileInfo::GetCount()
{
	/*if(m_nNodesCount)
	{
		return m_nNodesCount;
	}*/

	m_nNodesCount = 0;
	for(m_pTemp = m_pHead; m_pTemp; m_pTemp = m_pTemp->pNext)
	{
		m_nNodesCount++;
	}

	return m_nNodesCount;
}

bool CFileInfo::Load(LPCTSTR szFilePath)
{
	HANDLE hFile = 0;
	ULONG64 ulFileSize = 0;
	DWORD dwFileSizeHigh = 0, dwBytesRead = 0, dwBaseAddress = 0, dwBytesProcessed = 0;
	BYTE byHeader[sizeof(HEADER_FILEINFO)] = {0};
	SIZE_T * lpData = 0;
	LPTSTR pString = 0;

	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(!ReadFile(hFile, byHeader, sizeof(HEADER_FILEINFO), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(HEADER_FILEINFO, byHeader, sizeof(HEADER_FILEINFO)))
	{
		goto ERROR_EXIT;
	}

	if(!ReadFile(hFile, &m_nNodesCount, sizeof(m_nNodesCount), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	ulFileSize = GetFileSize(hFile, &dwFileSizeHigh);
	ulFileSize |= ((ULONG64)dwFileSizeHigh) << 32 ;

	if(ulFileSize <= sizeof(HEADER_FILEINFO) + sizeof(m_nNodesCount))
	{
		CloseHandle(hFile);
		return true;
	}

	if(ulFileSize >= MAXDWORD)
	{
		goto ERROR_EXIT;
	}

	m_cbBuffer = (DWORD)ulFileSize;
	m_cbBuffer = m_cbBuffer - (sizeof(HEADER_FILEINFO) + sizeof(m_nNodesCount));
	m_byBuffer = (LPBYTE) Allocate(m_cbBuffer);
	if(NULL == m_byBuffer)
	{
		goto ERROR_EXIT;
	}

	if(!ReadFile(hFile, m_byBuffer, m_cbBuffer, &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	dwBaseAddress = (DWORD)m_byBuffer;
	dwBaseAddress -= (sizeof(HEADER_FILEINFO) + sizeof(m_nNodesCount));

	m_pHead = m_pTemp = (LPFILE_INFO)m_byBuffer;
	lpData = (SIZE_T*)m_byBuffer;

	while(dwBytesProcessed < m_cbBuffer)
	{
		lpData = (SIZE_T*)(((LPBYTE)lpData) + SIZE_OF_NON_POINTER_DATA_FILE_INFO);

		CHECK_AND_MAKE_POINTER(lpData, dwBaseAddress, m_byBuffer, m_cbBuffer);
		CHECK_AND_MAKE_POINTER(lpData, dwBaseAddress, m_byBuffer, m_cbBuffer);
		CHECK_AND_MAKE_POINTER(lpData, dwBaseAddress, m_byBuffer, m_cbBuffer);
		CHECK_AND_MAKE_POINTER(lpData, dwBaseAddress, m_byBuffer, m_cbBuffer);
		CHECK_AND_MAKE_POINTER(lpData, dwBaseAddress, m_byBuffer, m_cbBuffer);
		CHECK_AND_MAKE_POINTER(lpData, dwBaseAddress, m_byBuffer, m_cbBuffer);

		dwBytesProcessed += sizeof(FILE_INFO);

		if(m_pTemp->szVersionNo)
		{
			pString = (LPTSTR)lpData;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			lpData =(SIZE_T*)pString;
		}

		if(m_pTemp->szCompanyName)
		{
			pString = (LPTSTR)lpData;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			lpData = (SIZE_T*)pString;
		}

		if(m_pTemp->szProductName)
		{
			pString = (LPTSTR)lpData;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			lpData = (SIZE_T*)pString;
		}

		if(m_pTemp->szDescription)
		{
			pString = (LPTSTR)lpData;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			lpData = (SIZE_T*)pString;
		}

		if(m_pTemp->szFullFilePath)
		{
			pString = (LPTSTR)lpData;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			lpData = (SIZE_T*)pString;
		}

		m_pTemp = m_pTemp->pNext ? m_pTemp->pNext : m_pTemp;
	}

	CloseHandle(hFile);
	return true;

ERROR_EXIT:

	if(0 != hFile && INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = 0;
	}

	return false;
}

bool CFileInfo::Save(LPCTSTR szFilePath)
{
	bool bWriteError = false;
	HANDLE hFile = 0;
	DWORD dwBytesWritten = 0, dwNodeOffset = 0;
	DWORD dwLinkOffset = 0;
	UINT nCount = 0;
	UINT ulVersionNo = 0, ulCompanyName = 0, ulProductName = 0, ulDescription = 0, ulFullFilePath = 0;

	hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(!WriteFile(hFile, HEADER_FILEINFO, sizeof(HEADER_FILEINFO), &dwBytesWritten, 0))
	{
		goto ERROR_EXIT;
	}

	nCount = GetCount();
	if(!WriteFile(hFile, &nCount, sizeof(nCount), &dwBytesWritten, 0))
	{
		goto ERROR_EXIT;
	}

	for(m_pTemp = m_pHead; m_pTemp; m_pTemp = m_pTemp->pNext)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		if(INVALID_SET_FILE_POINTER == dwNodeOffset)
		{
			bWriteError = true;
			break;
		}

		ulVersionNo = m_pTemp->szVersionNo ? UINT(_tcslen(m_pTemp->szVersionNo) + 1) * sizeof(TCHAR) : 0;
		ulCompanyName = m_pTemp->szCompanyName ? UINT(_tcslen(m_pTemp->szCompanyName) + 1) * sizeof(TCHAR) : 0;
		ulProductName = m_pTemp->szProductName ? UINT(_tcslen(m_pTemp->szProductName) + 1) * sizeof(TCHAR) : 0;
		ulDescription = m_pTemp->szDescription ? UINT(_tcslen(m_pTemp->szDescription) + 1) * sizeof(TCHAR) : 0;
		ulFullFilePath = m_pTemp->szFullFilePath ? UINT(_tcslen(m_pTemp->szFullFilePath) + 1) * sizeof(TCHAR) : 0;

		if(!WriteFile(hFile, m_pTemp, SIZE_OF_NON_POINTER_DATA_FILE_INFO, &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		dwLinkOffset = m_pTemp->szVersionNo ? dwNodeOffset + sizeof(FILE_INFO): 0;
		if(!WriteFile(hFile, &dwLinkOffset, sizeof(dwLinkOffset), &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		dwLinkOffset = m_pTemp->szCompanyName ? dwNodeOffset + sizeof(FILE_INFO) + ulVersionNo: 0;
		if(!WriteFile(hFile, &dwLinkOffset, sizeof(dwLinkOffset), &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		dwLinkOffset = m_pTemp->szProductName ? dwNodeOffset + sizeof(FILE_INFO) + ulVersionNo + ulCompanyName: 0;
		if(!WriteFile(hFile, &dwLinkOffset, sizeof(dwLinkOffset), &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		dwLinkOffset = m_pTemp->szDescription ? dwNodeOffset + sizeof(FILE_INFO) + ulVersionNo + ulCompanyName + ulProductName : 0;
		if(!WriteFile(hFile, &dwLinkOffset, sizeof(dwLinkOffset), &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		dwLinkOffset = m_pTemp->szFullFilePath ? dwNodeOffset + sizeof(FILE_INFO) + ulVersionNo + ulCompanyName + ulProductName + ulDescription : 0;
		if(!WriteFile(hFile, &dwLinkOffset, sizeof(dwLinkOffset), &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		dwLinkOffset = m_pTemp->pNext ? dwNodeOffset + sizeof(FILE_INFO) + ulVersionNo + ulCompanyName + ulProductName + ulDescription + ulFullFilePath : 0;
		if(!WriteFile(hFile, &dwLinkOffset, sizeof(dwLinkOffset), &dwBytesWritten, 0))
		{
			bWriteError = true;
			break;
		}

		if(ulVersionNo)
		{
			if(!WriteFile(hFile, m_pTemp->szVersionNo, ulVersionNo, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}		
		}

		if(ulCompanyName)
		{
			if(!WriteFile(hFile, m_pTemp->szCompanyName, ulCompanyName, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}		
		}

		if(ulProductName)
		{
			if(!WriteFile(hFile, m_pTemp->szProductName, ulProductName, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}		
		}

		if(ulDescription)
		{
			if(!WriteFile(hFile, m_pTemp->szDescription, ulDescription, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}		
		}

		if(ulFullFilePath)
		{
			if(!WriteFile(hFile, m_pTemp->szFullFilePath, ulFullFilePath, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}		
		}
	}

	if(bWriteError)
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	return true;

ERROR_EXIT:

	if(0 != hFile && INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = 0;
	}

	return false;
}
