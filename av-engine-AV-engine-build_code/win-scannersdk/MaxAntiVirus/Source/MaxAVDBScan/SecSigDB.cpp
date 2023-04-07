/*======================================================================================
   FILE				: SecSigDB.cpp
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
   NOTES			: This module manages the remaining part of signature after first part matches. 
   VERSION HISTORY	: 
=====================================================================================*/
#include "SecSigDB.h"
#include <tchar.h>
#include <stdio.h>

/*-------------------------------------------------------------------------------------
	Function		: CSecSigDB
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CSecSigDB::CSecSigDB(void)
: m_bIsValidSecSigDB(false)
{
	m_hSecDB = INVALID_HANDLE_VALUE;
	m_hSecDBMap = NULL;
	m_pSecDBView = NULL;
	m_bIsValidSecSigDB = false;
	memset(&m_SecDBInfo,0,sizeof(m_SecDBInfo));
	memset(m_szTempDBName,0,sizeof(m_szTempDBName));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CSecSigDB
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for class
--------------------------------------------------------------------------------------*/
CSecSigDB::~CSecSigDB(void)
{
	if (INVALID_HANDLE_VALUE != m_hSecDB)
	{
		CloseHandle(m_hSecDB);
		m_hSecDB = INVALID_HANDLE_VALUE;
	}
	if (NULL != m_hSecDBMap)
	{
		CloseHandle(m_hSecDBMap);
		m_hSecDBMap = NULL;
	}
	m_pSecDBView = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenSecDBFileEx
	In Parameters	: DWORD dwDBSize
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Create File Mapping to store secondary tree
--------------------------------------------------------------------------------------*/
int CSecSigDB::OpenSecDBFileEx(DWORD dwDBSize)
{
	DWORD dwAlignSize = ((dwDBSize + 0x1000 - 1) / 0x1000) * 0x1000;
	
	m_hSecDB = CreateFile(m_szTempDBName,GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
	if (INVALID_HANDLE_VALUE  != m_hSecDB)
	{
		m_hSecDBMap = CreateFileMapping(m_hSecDB, NULL, PAGE_READWRITE, 0x00, dwDBSize, NULL);
		if (NULL != m_hSecDBMap)
		{
			m_pSecDBView = MapViewOfFile(m_hSecDBMap, FILE_MAP_ALL_ACCESS, 0x00, 0x00, dwDBSize);
			SetFilePointer(m_hSecDB,0x00,0x00,FILE_BEGIN);
			return ERR_SUCCESS;
		}
	}
	return ERR_IN_OPENING_FILE;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenSecDB
	In Parameters	: DWORD dwDBSize
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: wrapper function for OpenSecDBFileEx
--------------------------------------------------------------------------------------*/
int CSecSigDB::OpenSecDB(DWORD dwDBSize)
{
	if (OpenSecDBFileEx(dwDBSize) == ERR_SUCCESS)
	{
		m_bIsValidSecSigDB = true;
		return ERR_SUCCESS;
	}
	else
	{
		m_bIsValidSecSigDB = false;
		return ERR_IN_OPENING_FILE;
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: InitSecSigStruct
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Initialize meory for Secondary Tree
--------------------------------------------------------------------------------------*/
int CSecSigDB::InitSecSigStruct(void)
{
	memset(&m_SecDBInfo,0,sizeof(m_SecDBInfo));
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: WriteSecSignature
	In Parameters	: unsigned int iSigID, LPCSTR szSecSig
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Stores signature in Secondary Signature Database
--------------------------------------------------------------------------------------*/
int CSecSigDB::WriteSecSignature(unsigned int iSigID, LPCSTR szSecSig)
{
	char			szSig2Add[MAX_SZ_LEN] = {0};
	unsigned int	iSinID2Add = 0;
	DWORD			dwBytesWritten = 0;

	InitSecSigStruct();
	sprintf_s(szSig2Add,MAX_SEC_SIG_LEN,"%s",szSecSig);
	iSinID2Add = iSigID;

	if (strlen(szSig2Add) == 0 || iSinID2Add == 0 || strlen(szSig2Add) > MAX_SEC_SIG_LEN)
			return ERR_INVALID_INPUT;
	
	m_SecDBInfo.m_iSigID = iSinID2Add;
	sprintf_s(m_SecDBInfo.m_szSecSig,MAX_SEC_SIG_LEN,"%s",szSig2Add);

	if (INVALID_HANDLE_VALUE != m_hSecDB)
	{
		//SetFilePointer(m_hSecDB,0L,NULL,FILE_END);
		WriteFile(m_hSecDB,&m_SecDBInfo,sizeof(m_SecDBInfo),&dwBytesWritten,NULL);
		return ERR_SUCCESS;
	}
	
	return ERR_INVALID_INPUT;
	
}

/*-------------------------------------------------------------------------------------
	Function		: GetSecondarySig
	In Parameters	: unsigned int iSigID
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Retrives Secondary Signature from DB
--------------------------------------------------------------------------------------*/
int CSecSigDB::GetSecondarySig(unsigned int iSigID)
{
	unsigned int	iSecSigID=0;
	DWORD			dwBytesRead=0;	
	
	iSecSigID = iSigID;

	if (m_bIsValidSecSigDB == false)
		return ERR_INVALID_POINTER;

	if (INVALID_HANDLE_VALUE == m_hSecDB)
		return ERR_INVALID_POINTER;

	InitSecSigStruct();
	iSecSigID--;
	if (iSecSigID < 0)
		return ERR_INVALID_INPUT;
	
	SetFilePointer(m_hSecDB,0L,NULL,FILE_BEGIN);
	SetFilePointer(m_hSecDB,(iSecSigID * sizeof(m_SecDBInfo)),NULL,FILE_BEGIN);
	if (ReadFile(m_hSecDB,&m_SecDBInfo,sizeof(m_SecDBInfo),&dwBytesRead,NULL))
	{
		return ERR_SUCCESS;
	}

	return ERR_INVALID_POINTER;
}

/*-------------------------------------------------------------------------------------
	Function		: CloseSecDB
	In Parameters	: unsigned int iSigID
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Clses Secondary Tree
--------------------------------------------------------------------------------------*/
int CSecSigDB::CloseSecDB(void)
{
	if (NULL != m_pSecDBView)
	{
		UnmapViewOfFile(m_pSecDBView);
		m_pSecDBView = NULL;
	}
	if (NULL != m_hSecDBMap)
	{
		CloseHandle(m_hSecDBMap);
		m_hSecDBMap = NULL;
	}
	if (INVALID_HANDLE_VALUE != m_hSecDB)
	{
		CloseHandle(m_hSecDB);
		m_hSecDB = INVALID_HANDLE_VALUE;
	}

	DeleteFile(m_szTempDBName);
	return 0;
}