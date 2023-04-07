/*=============================================================================
   FILE		           : FileOperations.h
   ABSTRACT		       : This Class perform file / folder related opration
						like DeleteFolderTree,DeleteCache,GetSignature,QurantineBackup
   DOCUMENTS	       : Refer The System Design.doc, System Requirement Document.doc
   AUTHOR		       : Dipali Pawar
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 26-Jan-2006
   NOTES		      : This Class perform file / folder related opration
						like DeleteFolderTree,DeleteCache,GetSignature,QurantineBackup
   VERSION HISTORY    : 
=============================================================================*/
#include "pch.h"
#include "FileOperations.h"

/*--------------------------------------------------------------------------------------
Function       : CFileOperations
In Parameters  :
Out Parameters :
Description    :
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
CFileOperations::CFileOperations()
{

}

/*--------------------------------------------------------------------------------------
Function       : ~CFileOperations
In Parameters  :
Out Parameters :
Description    :
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
CFileOperations::~CFileOperations()
{

}

/*--------------------------------------------------------------------------------------
Function       : CryptData
In Parameters  : DWORD *Data, DWORD dwDataSize, char *key, unsigned long keylen,
Out Parameters : void
Description    :
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
void CFileOperations::CryptData(DWORD *Data, DWORD dwDataSize, char *key, unsigned long keylen)
{
	//we will consider size of sbox 256 bytes
	//(extra byte are only to prevent any mishep just in case)
	DWORD Sbox[257], Sbox2[257];
	unsigned long i, j, t, x;

	//this unsecured key is to be used only when there is no input key from user
	static const DWORD OurUnSecuredKey[] = {0xFFAAFFAA, 0xAAFCAAFC, 0xA37EA37E,
											0xB34EB34E, 0xFFFFFFFF, 0x3BE73BE7,
											0xCBA9CBA9, 0x23C123C1, 0x2E6C2E6C,
											0x13CB13CB, 0x64E764E7, 0x34D234D2};

	static const int OurKeyLen = sizeof(OurUnSecuredKey)/sizeof(OurUnSecuredKey[0]);
	DWORD temp, k;
	temp = i = j = k = t =  x = 0;

	//always initialize the arrays with zero
	memset(Sbox, 0, sizeof(Sbox));
	memset(Sbox2, 0, sizeof(Sbox2));

	//initialize sbox i
	for(i = 0; i < 256U; i++)
	{
		Sbox[i] = (DWORD)0xFFFFFFFF - (DWORD)i;
	}
	j = 0;
	//whether user has sent any inpur key
	if(keylen)
	{
		//initialize the sbox2 with user key
		for(i = 0; i < 256U; i++)
		{
			if(j == keylen)
			{
				j = 0;
			}
			Sbox2[i] = key[j++];
		}
	}
	else
	{
		//initialize the sbox2 with our key
		for(i = 0; i < 256U; i++)
		{
			if(j == OurKeyLen)
			{
				j = 0;
			}
			Sbox2[i] = OurUnSecuredKey[j++];
		}
	}

	j = 0; //Initialize j
	//scramble sbox1 with sbox2
	for(i = 0; i < 256; i++)
	{
		j = (j + (unsigned long)Sbox[i] + (unsigned long)Sbox2[i])% 256U;
		temp =  Sbox[i];
		Sbox[i] = Sbox[j];
		Sbox[j] =  temp;
	}

	i = j = 0;
	for(x = 0; x < dwDataSize; x++)
	{
		//increment i
		i = (i + 1U)% 256U;
		//increment j
		j = (j + (unsigned long)Sbox[i])% 256U;

		//Scramble SBox #1 further so encryption routine will
		//will repeat itself at great interval
		temp = Sbox[i];
		Sbox[i] = Sbox[j];
		Sbox[j] = temp;

		//Get ready to create pseudo random  byte for encryption key
		t = ((unsigned long)Sbox[i] + (unsigned long)Sbox[j])%  256U;

		//get the random byte
		k = Sbox[t];

		//xor with the data and done
		Data[x] = (Data[x] ^ (DWORD)k);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CryptFile
In Parameters  : const TCHAR *csFileName, const TCHAR *csCryptFileName,
Out Parameters : bool
Description    :
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileOperations::CryptFile(const TCHAR *csFileName, const TCHAR *csCryptFileName)
{
	bool bReadError = false;
	BYTE * ReadBuffer = NULL;
	HANDLE hFile = 0, hCryptFile = 0;
	DWORD dwFileSize = 0, dwBytesRead = 0, dwBytesToRead = 0, dwTotalBytesRead = 0;
	DWORD dwReadBufferSize = 1024 * 512, dwRemainingData = 0;

	hFile = CreateFile(csFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	hCryptFile = CreateFile(csCryptFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
							0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return false;
	}

	dwFileSize = GetFileSize(hFile, 0);
	ReadBuffer = new BYTE[dwReadBufferSize];

	dwRemainingData = dwFileSize % 4;
	dwFileSize = dwFileSize - dwRemainingData;

	while(!bReadError && dwTotalBytesRead < dwFileSize)
	{
		if(dwFileSize - dwTotalBytesRead >= dwReadBufferSize)
		{
			dwBytesToRead = dwReadBufferSize;
		}
		else
		{
			dwBytesToRead = dwFileSize - dwTotalBytesRead;
		}

		ReadFile(hFile, ReadBuffer, dwBytesToRead, &dwBytesRead, 0);
		if(dwBytesToRead != dwBytesRead)
		{
			bReadError = true;
		}

		dwTotalBytesRead += dwBytesRead;

		CryptData((DWORD*)ReadBuffer, dwBytesRead / 4);
		WriteFile(hCryptFile, ReadBuffer, dwBytesRead, &dwBytesRead, 0);
	}

	if(dwRemainingData <= 3)
	{
		BYTE Buffer[3] = {0};
		ReadFile(hFile, Buffer, dwRemainingData, &dwBytesRead, 0);
		for(DWORD dwIndex = 0; dwIndex < dwBytesRead; dwIndex++)
		{
			Buffer[dwIndex] ^= (BYTE)141;
		}

		WriteFile(hCryptFile, Buffer, dwBytesRead, &dwBytesRead, 0);
	}

	CloseHandle(hFile);
	CloseHandle(hCryptFile);
	delete [] ReadBuffer;
	ReadBuffer = NULL;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : ProcessDatabase
In Parameters  : LPCWSTR lstrFileName, CObject &objDatabaseMap, bool bSave,
Out Parameters : bool
Description    :
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileOperations::ProcessDatabase(LPCWSTR lstrFileName, CObject &objDatabaseMap, bool bSave)
{
	WCHAR wsTempFileName[MAX_PATH] = {0};
	wcscpy_s(wsTempFileName, MAX_PATH, lstrFileName);
	wcscat_s(wsTempFileName, MAX_PATH, L".tmp");
	if(!bSave)
	{
		if(!CryptFile(lstrFileName, wsTempFileName))
		{
			return false;
		}
	}

	CFile theFile;
	if(!theFile.Open(wsTempFileName, 
		(bSave ? CFile::modeWrite | CFile::modeCreate : CFile::modeRead | CFile::shareDenyNone)))
	{
		return false;
	}
	CArchive archive(&theFile, (bSave ? CArchive::store : CArchive::load));
	objDatabaseMap.Serialize(archive);
	archive.Close();
	theFile.Close();

	if(bSave)
	{
		if(!CryptFile(wsTempFileName, lstrFileName))
		{
			return false;
		}
	}
	::DeleteFile(wsTempFileName);
	return true;
}