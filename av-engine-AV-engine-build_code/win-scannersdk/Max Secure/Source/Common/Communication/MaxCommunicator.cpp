/*======================================================================================
FILE             : MaxCommunicator.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 5/14/2009
NOTES		     : Implementation of the Named Pipe client class
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxCommunicator.h"
#include "MaxExceptionFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const int MAX_CONNECT_RETRY = 30;
const int MAX_CONNECT_TIMEOUT = 1000;

/*--------------------------------------------------------------------------------------
Function       : CMaxCommunicator
In Parameters  : const TCHAR* tchPipeName, bool bRetryConnection,
Out Parameters :
Description    : C'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxCommunicator::CMaxCommunicator(const TCHAR* tchPipeName, bool bRetryConnection)
{
	_tcscpy_s(m_tchPipe, tchPipeName);
	m_hPipe = INVALID_HANDLE_VALUE;
	m_bRetryConnection = bRetryConnection;
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxCommunicator
In Parameters  :
Out Parameters :
Description    : C'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxCommunicator::~CMaxCommunicator()
{
	Close();
}

/*--------------------------------------------------------------------------------------
Function       : Close
In Parameters  :
Out Parameters : void
Description    : Closing the client connection
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMaxCommunicator::Close()
{
	__try{
		if(m_hPipe != INVALID_HANDLE_VALUE)
		{
			FlushFileBuffers(m_hPipe);
			DisconnectNamedPipe(m_hPipe);
			CloseHandle(m_hPipe);
			m_hPipe = INVALID_HANDLE_VALUE;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Communicator Close Mode"),false))
	{

	}
}

/*--------------------------------------------------------------------------------------
Function       : Connect
In Parameters  : void,
Out Parameters : bool
Description    : Connecting to the server
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicator::Connect(void)
{
	int nTryCount = 0;
	bool bConnected = false;
	__try{
		do{
			m_hPipe = CreateFile(
				m_tchPipe,		// __in          LPCTSTR lpFileName,
				GENERIC_WRITE | GENERIC_READ,					// __in          DWORD dwDesiredAccess,
				0,								// __in          DWORD dwShareMode,
				NULL,							// __in          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
				OPEN_EXISTING,					// __in          DWORD dwCreationDisposition,
				FILE_ATTRIBUTE_NORMAL,			// DWORD dwFlagsAndAttributes,
				NULL							// __in          HANDLE hTemplateFile
				);

			if(m_hPipe == INVALID_HANDLE_VALUE)
			{
				if(m_bRetryConnection)
				{
					if(nTryCount >= MAX_CONNECT_RETRY)
					{
						m_bRetryConnection = false;
						break;
					}
					nTryCount ++;
					Sleep(MAX_CONNECT_TIMEOUT);
				}
			}
			else
			{
				bConnected = true;
				m_bRetryConnection = false;
			}
		}while ((!bConnected) && m_bRetryConnection);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Communicator Connect Mode")))
	{
		bConnected = false;
	}
	return bConnected;
}

/*--------------------------------------------------------------------------------------
Function       : SendData
In Parameters  : LPVOID lpMaxData, DWORD dwSize,
Out Parameters : bool
Description    : Sending Data to the server using the Max Structures
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicator::SendData(LPVOID lpMaxData, DWORD dwSize)
{
	BOOL bReturn = FALSE;
	__try{
		if(m_hPipe == INVALID_HANDLE_VALUE)
		{
			if(false == Connect())
			{
				return false;
			}
		}

		DWORD nWritten = 0;

		bReturn = WriteFile(
			m_hPipe,			// __in          HANDLE hFile,
			(LPCVOID)lpMaxData,		// __in          LPCVOID lpBuffer,
			dwSize,			// __in          DWORD nNumberOfBytesToWrite,
			&nWritten,		// __out         LPDWORD lpNumberOfBytesWritten,
			NULL				// __in          LPOVERLAPPED lpOverlapped
			);
		if(!bReturn)
		{
			Close();
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Communication SendData")))
	{

	}

	return (bReturn == FALSE ? false : true); 
}

/*--------------------------------------------------------------------------------------
Function       : ReadData
In Parameters  : LPVOID lpMaxData, DWORD dwSize,
Out Parameters : bool
Description    : Getting a response from the server sent using SendResponse
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicator::ReadData(LPVOID lpMaxData, DWORD dwSize)
{
	BOOL bReturn = FALSE;
	__try{
		if(m_hPipe == INVALID_HANDLE_VALUE)
			return false;

		DWORD nRead = 0;

		bReturn = ReadFile(
			m_hPipe,			// __in          HANDLE hFile,
			lpMaxData,		// __in          LPCVOID lpBuffer,
			dwSize,			// __in          DWORD nNumberOfBytesToWrite,
			&nRead,		// __out         LPDWORD lpNumberOfBytesWritten,
			NULL				// __in          LPOVERLAPPED lpOverlapped
			);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Communicator ReadData Mode")))
	{

	}

	return (bReturn == FALSE ? false : true); 
}