/*=============================================================================
   FILE			: HardDiskManager.cpp
   DESCRIPTION	: This class provides the functionality to manage the harddisk information
   DOCUMENTS	: 
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 20/09/2006
   NOTES		:
VERSION HISTORY	: 17 Aug 2007, Avinash B : Unicode Supported
============================================================================*/

#include "stdafx.h"
#include "HardDiskManager.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CHardDiskManager ( CONSTRUCTOR )
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This Function Initiailize CHardDiskManager class 
	Author			: 
--------------------------------------------------------------------------------------*/
CHardDiskManager::CHardDiskManager()
{
    // bytes available to caller
	m_uliFreeBytesAvailable.QuadPart     = 0L;
	// bytes on disk
	m_uliTotalNumberOfBytes.QuadPart     = 0L;
	// free bytes on disk
	m_uliTotalNumberOfFreeBytes.QuadPart = 0L;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CHardDiskManager (DESTRUCTOR )
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This Function Destruct CHardDiskManager class 
	Author			: 
--------------------------------------------------------------------------------------*/
CHardDiskManager::~CHardDiskManager()
{
}

/*-------------------------------------------------------------------------------------
	Function		: CheckFreeSpace
	In Parameters	: -
	Out Parameters	: bool  : True if successfully checked for free space on machine 
							  else false
	Purpose			: This Function checks for free memory on local Machine
					  Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
bool CHardDiskManager::CheckFreeSpace(LPCTSTR lpDirectoryName)
{
	if(!GetDiskFreeSpaceEx(lpDirectoryName, &m_uliFreeBytesAvailable, &m_uliTotalNumberOfBytes, &m_uliTotalNumberOfFreeBytes))
		return false;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFreeBytesAvailable
	In Parameters	: -
	Out Parameters	: DWORD64 : Total available freeMemory in Bytes
	Purpose			: This Function obtains Total available free Memory in Bytes on 
					  Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
DWORD64 CHardDiskManager::GetFreeBytesAvailable(void)
{ 

	return m_uliFreeBytesAvailable.QuadPart;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTotalNumberOfBytes
	In Parameters	: -
	Out Parameters	: DWORD64 : Total Memory in Bytes
	Purpose			: This Function obtains Total Memory in Bytes on 
					  Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
DWORD64 CHardDiskManager::GetTotalNumberOfBytes(void)
{ 
	return m_uliTotalNumberOfBytes.QuadPart;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTotalNumberOfFreeBytes
	In Parameters	: -
	Out Parameters	: DWORD64 : Total  Free Memory in Bytes
	Purpose			: This Function obtains Total  Memory in Bytes on 
					  Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
DWORD64 CHardDiskManager::GetTotalNumberOfFreeBytes(void)
{ 
	return m_uliTotalNumberOfFreeBytes.QuadPart;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFreeGBytesAvailable
	In Parameters	: void
	Out Parameters	: double : Total available Free Memory in GB
	Purpose			: This Function obtains Total available Free Memory in GB on Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
double CHardDiskManager::GetFreeGBytesAvailable(void)
{ 
	return (double)( (signed __int64)(m_uliFreeBytesAvailable.QuadPart)/1.0e9 );
}

/*-------------------------------------------------------------------------------------
	Function		: GetTotalNumberOfGBytes
	In Parameters	: void
	Out Parameters	: double : Total Memory in GB
	Purpose			: This Function obtains Total Memory in GB on Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
double CHardDiskManager::GetTotalNumberOfGBytes(void)
{ 
	return (double)( (signed __int64)(m_uliTotalNumberOfBytes.QuadPart)/1.0e9 );     
}

/*-------------------------------------------------------------------------------------
	Function		: GetTotalNumberOfFreeGBytes
	In Parameters	: void
	Out Parameters	: double : Free Memory in GB
	Purpose			: This Function obtains Free Memory in GB on Local machine
	Author			: 
--------------------------------------------------------------------------------------*/
double CHardDiskManager::GetTotalNumberOfFreeGBytes(void)
{ 
	return (double)( (signed __int64)(m_uliTotalNumberOfFreeBytes.QuadPart)/1.0e9 ); 
}
