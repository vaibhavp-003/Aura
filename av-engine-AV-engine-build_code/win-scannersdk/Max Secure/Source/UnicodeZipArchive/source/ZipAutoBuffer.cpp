/*=============================================================================
   FILE		           : CZipAutoBuffer.cpp
   ABSTRACT		       : implementation of the CZipAutoBuffer class.
   DOCUMENTS	       : 
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 
   NOTES		      : 
   VERSION HISTORY    :
				
=============================================================================*/
#include "stdafx.h"
#include "ZipAutoBuffer.h"
#include <memory.h> 

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipAutoBuffer
	Purpose		   : Constructor for class CZipAutoBuffer
	Author		   : 
-------------------------------------------------------------------------------------*/

CZipAutoBuffer::CZipAutoBuffer()
{
	m_iSize = 0;
	m_pBuffer = NULL;	
}
/*-------------------------------------------------------------------------------------
	Function       : CZipAutoBuffer
	Purpose		   : Copy Constructor for class CZipAutoBuffer
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBuffer::CZipAutoBuffer(DWORD iSize, bool bZeroMemory)
{
	m_iSize = 0;
	m_pBuffer = NULL;
	Allocate(iSize, bZeroMemory);
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipAutoBuffer
	Purpose		   : Destructor for class CZipAutoBuffer
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBuffer::~CZipAutoBuffer()
{
	Release();
}

/*-------------------------------------------------------------------------------------
	Function       : Release
	In Parameters  : 
	Out Parameters : 
	Purpose		   : Release the buffer by Delete
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipAutoBuffer::Release()
{
	if (m_pBuffer)
	{
		delete [] m_pBuffer;
		m_iSize = 0;
		m_pBuffer = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function       : Allocate
	In Parameters  : DWORD iSize, bool bZeroMemory
	Out Parameters : char*
	Purpose		   : Allocate the memory by using new
	Author		   : 
-------------------------------------------------------------------------------------*/
char* CZipAutoBuffer::Allocate(DWORD iSize, bool bZeroMemory)
{
	if (iSize != m_iSize)
		Release();
	else
	{
		if (bZeroMemory)
			memset(m_pBuffer, 0, iSize); // zerowanie bufora
		return m_pBuffer;
	}

	if (iSize > 0)
	{
			m_pBuffer = new char [iSize];
			if (bZeroMemory)
				memset(m_pBuffer, 0, iSize); // zerowanie bufora
			m_iSize = iSize;
	}
	else 
		m_pBuffer = NULL;

	return m_pBuffer;
}


/*-------------------------------------------------------------------------------------
	Function       : CZipAutoBuffer
	In Parameters  : const CZipAutoBuffer& buffer
	Out Parameters : 
	Purpose		   : Copy constructor used
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBuffer::CZipAutoBuffer(const CZipAutoBuffer& buffer)
{
	m_pBuffer = NULL;
	m_iSize = 0;

	if (buffer.m_pBuffer)
	{
		Allocate(buffer.m_iSize);
		memcpy(m_pBuffer, buffer.m_pBuffer, buffer.m_iSize);
	}	
}
/*-------------------------------------------------------------------------------------
	Function       : operator=
	In Parameters  : const CZipAutoBuffer& buffer
	Out Parameters : 
	Purpose		   : Define = operator
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBuffer& CZipAutoBuffer::operator=(const CZipAutoBuffer& buffer)
{
	if (this == &buffer)
		return *this;
	Release();
	if (buffer.m_pBuffer)
	{
		Allocate(buffer.m_iSize);
		memcpy(m_pBuffer, buffer.m_pBuffer, buffer.m_iSize);
	}
	return *this;
}