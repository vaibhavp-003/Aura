/*=============================================================================
   FILE		           : CZipAutoBufferA.cpp
   ABSTRACT		       : implementation of the CZipAutoBufferA class.
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
#include "ZipAutoBufferA.h"
#include <memory.h> 

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipAutoBufferA
	Purpose		   : Constructor for class CZipAutoBufferA
	Author		   : 
-------------------------------------------------------------------------------------*/

CZipAutoBufferA::CZipAutoBufferA()
{
	m_iSize = 0;
	m_pBuffer = NULL;	
}
/*-------------------------------------------------------------------------------------
	Function       : CZipAutoBufferA
	Purpose		   : Copy Constructor for class CZipAutoBufferA
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBufferA::CZipAutoBufferA(DWORD iSize, bool bZeroMemory)
{
	m_iSize = 0;
	m_pBuffer = NULL;
	Allocate(iSize, bZeroMemory);
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipAutoBufferA
	Purpose		   : Destructor for class CZipAutoBufferA
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBufferA::~CZipAutoBufferA()
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
void CZipAutoBufferA::Release()
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
char* CZipAutoBufferA::Allocate(DWORD iSize, bool bZeroMemory)
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
	Function       : CZipAutoBufferA
	In Parameters  : const CZipAutoBufferA& buffer
	Out Parameters : 
	Purpose		   : Copy constructor used
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBufferA::CZipAutoBufferA(const CZipAutoBufferA& buffer)
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
	In Parameters  : const CZipAutoBufferA& buffer
	Out Parameters : 
	Purpose		   : Define = operator
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipAutoBufferA& CZipAutoBufferA::operator=(const CZipAutoBufferA& buffer)
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