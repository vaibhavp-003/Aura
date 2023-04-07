/*=============================================================================
   FILE		           : ZipInternalInfoA.cpp
   ABSTRACT		       : implementation of the CZipInternalInfoA class.
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
#include "ZipInternalInfoA.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipInternalInfoA
	Purpose		   : Constructor for class CZipInternalInfoA
	Author		   : 
-------------------------------------------------------------------------------------*/

CZipInternalInfoA::CZipInternalInfoA()
{
	m_iBufferSize = 16384;
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipInternalInfoA
	Purpose		   : Destructor for class CZipInternalInfoA
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipInternalInfoA::~CZipInternalInfoA()
{

}
/*-------------------------------------------------------------------------------------
	Function       : Init
	In Parameters  : void
	Out Parameters : void
	Purpose		   : Initialize  CZipAutoBufferA object
	Author		   : 
-------------------------------------------------------------------------------------*/

void CZipInternalInfoA::Init()
{
	m_pBuffer.Allocate(m_iBufferSize);
}
