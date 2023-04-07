/*=============================================================================
   FILE		           : ZipInternalInfo.cpp
   ABSTRACT		       : implementation of the CZipInternalInfo class.
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
#include "ZipInternalInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipInternalInfo
	Purpose		   : Constructor for class CZipInternalInfo
	Author		   : 
-------------------------------------------------------------------------------------*/

CZipInternalInfo::CZipInternalInfo()
{
	m_iBufferSize = 16384;
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipInternalInfo
	Purpose		   : Destructor for class CZipInternalInfo
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipInternalInfo::~CZipInternalInfo()
{

}
/*-------------------------------------------------------------------------------------
	Function       : Init
	In Parameters  : void
	Out Parameters : void
	Purpose		   : Initialize  CZipAutoBuffer object
	Author		   : 
-------------------------------------------------------------------------------------*/

void CZipInternalInfo::Init()
{
	m_pBuffer.Allocate(m_iBufferSize);
}
