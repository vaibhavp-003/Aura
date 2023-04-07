/*======================================================================================
   FILE			: HeuristicInfo.Cpp
   ABSTRACT		: Serialize class. To store file information like heuristicpattern, threateweight,
				  date time 
   DOCUMENTS	: Heuristics_LocalDb Design document.DOC
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 15-May-2008
   NOTES		:
   VERSION HISTORY	:
======================================================================================*/
#include "StdAfx.h"
#include "HeuristicFileInfo.h"
IMPLEMENT_SERIAL(CHeuristicFileInfo, CObject, 1)

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*--------------------------------------------------------------------------------------
Function       : CHeuristicFileInfo
In Parameters  : void,
Out Parameters :
Description    : C'tor
Author         :
--------------------------------------------------------------------------------------*/
CHeuristicFileInfo::CHeuristicFileInfo(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CHeuristicFileInfo
In Parameters  : void,
Out Parameters :
Description    : D'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CHeuristicFileInfo::~CHeuristicFileInfo(void)
{
}


/*-------------------------------------------------------------------------------------
Function		: Serialize
In Parameters	: CArchive &archive - archive object
Out Parameters	: void
Purpose			: Serialize member
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CHeuristicFileInfo::Serialize(CArchive &archive)
{
	CObject::Serialize(archive);
	if(archive.IsStoring())
		archive << m_csHeuristicPattern << m_dTotalWeight << m_dwHighDateTime << m_dwLowDateTime << m_ulSize;
	else
		archive >> m_csHeuristicPattern >> m_dTotalWeight >> m_dwHighDateTime >> m_dwLowDateTime >> m_ulSize;
}