/*======================================================================================
   FILE				: SigMatchLink.cpp
   ABSTRACT			: Supportive class Scan Tree
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
   NOTES			: This module keeps the information of all the secondary signatures 
					  with common first part, for unique virus detection 
   VERSION HISTORY	: 
=====================================================================================*/
#include "SigMatchLink.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CSigMatchLink
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CSigMatchLink::CSigMatchLink(void)
: m_FinalSigsCnt(0)
, m_FinalSigs (NULL)
{
	m_FinalSigsCnt = 0;
	m_FinalSigs = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CSigMatchLink
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CSigMatchLink::~CSigMatchLink(void)
{
}
