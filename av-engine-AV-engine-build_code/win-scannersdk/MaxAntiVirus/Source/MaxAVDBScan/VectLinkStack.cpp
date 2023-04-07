/*======================================================================================
   FILE				: VectLinkStack.cpp
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
   NOTES			: This class module is used in failure node calculation by creating stack of all the vectors
   VERSION HISTORY	: 
=====================================================================================*/
#include "VectLinkStack.h"

/*-------------------------------------------------------------------------------------
	Function		: CVectLinkStack
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CVectLinkStack::CVectLinkStack(void)
: m_pNextLink(NULL)
, m_pVect(NULL)
, m_pParentVect(NULL)
{
	m_pNextLink = NULL;
	m_pVect = NULL;
	m_pParentVect = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CVectLinkStack
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CVectLinkStack::~CVectLinkStack(void)
{
}
