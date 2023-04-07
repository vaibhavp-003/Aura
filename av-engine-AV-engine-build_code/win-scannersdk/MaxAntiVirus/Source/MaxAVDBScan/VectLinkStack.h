/*======================================================================================
FILE				: VectLinkStack.h
ABSTRACT			: This module is used in Failure Node calculation of Tree
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: 
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar + Rupali
=====================================================================================*/
#pragma once
#include <windows.h>
#ifndef CVECTLINKSTACK
	#define CVECTLINKSTACK
#endif


#ifndef CVECTOR
	#include "Vector.h"
#endif

class CVectLinkStack
{
public:
	CVectLinkStack(void);
	~CVectLinkStack(void);
	CVectLinkStack *m_pNextLink;
	CVector *m_pVect;
	CVector *m_pParentVect;
};
