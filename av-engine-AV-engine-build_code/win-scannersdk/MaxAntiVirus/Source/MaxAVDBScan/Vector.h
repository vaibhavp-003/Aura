/*======================================================================================
FILE				: Vector.h
ABSTRACT			: Core structure for Aho-corasick binary searching tree
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
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#pragma pack (1)
#ifndef CVECTOR
	#define CVECTOR
#endif

#ifndef CNODE
	#include "Node.h"
#endif

struct TREE_NODE;

typedef struct VECTOR
{
	unsigned int	m_cVector:8;
	unsigned int	m_bIsFinal:1;
	unsigned int	m_bIsQuestion:1;
	unsigned int	m_iSigID:22;
	VECTOR			*m_pFailureVect;
	TREE_NODE		*m_pSuccessList;
}CVector;
#pragma pack ()