/*======================================================================================
FILE				: Node.h
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



#ifndef CNODE
	#define CNODE
#endif

#ifndef CVECTOR
	#include "Vector.h"
#endif

struct VECTOR;
#pragma pack (1)
typedef struct TREE_NODE
{
	unsigned char	m_cNodeChr;
	TREE_NODE		*m_pNextNode;
	VECTOR			*m_pSuccess;

}CNode;
#pragma pack ()