#include "pch.h"
#include "MaxFileShredder.h"

//#include "BitTools.h"


CMaxFileShredder::CMaxFileShredder(void)
{
	m_hEvidence = NULL;
	m_lpfnEvidence = NULL;

	
}

CMaxFileShredder::~CMaxFileShredder(void)
{
}

void CMaxFileShredder::InitializeDll(void)
{
	if(m_lpfnEvidence != NULL)
		m_lpfnEvidence();
}

