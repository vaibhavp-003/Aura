#pragma once
#include "MaxConstant.h"
//#include "Backend.h"

typedef bool (*LPFN_StartEvidenceThread)();

class CMaxFileShredder
{
private:
	HMODULE					m_hEvidence;
public:
	CMaxFileShredder(void);
	~CMaxFileShredder(void);
	void InitializeDll();
	LPFN_StartEvidenceThread			m_lpfnEvidence;
};
