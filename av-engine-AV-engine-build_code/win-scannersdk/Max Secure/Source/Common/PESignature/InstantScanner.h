#pragma once
#include "S2U.h"
#include "Q2S.h"

class CInstantScanner
{
	CS2U m_objFileNameDB;
	CQ2S m_objSignatureDB;

public:
	CInstantScanner(void);
	~CInstantScanner(void);

	void LoadEntriesFromINI();
	bool ScanFile(LPCTSTR lpstrFileToScan, bool bSigCreated, ULONG64 ulSignature);

};
