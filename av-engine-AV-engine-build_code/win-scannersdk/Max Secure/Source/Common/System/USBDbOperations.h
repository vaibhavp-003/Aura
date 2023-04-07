#pragma once
#include "S2S.h"
class CUSBDbOperations
{
public:
	CUSBDbOperations(void);
	~CUSBDbOperations(void);
	CS2S *m_pUSBWhiteDb;
	bool LoadDB();
	bool SearchSerialNo(CString csUSBSerialNo);
	bool AddSerialNo(CString csUSBSerialNo,CString csUSBName);
	bool DeleteSerialNo(CString csUSBSerialNo);
	bool SearchUSBName(CString csUSBName);
	bool SaveDB();
	CString m_csWhiteUSBDB;
};
