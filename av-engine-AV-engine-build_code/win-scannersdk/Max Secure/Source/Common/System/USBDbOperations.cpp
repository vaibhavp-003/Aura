#include "pch.h"
#include "USBDbOperations.h"
#include "ProductInfo.h"
CUSBDbOperations::CUSBDbOperations(void)
{
	m_pUSBWhiteDb = new CS2S(false);
	CProductInfo objProductInfo;
	CString csAppPath = objProductInfo.GetInstallPath();
	m_csWhiteUSBDB = csAppPath+L"WhiteUSB.db";	
}

CUSBDbOperations::~CUSBDbOperations(void)
{
	if(m_pUSBWhiteDb)
	{
		delete m_pUSBWhiteDb;
		m_pUSBWhiteDb = NULL;
	}
}
bool CUSBDbOperations::LoadDB()
{	
	return m_pUSBWhiteDb->Load(m_csWhiteUSBDB);
}
bool CUSBDbOperations::SearchSerialNo(CString csUSBSerialNo)
{
	TCHAR *csData = NULL;
	return m_pUSBWhiteDb->SearchItem(csUSBSerialNo,csData);
	
}
bool  CUSBDbOperations::SearchUSBName(CString csUSBName)
{
	LPVOID lpUsb = m_pUSBWhiteDb->GetFirst();
	TCHAR *szData = NULL;
	bool bRet = false;
	while(lpUsb)
	{
		m_pUSBWhiteDb->GetData(lpUsb,szData);
		CString csRetrievedData(szData);
		if(csUSBName.CompareNoCase(csRetrievedData)==0)
		{
			bRet =  true;
			break;
		}
		lpUsb = m_pUSBWhiteDb->GetNext(lpUsb);
	}
	return bRet;
}
bool CUSBDbOperations::AddSerialNo(CString csUSBSerialNo,CString csUSBName)
{
	return m_pUSBWhiteDb->AppendItem(csUSBSerialNo,csUSBName);	
}
bool CUSBDbOperations::DeleteSerialNo(CString csUSBSerialNo)
{
	return m_pUSBWhiteDb->DeleteItem(csUSBSerialNo);
}
bool CUSBDbOperations::SaveDB()
{
	m_pUSBWhiteDb->Balance();
	return m_pUSBWhiteDb->Save(m_csWhiteUSBDB);
}