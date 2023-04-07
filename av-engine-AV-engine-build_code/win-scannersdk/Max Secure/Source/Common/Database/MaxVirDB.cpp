// LoadMMF.cpp : Defines the entry point for the console application.
//
#include "pch.h"
#include <fstream>
#include <string>
#include <iostream>
using namespace std;
#include <atlbase.h>
#include "MaxVirDB.h"

CMaxVirDB::CMaxVirDB(int nStructSize, VIRDBTYPE eDBType)
{
	m_dwFileSize = 0;
	m_nStructSize = nStructSize;
	m_hFile = INVALID_HANDLE_VALUE;
	m_hFileMapp = INVALID_HANDLE_VALUE;
	m_pFileBase = NULL;
	m_pCurrPos = NULL;
	m_bSaveMode = false;
	m_eDBType = eDBType;
	m_dwLastIDIndex = 0;
	m_bAppendFile = false;
	::ZeroMemory(m_szMainDBFile,sizeof(m_szMainDBFile));
}

CMaxVirDB::~CMaxVirDB()
{
	CloseFile();
}
bool CMaxVirDB::IsRepairDBLoaded()
{
	if(m_pFileBase)
	{
		return true;
	}
	return false;
}
void CMaxVirDB::CloseFile()
{
	__try{
		if(m_bSaveMode)
		{
			FlushViewOfFile(m_pFileBase, 0 ) ;
		}
		if(m_pFileBase)
		{
			UnmapViewOfFile( m_pFileBase ) ;
			m_pFileBase = NULL;
		}
		if(m_hFileMapp != INVALID_HANDLE_VALUE)
		{
			CloseHandle( m_hFileMapp ) ;
			m_hFileMapp = INVALID_HANDLE_VALUE;
		}
		if(m_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle( m_hFile ) ;
			m_hFile = INVALID_HANDLE_VALUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
}

bool CMaxVirDB::GetInstallPath(LPTSTR szInstallPath)
{
	TCHAR szVPath[MAX_PATH] = {0};
	::GetModuleFileName(NULL,szVPath,MAX_PATH);
	LPTSTR szSlash = _tcsrchr(szVPath,_T('\\'));
	if(szSlash == NULL)
	{
		return false;
	}
	szSlash++;
	*szSlash = 0;
	_tcscat_s(szInstallPath,MAX_PATH,szVPath);
	return true;
}

bool CMaxVirDB::LoadMMFDB(LPCTSTR lpFileName,bool bReadOnly)
{	
	CloseFile();
	if(_taccess_s(lpFileName, 0))
	{
		return false;
	}
	
	DWORD dwFileFlag = GENERIC_READ,dwMapFlag = PAGE_READONLY,dwViewFlag = FILE_MAP_READ;
	if(!bReadOnly)
	{
		dwFileFlag = GENERIC_READ | GENERIC_WRITE;
		dwMapFlag = PAGE_READWRITE|SEC_COMMIT;
		dwViewFlag = FILE_MAP_WRITE;
		m_bSaveMode = true;
	}
	SetFileAttributes(lpFileName, FILE_ATTRIBUTE_NORMAL) ;
	m_hFile = CreateFile(lpFileName, dwFileFlag , 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, NULL ) ;
	if( m_hFile == INVALID_HANDLE_VALUE )
		return FALSE ;

	m_hFileMapp = CreateFileMapping(m_hFile, NULL, dwMapFlag, 0, 0, NULL ) ;
	if( !m_hFileMapp )
	{
		return FALSE ;
	}

	m_pCurrPos = m_pFileBase = MapViewOfFile(m_hFileMapp, dwViewFlag, 0, 0, 0 ) ;
	if( !m_pFileBase )
	{
		return FALSE ;
	}
	m_dwFileSize = GetFileSize( m_hFile, NULL ) ;
	if(!bReadOnly)
	{
		char* lpLastIndex = (char*)((char*)m_pCurrPos + (m_dwFileSize - m_nStructSize));
		m_dwLastIDIndex = *((LPDWORD) lpLastIndex);
	}
	_tcscpy_s(m_szMainDBFile,lpFileName);
	return TRUE;
}

bool CMaxVirDB::CreateRepairDB(LPCTSTR lpIniFileName, LPCTSTR lpFileName)
{
	bool bRet = false;
	USES_CONVERSION;
	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}
	ifstream myfile (W2A(lpIniFileName));
	string strLine;
	if (myfile.is_open())
	{
		while (! myfile.eof() )
		{
			getline (myfile,strLine);
			if(strLine.length() > 0)
			{
				if(!ProcessBuffer(hFile,strLine))
				{
					goto CLEANUP;
				}
			}
		}
		myfile.close();
		bRet = true;
	}
CLEANUP:
	::CloseHandle(hFile);
	return bRet;
}

bool CMaxVirDB::MergeBuffer(string &strLine)
{
	DWORD dwID = 0;
	string strExpression;
	size_t found = strLine.find('=');
	if (found!=string::npos)
	{
		string strID = strLine.substr(0,found);
		dwID = atol(strID.c_str());
		strExpression = strLine.substr(found+1);
	}
	else
	{
		return false;
	}
	if(dwID > m_dwLastIDIndex)
	{
		if(dwID != m_dwLastIDIndex+1) 
		{
			return false;
		}
		m_dwLastIDIndex++;
		m_bAppendFile = true;
		REPAIRDB rDB = {0};
		rDB.dwID = dwID;
		strcpy_s(rDB.sbExpr, strExpression.c_str());
		m_objAppendList.push_back(rDB);
		return true;
	}
	DWORD dwFileOffset = dwID*m_nStructSize;
	if(dwFileOffset >= m_dwFileSize)
	{
		return false;
	}
	m_pCurrPos = (char*)m_pFileBase + dwFileOffset+sizeof(DWORD);
	memset((LPVOID)m_pCurrPos,0,MAX_EXPRESSION_SIZE);
	memcpy_s((LPVOID)m_pCurrPos,MAX_EXPRESSION_SIZE,strExpression.c_str(), MAX_EXPRESSION_SIZE);
	return true;
}

bool CMaxVirDB::UpdateScanDB(LPCTSTR lpIniFileName,LPCTSTR lpFileName)
{
	bool bRet = false;
	SCANDBMAP objDeltaDB;
	SCANDBMAP objScanDB;
	string strID,strExpr;
	SCANDBMAP::iterator iter;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesWritten = 0;
	SCANDBMAP::iterator tempiter;
	SCANDBMAP::iterator finditer;
	if(!LoadScanDB(lpIniFileName,objDeltaDB))
	{
		goto CLEANUP;
	}
	if(!LoadScanDB(lpFileName,objScanDB))
	{
		goto CLEANUP;
	}
	tempiter = objScanDB.begin();
	for(iter = objDeltaDB.begin(); iter != objDeltaDB.end(); iter++)
	{
		strID = (*iter).first;
		strExpr = (*iter).second;
		finditer = objScanDB.find(strID);
		if(finditer != objScanDB.end())
		{
			objScanDB.erase(finditer);
		}
		objScanDB.insert(tempiter, SCANDBMAP::value_type(strID,strExpr));
	}

	hFile = CreateFile(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}
	
	for(iter = objScanDB.begin(); iter != objScanDB.end(); iter++)
	{
		strID = (*iter).first;
		strID += "=";
		strID += (*iter).second;
		strID += "\n";
		if(!::WriteFile(hFile,strID.c_str(),(DWORD)strID.size(),&dwBytesWritten,NULL))
		{
			goto CLEANUP;
		}
	}
	bRet = true;
CLEANUP:
	if(hFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
	}
	return bRet;
}

bool CMaxVirDB::LoadScanDB(LPCTSTR lpIniFileName,SCANDBMAP& objScanDBMap)
{
USES_CONVERSION;
	bool bRet = false;
	ifstream myfile (W2A(lpIniFileName));
	string strLine;
	if (myfile.is_open())
	{
		while (! myfile.eof() )
		{
			getline (myfile,strLine);
			if(strLine.length() > 0)
			{
				if(!ProcesScanBuffer(strLine, objScanDBMap))
				{
					bRet = false;
					goto CLEANUP;
				}
			}
		}
		bRet = true;
		myfile.close();

	}	
CLEANUP:
	return bRet; 
}

bool CMaxVirDB::ProcesScanBuffer(string &strLine,SCANDBMAP& objScanDBMap)
{
	bool bRet = false;
	string strExpression;
	SCANDBMAP::iterator iter;
	iter = objScanDBMap.begin();
	
	size_t found = strLine.find('=');
	if (found!=string::npos)
	{
		string strID = strLine.substr(0,found);
		strExpression = strLine.substr(found+1);
		objScanDBMap.insert(iter, SCANDBMAP::value_type(strID,strExpression));
		bRet = true;
	}
	return bRet;
}

bool CMaxVirDB::MergeRepairDB(LPCTSTR lpIniFileName,LPCTSTR lpFileName)
{
USES_CONVERSION;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	bool bRet = false;
	LoadMMFDB(lpFileName,false);
	if(!m_pFileBase)
	{
		return false;
	}

	ifstream myfile (W2A(lpIniFileName));
	string strLine;
	if (myfile.is_open())
	{
		while (! myfile.eof() )
		{
			getline (myfile,strLine);
			if(strLine.length() > 0)
			{
				if(!MergeBuffer(strLine))
				{
					bRet = false;
					goto CLEANUP;
				}
			}
		}
		myfile.close();
	}
	CloseFile();
	if(m_bAppendFile)
	{
		//Update File
		DWORD dwFileFlag = GENERIC_READ | GENERIC_WRITE;

		hFile = CreateFile(lpFileName, dwFileFlag , 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, NULL ) ;
		if( hFile == INVALID_HANDLE_VALUE )
			return FALSE ;
		SetFilePointer(hFile,0L,NULL,FILE_END);
		for(unsigned int i = 0;i< m_objAppendList.size() ; i++)
		{
			DWORD dwBytesWritten = 0;
			if(!::WriteFile(hFile,&m_objAppendList[i],m_nStructSize,&dwBytesWritten,NULL))
			{
				bRet = false;
				goto CLEANUP;	
			}
		}
		bRet = true;
	}
CLEANUP:	
	if(hFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
	}
	if(!bRet)
	{
		m_bSaveMode = false;
	}
	return bRet;
}

bool CMaxVirDB::GetRepairExpression(DWORD &dwRepairID,LPTSTR szRepairAction)
{
	__try{
USES_CONVERSION;
		DWORD dwFileOffset = dwRepairID*m_nStructSize;
		if(dwFileOffset >= m_dwFileSize)
		{
			return false;
		}

		m_pCurrPos = (char*)m_pFileBase + dwFileOffset;
		DWORD dwID = *((LPDWORD) m_pCurrPos);
		char szTempRepairAction[MAX_EXPRESSION_SIZE+2] = {0};
		strncpy_s(szTempRepairAction,MAX_EXPRESSION_SIZE,(char*)m_pCurrPos+sizeof(DWORD),MAX_EXPRESSION_SIZE);
		_tcscpy_s(szRepairAction,MAX_PATH,A2W(szTempRepairAction));
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
}

BOOL CMaxVirDB::ProcessBuffer(HANDLE hFile, string &strLine)
{
	BOOL bRet = FALSE;
	try{
		size_t found = strLine.find('=');
		if (found!=string::npos)
		{	
			REPAIRDB sRepairDB = {0};
			string strID = strLine.substr(0,found);
			string strExpression = strLine.substr(found+1);
			sRepairDB.dwID = atol(strID.c_str());
			strcpy_s(sRepairDB.sbExpr,MAX_EXPRESSION_SIZE,strExpression.c_str());
			DWORD dwBytesWritten = 0;
			bRet = ::WriteFile(hFile,&sRepairDB,SIZE_OF_REPAIR_DB,&dwBytesWritten,NULL);

		}
	}
	catch(...)
	{
		return false;
	}
	return bRet;	
}