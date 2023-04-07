/*======================================================================================
   FILE			: Registry.h
   ABSTRACT		: This class provides the functionality to manupulate regstry
   DOCUMENTS	: 
   AUTHOR		: Vikas Jain 
   COMPANY		:Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 25/12/2003
   NOTES		:Registry Wrapper
======================================================================================*/
#pragma once

#include <Afxtempl.h>
#include <vector>
using namespace std;

#define MAX_SIZE		9000
struct REG_VALUE_DATA
{
	int		Type_Of_Data;
	TCHAR	strValue[MAX_PATH];
	int		iSizeOfData;
	BYTE	bData[MAX_PATH*4];
};

class CRegistry
{
public:
	CRegistry();
	virtual ~CRegistry();

	// read the data from registry
	// read SZ_STRING
	bool	Get(CString strKeyPath, CString strValueName, CString &strValue, HKEY HiveRoot = HKEY_CURRENT_USER, DWORD * dwRegType = 0)const;
	// read SZ_DWORD
	bool	Get(CString strKeyPath, CString strValueName, DWORD &dwValue, HKEY HiveRoot = HKEY_CURRENT_USER)const;
	// read SZ_BINARY (read custom data)
	bool	Get(CString strKeyPath, CString strValueName, DWORD dwType, LPBYTE pByte, DWORD dwSizeOfBuffer, HKEY HiveRoot = HKEY_CURRENT_USER)const;
	// read REG_MULTI_SZ
	bool	Get(CString strKeyPath, CString strValueName, CStringArray &arrData, HKEY HiveRoot)const;

	//Get Value Type
	bool	GetValueType(CString strKeyPath, CString strValueName, DWORD &dwType, HKEY HiveRoot);

	// Write the data into registry
	// Write SZ_DWORD
	bool	Set(CString strKeyPath, CString strValueName, DWORD dwValue, HKEY HiveRoot = HKEY_CURRENT_USER)const;
	// Write SZ_STRING
	bool	Set(CString strKeyPath, CString strValueName, CString strValue, HKEY HiveRoot = HKEY_CURRENT_USER, bool bFulshKey = false)const;
	// Write SZ_BINARY (write custom data)
	bool	Set(CString strKeyPath, CString strValueName, LPBYTE pByte, DWORD dwSizeOfBuffer, DWORD dwType, HKEY HiveRoot)const;
	// Write REG_MULTI_SZ
	bool	Set(CString strKeyPath, CString strValueName, CStringArray &arrData, HKEY HiveRoot)const;

	// Verification
	bool	KeyExists(CString strKeyPath, HKEY HiveRoot = HKEY_CURRENT_USER);
	bool	ValueExists(CString strKeyPath, CString strValueName, HKEY HiveRoot = HKEY_CURRENT_USER);

	// Deletion
	bool	DeleteKey		(CString strKeyPath, CString strSubKey, HKEY HiveRoot = HKEY_CURRENT_USER);
	bool	DeleteValue		(CString strKeyPath, CString strValueName, HKEY HiveRoot = HKEY_CURRENT_USER);
	bool	Flush(HKEY &hKey);
	bool	DeleteEnumRegValue(const TCHAR *cEnumKey, const TCHAR *cValue, const TCHAR *cData, HKEY RootKey);

	// Enumerate
	bool	EnumSubKeys		(CString csMainKey, CArray<CString,CString> &o_arrEnumSubKeys,		HKEY hHiveKey = HKEY_CURRENT_USER, bool bReturnOnlySubKey = false);
	bool	EnumSubKeys		(CString csMainKey, CStringArray &objSubKeyArr,	HKEY hHiveKey);
	bool	EnumSubKeys		(CString csMainKey, CMapStringToString &objSubKeyMap,	HKEY hHiveKey);
	bool	EnumValues		(CString csMainKey, CStringArray &arrValues, HKEY hHive);
	bool	QueryValue		(CString csMainKey, CArray<CString,CString> &o_arrQueryKeysValues, HKEY hHiveKey = HKEY_CURRENT_USER);
	bool	QueryDataValue (CString csMainKey, CStringArray &o_arrValues, CStringArray &o_arrData,HKEY hHiveKey = HKEY_CURRENT_USER);
	void	EnumValues		(CString csMainKey, vector<REG_VALUE_DATA> &vecRegValues, HKEY hHiveKey);

	bool	FormulatePath(CString &strRegPath, HKEY &hKey);
	CString RootKey2String(HKEY hKey);
	bool	StringRoot2key(CString strRoot, HKEY &hKey);
	bool	SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	bool	SaveRegKeyPath(HKEY HiveRoot, CString &SubKey, CString &csSdbDatFilePath);
	bool	RestoreRegKeyPath(HKEY HiveRoot, CString &SubKey, CString &InFile, BOOL Force = TRUE);
	bool	RestoreRegKeyPath98(HKEY HiveRoot, CString &SubKey, CString &InFile);

	//Load/UnLoad hives
	bool	LoadKey(HKEY HiveRoot, CString SubKey, CString ntUserFile);
	bool	UnLoadKey(HKEY HiveRoot, CString SubKey);
	bool	Open(CString strKeyPath, HKEY & hKey, HKEY HiveRoot, REGSAM regSam = KEY_ALL_ACCESS);

	// function and data for deleting registry keys
	bool	DeleteRegKey(HKEY hParentKey, CString csRegKeyName);
	bool	AdjustPermissions(HKEY hParent, CString csKeyName);
	bool	AllowAccessToEveryone(HKEY hParentKey, CString csRegKeyName);

	CString GetHiveName(HKEY hHive);
	HKEY	GetHiveByName(CString csHive);

	bool	CreateKey(CString strKeyPath, HKEY & hkey, HKEY HiveRoot);
	bool	CloseKey(HKEY &hKey);
	bool	CopyKeyRecursive(CString csKeyPathCopyFrom, CString csKeyPathCopyTo, HKEY HiveCopyFrom,	HKEY HiveCopyTo);
	bool	CopyKeyUsingPreQueryKey(CString csMainKeyCopyFrom,	CString csMainKeyCopyTo,	HKEY hHiveKeyCopyFrom, HKEY hHiveKeyCopyTo);
	void    SetWow64Key(bool bWow64Key);
	bool    GetWow64Key(){return m_bWOW64Key? true: false;}
	BOOL	IsOS64Bit();
private:
	DWORD					m_dwOrgSecDesc;
	TCHAR*					m_szp;
	PSECURITY_DESCRIPTOR	m_pOrgSecDesc;
	BOOL					m_bWOW64Key;
};
