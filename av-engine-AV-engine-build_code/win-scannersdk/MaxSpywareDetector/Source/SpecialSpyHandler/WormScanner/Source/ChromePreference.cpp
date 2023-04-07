#include "pch.h"
#include "ChromePreference.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include <iostream>
#include "DBWrapper.h"
#include "CPUInfo.h"
#include "Shlwapi.h"
#include "DirectoryManager.h"
CChromePreference::CChromePreference(void)
{
	CRegistry m_oReg;
	m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),m_csFilePath,HKEY_LOCAL_MACHINE);
	m_csFilePath = m_csFilePath + _T("WhiteINI.ini");
	m_bCleanIE = true;
	m_bCleanChrome = false;
	m_bCleanFireFox = false;
	m_bCleanOpera = false;
}

CChromePreference::~CChromePreference(void)
{
}
void CChromePreference::RemoveExtensionFromChrome()
{
	try
	{
		CDirectoryManager objDirManger;
		CString cszAppdataLocal,cszWebDataDBPath;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),cszAppdataLocal,HKEY_LOCAL_MACHINE);

		CString cszPrefPath,cszSecurePrefPath,cszSecurePrefPathDup,cszWriteString,cszPrefPathDup,csFolderPathRec,csInvalidFolderName;
		//CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),cszAppdataLocal,HKEY_LOCAL_MACHINE);
		cszPrefPath = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Preferences");
		cszPrefPathDup = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\PreferencesDup");
		cszSecurePrefPath = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Secure Preferences");
		cszSecurePrefPathDup =  cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Secure PreferencesDup");

		LPTSTR lpszText = NULL;
		CString cszText,cszTempUrl;
		CStdioFile objStdioFile;
		int iPos = 0;
		if(!objStdioFile.Open(cszSecurePrefPath, CFile::modeReadWrite))
		{
			return;
		}
		while(objStdioFile.ReadString(cszText))
		{
			int iExtPath = cszText.Find(_T("\"path\""));
			cszTempUrl = cszText;
			int iPathCnt = cszTempUrl.Replace(_T("\"path\""),_T("\"Max\""));
			cszTempUrl = cszText;
			CString cszOrgignalStr;
			cszOrgignalStr = cszText;
			if(iExtPath != -1)
			{
				for(int iPos =0; iPos<iPathCnt; iPos++)
				{
					cszTempUrl = cszOrgignalStr;
					iExtPath = cszTempUrl.Find(_T("\"path\""));
					if(iExtPath != -1)
					{
						cszTempUrl.Delete(0, cszTempUrl.Find(_T("\"path\"")) +8);
						cszOrgignalStr = cszTempUrl;
						int j = cszTempUrl.Find(_T("\""));
						int iLen = cszTempUrl.GetLength();
						iLen -= j;
						int iret = cszTempUrl.Delete(j,iLen);
						cszTempUrl.Replace(_T("\\\\"),_T("\\"));

						if(!PathFileExists(cszTempUrl))
						{
							continue;
						}

						CString cszFolderName;

						cszFolderName = cszTempUrl;
						iLen = cszFolderName.GetLength();
						j = cszFolderName.ReverseFind(_T('\\'));
						iLen--;
						cszFolderName.Delete(0,iLen);
						
						if(cszFolderName.Compare(_T("\\")) == 0)
						{
							cszFolderName = cszTempUrl;
							iLen = cszFolderName.GetLength();
							j = cszFolderName.ReverseFind(_T('\\'));
							iLen -= j;
							iLen++;
							cszFolderName.Delete(j,iLen);
						}
						else
						{
							cszFolderName = cszTempUrl;
						}

						if(!PathFileExists(cszFolderName))
						{
							continue;
						}
						csFolderPathRec = cszFolderName;

						iLen = cszFolderName.GetLength();
						j = cszFolderName.ReverseFind(_T('\\'));
						iLen -= j;
						cszFolderName.Delete(0,j+1);

						bool bRenameVal = true;
						char m_szWhiteIniFile[MAX_PATH];
						sprintf(m_szWhiteIniFile, "%S", m_csFilePath);
						CString csRegistryValName,csRegistryName;
						int iPathLength = 1024*2;
							if(!PathFileExists(m_csFilePath))
							{
								return ;
							}
						m_nRegistryValueCount = GetPrivateProfileIntA("IgnoreValues","Count",0,m_szWhiteIniFile);
						for(int nCount = 1; nCount <= m_nRegistryValueCount && bRenameVal; nCount++ )
						{
							csRegistryValName.Format(_T("%d"),nCount);
							GetPrivateProfileString(_T("IgnoreValues"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, m_csFilePath);
							if(cszFolderName.CompareNoCase(csRegistryValName)!= 0 && !(cszFolderName.IsEmpty()))
							{
								bRenameVal = true;
							}
							else
							{
								bRenameVal = false;
							}
						}
						csInvalidFolderName = csFolderPathRec + _T("_dis");
						if(bRenameVal)
						{
							objDirManger.MaxDeleteDirectory(csFolderPathRec, true);
						}
					}
					else
					{
						continue;
					}
				
				}
				//cszWriteString = cszText;
			}
			// startup_urls

		}
		objStdioFile.Close();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::RemoveExtensionFromChrome"));
		return ;
	}
}
bool CChromePreference::RemoveUrl()
{
	try
	{
		CString cszAppdataLocal,cszWebDataDBPath;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),cszAppdataLocal,HKEY_LOCAL_MACHINE);
		cszWebDataDBPath = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Web Data");

		if(!PathFileExists(cszWebDataDBPath))
			return false;

		char strDBPath[256] ={0} ;
		sprintf_s(strDBPath,sizeof ( strDBPath ),"%S",static_cast<LPCTSTR>(cszWebDataDBPath));

		CDBWrapper objDBWrapper;
		bool bIsDbOpen = false;
		//const char *strDBPath = {"C:\\Users\\Ravinrdas\\Desktop\\Notepad files\\Web Data"};
		bIsDbOpen = objDBWrapper.OpenDB(strDBPath);
		if(!bIsDbOpen)
		{
			return false;
		}
		bIsDbOpen = false;
		bIsDbOpen = objDBWrapper.DeleteQuery(strDBPath);
		if(!bIsDbOpen)
		{
			return false;
		}
		bIsDbOpen = false;
		bIsDbOpen = objDBWrapper.InsertDefaultGoogle(strDBPath);
		if(!bIsDbOpen)
		{
			return false;
		}

		bIsDbOpen = false;
		bIsDbOpen = objDBWrapper.InsertDefaultYahoo(strDBPath);
		if(!bIsDbOpen)
		{
			return false;
		}

		bIsDbOpen = false;
		bIsDbOpen = objDBWrapper.InsertDefaultBing(strDBPath);
		if(!bIsDbOpen)
		{
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::RemoveUrl"));
		return false;
	}
}
void CChromePreference::ResetMozillaUsingPrefJS()
{
	try
	{
		DWORD dwBlockPopVal = 0;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csActMonRegKey,BLOCKPOPUP,dwBlockPopVal,HKEY_LOCAL_MACHINE);
		
		CString csMozillaFolderPath;
		CString csAppdataLocalRoming;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"),csAppdataLocalRoming,HKEY_LOCAL_MACHINE);
		CString csProfileIniPath = csAppdataLocalRoming + _T("\\Mozilla\\Firefox\\profiles.ini");
		csAppdataLocalRoming = csAppdataLocalRoming + _T("\\Mozilla\\Firefox\\");
		CString csRegistryValName;
		int iPathLength = 1024*2;
		csRegistryValName = _T("Path");
		GetPrivateProfileString(_T("Profile0"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, csProfileIniPath);
		csAppdataLocalRoming.Replace(_T("\\"),_T("/"));
		CString cs;
		cs.Format(_T("%s%s/prefs.js"),csAppdataLocalRoming,csRegistryValName);
		CString csPrefFilePath = cs;//_T("C:\\Users\\Ravinrdas\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xajsjuli.default\\prefs.js");
		cs.Format(_T("%s%s/prefsDup.js"),csAppdataLocalRoming,csRegistryValName);
		CString csPrefFilePathDup = cs;//_T("C:\\Users\\Ravinrdas\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xajsjuli.default\\prefsDup.js");
		CString csText;
		CStdioFile theFile;
		CStdioFile theFileDup;
		if(!theFile.Open(csPrefFilePath, CFile::modeReadWrite))
		{
			return;
		}
		if(!theFileDup.Open(csPrefFilePathDup, CFile::modeCreate | CFile::modeReadWrite))
		{
			return;
		}
		
		while(theFile.ReadString(csText))
		{
			if(csText.Find(_T("browser.startup.homepage")) != -1 
				|| csText.Find(_T("browser.search.defaultenginename")) != -1
				|| csText.Find(_T("browser.search.defaulturl")) != -1)
			{
				CString csOrgStr = csText;
				if(csText.Find('(') != -1)
				{
					int i = (csText.Find('('));
					csText.Delete(0, csText.Find('(') +2);
					int j = (csText.Find(','));
					csText.Delete(j - 1, csText.Find(')'));
				}
				if(csText.CompareNoCase(_T("browser.startup.homepage")) == 0
					|| csText.CompareNoCase(_T("browser.search.defaultenginename")) == 0
					|| csText.CompareNoCase(_T("browser.search.defaulturl")) == 0)
				{
					continue;
				}
				else
				{
					theFileDup.WriteString(csOrgStr + _T("\n"));
				}
				
			}
			else
			{
				theFileDup.WriteString(csText + _T("\n"));
			}
		}
		theFileDup.Close();
		theFile.Close();
		if(PathFileExists(csPrefFilePath))
			DeleteFile(csPrefFilePath);
			if(PathFileExists(csPrefFilePathDup))
			{
				_wrename(csPrefFilePathDup, csPrefFilePath);
			}



		if(theFile.Open(csPrefFilePath, CFile::modeReadWrite))
		{
			//Setting Home page
			theFile.SeekToEnd();
			csText = _T("user_pref(\"browser.startup.homepage\", \"https:\\\\www.google.com\");");
			theFile.WriteString(csText);
			
			// Setting Default Serach engine
			theFile.WriteString(_T("\n"));
			csText = _T("user_pref(\"browser.search.defaultenginename\", \"Google\");");
			theFile.WriteString(csText);

			//Setting Default Url
			theFile.WriteString(_T("\n"));
			csText = _T("user_pref(\"browser.search.defaulturl\", \"http:\\\\www.google.co\\search?num=100&q=\");");
			theFile.WriteString(csText);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::ResetMozillaUsingPrefJS"));
		return ;
	}
	
}
bool CChromePreference::RemoveToolbarFromMozilla()
{	
	try
	{
		CString csMozillaFolderPath;
		CString csAppdataLocalRoming;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"),csAppdataLocalRoming,HKEY_LOCAL_MACHINE);
		//C:\Users\pawan\AppData\Roaming\Mozilla\Firefox\Profiles\g25ygt4h.default-1426481317437\extensions
		//C:\Users\Ravinrdas\AppData\Roaming\Mozilla\Firefox\profiles.ini
		//C:/Users/Ravinrdas/AppData/Roaming/Mozilla/Firefox/profiles.ini
		CString csProfileIniPath = csAppdataLocalRoming + _T("\\Mozilla\\Firefox\\profiles.ini");
		csAppdataLocalRoming = csAppdataLocalRoming + _T("\\Mozilla\\Firefox\\");
		
		CString csRegistryValName;
		int iPathLength = 1024*2;
		csRegistryValName = _T("Path");
		GetPrivateProfileString(_T("Profile0"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, csProfileIniPath);
		//csRegistryValName.Replace(_T("/"),_T("\\"));
		//csRegistryValName.Replace(_T("\/"), _T("\\"));
		csAppdataLocalRoming.Replace(_T("\\"),_T("/"));
		//csAppdataLocalRoming = csAppdataLocalRoming + csRegistryValName;
		CString cs;
		cs.Format(_T("%s%s/extensions"),csAppdataLocalRoming,csRegistryValName);
		EnumrateAndRenameFolder(cs,true);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::RemoveToolbarFromMozilla"));
		return false;
	}
}
bool CChromePreference::EnumrateAndRenameFolder(CString csFolderPath,bool bRenameFile,bool bDeleteFile)
{
	try
	{
		bool bRenameVal =true;
		if(csFolderPath.IsEmpty() || !PathFileExists(csFolderPath))
		{
			return false;
		}	
		CDirectoryManager objDirManger;
		CFileFind finder;
		 CString strWildcard,strLWrite;
		 strWildcard=csFolderPath;
		 strWildcard += _T("\\*.*");

		 // start working for files
		 BOOL bWorking = finder.FindFile(strWildcard);
		 int Index = 0;
		 while (bWorking)
		 { 
			bWorking = finder.FindNextFile();
			if (finder.IsDots())
			{
				//StopExeAndDeleteDirectory(strWildcard,true);
				 continue;
			}
			CString csFileName=finder.GetFileName();
			if(finder.IsDirectory())
			{
				CString csFolderName = finder.GetFileName();
				CString csFolderPathRec = csFolderPath + _T("\\") +  finder.GetFileName();
				CString csInvalidFolderName = csFolderPathRec + _T("_dis");
				bRenameVal = true;
				char m_szWhiteIniFile[MAX_PATH];
				sprintf(m_szWhiteIniFile, "%S", m_csFilePath);
				if(!PathFileExists(m_csFilePath))
				{
					return false;
				}
				CString csRegistryValName,csRegistryName;
				int iPathLength = 1024*2;
				m_nRegistryValueCount = GetPrivateProfileIntA("IgnoreValues","Count",0,m_szWhiteIniFile);
				for(int nCount = 1; nCount <= m_nRegistryValueCount && bRenameVal; nCount++ )
				{
					csRegistryValName.Format(_T("%d"),nCount);
					GetPrivateProfileString(_T("IgnoreValues"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, m_csFilePath);
					if(csFolderName.CompareNoCase(csRegistryValName)!= 0 && !(csFolderName.IsEmpty()))
					{
						bRenameVal = true;
					}
					else
					{
						bRenameVal = false;
					}
				}	
				if(bRenameVal && csFolderPathRec.Find(_T("_dis")) == -1)
				{
					if(bDeleteFile)
					{
						if(PathFileExists(csFolderPathRec))
						{
							objDirManger.MaxDeleteDirectory(csFolderPathRec, true);
						}
					}
					else
					{
						_wrename(csFolderPathRec, csInvalidFolderName);
					}
				}
				CString csChromeRegKeyPath64;
	
				CString csTemp= _T("SOFTWARE\\Wow6432Node\\Google\\Chrome\\Extensions");
				CString csChromeRegKeyPath32= _T("SOFTWARE\\Google\\Chrome\\Extensions");
				CCPUInfo objInfo;
				if(objInfo.isOS64bit())
				{
					csChromeRegKeyPath64 = csTemp + _T("\\") + csFolderName;
				}
				else
				{
					csChromeRegKeyPath64 = csChromeRegKeyPath32 + _T("\\") + csFolderName;
				}
				
				CRegistry objReg;
				if(bRenameVal && csFolderPathRec.Find(_T("_dis")) == -1 && objReg.KeyExists(csChromeRegKeyPath64,HKEY_LOCAL_MACHINE))
				{
					//EnumerateRegKeyByValue(csChromeRegKeyPath64,HKEY_LOCAL_MACHINE,m_csFilePath,false,true);
				}
			
	
			}
			else
			{
				bRenameFile = true;
				if(bRenameFile)
				{
					CString csFolderName = finder.GetFileName();
					CString csFolderPathRec = csFolderPath + _T("\\") +  finder.GetFileName();
					CString csInvalidFolderName = csFolderPathRec + _T("_dis");
					bRenameVal = true;
					char m_szWhiteIniFile[MAX_PATH];
					sprintf(m_szWhiteIniFile, "%S", m_csFilePath);
					if(!PathFileExists(m_csFilePath))
					{
						return false;
					}
					CString csRegistryValName,csRegistryName;
					int iPathLength = 1024*2;
					m_nRegistryValueCount = GetPrivateProfileIntA("IgnoreValues","Count",0,m_szWhiteIniFile);
					for(int nCount = 1; nCount <= m_nRegistryValueCount && bRenameVal; nCount++ )
					{
						csRegistryValName.Format(_T("%d"),nCount);
						GetPrivateProfileString(_T("IgnoreValues"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, m_csFilePath);
						if(csFolderName.CompareNoCase(csRegistryValName)!= 0 && !(csFolderName.IsEmpty()))
						{
							bRenameVal = true;
						}
						else
						{
							bRenameVal = false;
						}
					}	
					if(bRenameVal && csFolderPathRec.Find(_T("_dis")) == -1 && csFolderPathRec.Find(_T(".xpi")) != -1)
					{
						if(bDeleteFile)
						{	
							if(PathFileExists(csFolderPathRec))
							{
								objDirManger.MaxDeleteDirectory(csFolderPathRec, true);
							}
						}
						else
						{
							_wrename(csFolderPathRec, csInvalidFolderName);
						}
					}
				}
			}
		 }
		 finder.Close();
		 return true;
	 }
	catch(...)
	{
		AddLogEntry(_T("Exception caught in StopExeAndDeleteDirectory()"));
		return false;
	}
	return true;
}
bool CChromePreference::RemoveToolbarFromChrome()
{
	try
	{
		CCPUInfo objSystem;
		CRegistry objReg;
		CString csChromeToolPath,csChromeFolderPath;
		if(objSystem.isOS64bit())
		{
			csChromeToolPath = _T("SOFTWARE\\Wow6432Node\\Google\\Chrome\\Extensions");
		}
		else
		{
			csChromeToolPath = _T("SOFTWARE\\Google\\Chrome\\Extensions");
		}
		CString csAppdataLocal;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),csAppdataLocal,HKEY_LOCAL_MACHINE);
		//EnumrateAndRenameRegKey(csChromeToolPath,HKEY_LOCAL_MACHINE);
		csAppdataLocal = csAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Extensions");
		EnumrateAndRenameFolder(csAppdataLocal,true);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::RemoveToolbarFromChrome"));
		return false;
	}
}
bool CChromePreference::EnumrateAndRenameRegKey(CString csToolPath,HKEY HiveRoot)
{
	try
	{
		DWORD LengthOfLongestValueName;
		DWORD LengthOfLongestValueData;
		DWORD LengthOfLongestSubkeyName;
		bool bRenameVal = true;

		LengthOfLongestSubkeyName = 4096; 
		LengthOfLongestValueName  = 4096; 
		LengthOfLongestValueData  = 4096;

		DWORD TypeCode;
		DWORD LengthOfValueName;
		DWORD LengthOfValueData;
		int NTr;
		DWORD iValIdx;

		LPWSTR lpValueName;
		LPWSTR lpValueData;
		lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueName);
		lpValueData = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueData);


		CRegistry objReg;
		CStringArray arrKeys,arrKeys1;
		CString csKey = csToolPath;
		objReg.EnumSubKeys(csKey, arrKeys, HiveRoot);
		INT_PTR nKeyCount = arrKeys.GetCount();
		for(int iCtr = 0; iCtr < nKeyCount; iCtr++)
		{
			CString csKeyInarr = arrKeys.GetAt(iCtr);
			csKeyInarr.Trim().MakeLower();
			if(!(csKeyInarr.IsEmpty()))
			{
				// check whether matches with clsid 
				for(int iCtr = 0; iCtr < nKeyCount; iCtr++)
				{
					bRenameVal = true;
					HKEY hSubKey = NULL;
					CString csKey = arrKeys.GetAt(iCtr);
					//csKey2.Trim().MakeLower();
					
					char m_szWhiteIniFile[MAX_PATH];
					sprintf(m_szWhiteIniFile, "%S", m_csFilePath);
					if(!PathFileExists(m_csFilePath))
					{
						return false;
					}
					CString csRegistryValName,csRegistryName;
					int iPathLength = 1024*2;
					m_nRegistryValueCount = GetPrivateProfileIntA("IgnoreValues","Count",0,m_szWhiteIniFile);
					for(int nCount = 1; nCount <= m_nRegistryValueCount && bRenameVal; nCount++ )
					{
						csRegistryValName.Format(_T("%d"),nCount);
						GetPrivateProfileString(_T("IgnoreValues"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, m_csFilePath);
						if(csKey.CompareNoCase(csRegistryValName)!= 0 && !(csKey.IsEmpty()))
						{
							bRenameVal = true;
						}
						else
						{
							bRenameVal = false;
						}
					}	
					if(bRenameVal)
					{
						CString csRegKey = csToolPath +_T("\\") + csKey;
						if(RegOpenKeyEx(HiveRoot, csRegKey, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
						{
							int i = GetLastError();
						}
						for(iValIdx = 0; ; iValIdx++)
						{
							SecureZeroMemory(lpValueName, LengthOfLongestValueName);
							SecureZeroMemory(lpValueData, LengthOfLongestValueData);

							LengthOfValueName = LengthOfLongestValueName;
							LengthOfValueData = LengthOfLongestValueData;
							NTr = RegEnumValue(hSubKey, iValIdx, lpValueName, &LengthOfValueName, NULL,&TypeCode, (LPBYTE)lpValueData, &LengthOfValueData);

							if(NTr == ERROR_NO_MORE_ITEMS)
							{
								break;
							}
							CString csTemp,csValName;
							csTemp.Format(_T("%s"),lpValueData);
							csValName.Format(_T("%s"),lpValueName);
							if(csValName.CompareNoCase(_T("path")) == 0)
							{
								if(csTemp.Find(_T("_dis")) == -1)
								{
									csTemp = csTemp + _T("_dis");
									objReg.Set(csRegKey,_T("path"),csTemp,HKEY_LOCAL_MACHINE);
								}
							}
							
						}
					}
					
				}
			}
			
		}
		GlobalFree(lpValueName);
		GlobalFree(lpValueData);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in EnumrateAndRenameRegKey()"));
		return false;
	}
}
void CChromePreference::RemoveCommandLine()
{
	try
	{
		CRegistry	objReg;

		CCPUInfo	objCPUInfo;

		CString cszRegPath,cszRegVal;
		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\IEXPLORE.EXE\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		int iPos = 0;
		int iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			//CString cszExeName = _T("iexplore.exe");
			iPos = cszRegVal.Find(_T("iexplore.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 12,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}

		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		iPos = 0;
		iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			//CString cszExeName = _T("iexplore.exe");
			iPos = cszRegVal.Find(_T("chrome.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 10,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}

		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\chrome.exe\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		iPos = 0;
		iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			//CString cszExeName = _T("iexplore.exe");
			iPos = cszRegVal.Find(_T("chrome.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 10,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}

		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\FIREFOX.EXE\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		iPos = 0;
		iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			//CString cszExeName = _T("iexplore.exe");
			iPos = cszRegVal.Find(_T("firefox.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 11,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}

		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\Opera\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		iPos = 0;
		iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			//CString cszExeName = _T("iexplore.exe");
			iPos = cszRegVal.Find(_T("Opera.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 9,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}

		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\Opera.exe\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		iPos = 0;
		iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			//CString cszExeName = _T("iexplore.exe");
			iPos = cszRegVal.Find(_T("Opera.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 9,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}
		cszRegPath = _T("SOFTWARE\\Clients\\StartMenuInternet\\OperaStable\\shell\\open\\command");
		objReg.Get(cszRegPath, _T(""),cszRegVal,HKEY_LOCAL_MACHINE);
		iPos = 0;
		iLen = 0;
		if(!cszRegVal.IsEmpty())
		{
			iPos = cszRegVal.Find(_T("Launcher.exe"));	
			iLen = cszRegVal.GetLength();
			iLen -= iPos;
			cszRegVal.Delete(iPos + 12,iLen);
			cszRegVal.Replace('\"',' ');
			cszRegVal.TrimLeft();
			cszRegVal.TrimRight();
			CString cszTemp;
			cszTemp.Format(_T("\"%s\""),cszRegVal);
			objReg.Set(cszRegPath, _T(""),cszTemp,HKEY_LOCAL_MACHINE);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::RemoveCommandLine"));
		return ;
	}
}
bool CChromePreference::RenameSecurePreference()
{
	try
	{
		bool bRetVal = false;
		bool bRename = false;

		CString cszAppdataLocal,cszWebDataDBPath;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),cszAppdataLocal,HKEY_LOCAL_MACHINE);
		cszWebDataDBPath = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Web Data");

		CString cszPrefPath,cszSecurePrefPath,cszSecurePrefPathDup,cszWriteString,cszPrefPathDup,csFolderPathRec,csInvalidFolderName;
		//CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),cszAppdataLocal,HKEY_LOCAL_MACHINE);
		cszPrefPath = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Preferences");
		cszPrefPathDup = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\PreferencesDup");
		cszSecurePrefPath = cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Secure Preferences");
		cszSecurePrefPathDup =  cszAppdataLocal + _T("\\Google\\Chrome\\User Data\\Default\\Secure PreferencesDup");
		//cszSecurePrefPath =  _T("C:\\Users\\Ravinrdas\\Desktop\\Notepad files\\Secure Preferences");
		//cszSecurePrefPathDup =  _T("C:\\Users\\Ravinrdas\\Desktop\\Notepad files\\Secure PreferencesDup");
		//cszPrefPath =  _T("C:\\Users\\Ravinrdas\\Desktop\\Notepad files\\PreferencesDup");
		//cszPrefPathDup =  _T("C:\\Users\\Ravinrdas\\Desktop\\Notepad files\\PreferencesDup");


		LPTSTR lpszText = NULL;
		CString cszText,cszTokenized,cszTemp,cszTempFIcon,cszTempUrl;
		CStdioFile objStdioFile,objStdioFileDup,objStdioFileSec,objStdioFileSecDup;
		int iPos = 0;
		if(!objStdioFile.Open(cszSecurePrefPath, CFile::modeReadWrite))
		{
			OutputDebugString(_T(" splSpy>>> Secure Preference open fail returning") );
			return bRetVal;
		}
		while(objStdioFile.ReadString(cszText))
		{
			cszTokenized = cszText.Tokenize(_T("{"),iPos);
			int iPos = cszText.Find(_T("\"startup_urls\""));
			int iExtPath = cszText.Find(_T("\"startup_urls\""));
			cszTempUrl = cszText;
			int iPathCnt = cszTempUrl.Replace(_T("\"startup_urls\""),_T("\"Max\""));
			cszTempUrl = cszText;
			CString cszOrgignalStr;
			cszOrgignalStr = cszText;
			if(iExtPath != -1)
			{
				for(int iPos =0; iPos<iPathCnt; iPos++)
				{ 
					cszTempUrl = cszOrgignalStr;
					iExtPath = cszTempUrl.Find(_T("\"startup_urls\""));
					if(iExtPath != -1)
					{
						cszTempUrl.Delete(0, cszTempUrl.Find(_T("\"startup_urls\"")) + 17);
						cszOrgignalStr = cszTempUrl;
						int j = cszTempUrl.Find(_T("\""));
						int iLen = cszTempUrl.GetLength();
						iLen -= j;
						int iret = cszTempUrl.Delete(j,iLen);
						cszTempUrl.Replace(_T("\\\\"),_T("\\"));

						CString cszFolderName;

						cszFolderName = cszTempUrl;

						if(cszFolderName.Find(_T("www.")) == -1 && cszFolderName.Find(_T(".com")) == -1 && cszFolderName.Find(_T("http")) == -1 && cszFolderName.Find(_T("https")) == -1)
							continue;
					
						bool bRenameVal = false;
						char m_szWhiteIniFile[MAX_PATH];
						sprintf(m_szWhiteIniFile, "%S", m_csFilePath);
						if(!PathFileExists(m_csFilePath))
						{
							return false;
						}
						CString csRegistryValName,csRegistryName;
						int iPathLength = 1024*2;
						m_nRegistryValueCount = GetPrivateProfileIntA("WHITEURLS","Count",0,m_szWhiteIniFile);
						for(int nCount = 1; nCount <= m_nRegistryValueCount && (!bRenameVal); nCount++ )
						{
							csRegistryValName.Format(_T("%d"),nCount);
							GetPrivateProfileString(_T("WHITEURLS"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, m_csFilePath);
							if(cszFolderName.Find(csRegistryValName)== -1 && !(cszFolderName.IsEmpty()))
							{
								
								// if urls not match then true
								bRenameVal = false;
								bRename = true;
							}
							else
							{
								// if urls  match then false
								bRenameVal = true;
								bRename = false;
							}
						}
					}
					else
					{
						continue;
					}
					if(bRename)
						break;
				
				}
			}
		}
		//favicon_url
		objStdioFile.Close();
		
		if(bRename)
		{
			if(PathFileExists(cszSecurePrefPathDup))
				DeleteFile(cszSecurePrefPathDup);
			if(PathFileExists(cszSecurePrefPath))
			{
				if(_wrename(cszSecurePrefPath,cszSecurePrefPathDup) == 0)
				{			
					bRetVal = true;
				}
				else
				{
					bRetVal = false;
				}
			}
			if(PathFileExists(cszPrefPathDup))
				DeleteFile(cszPrefPathDup);
			if(PathFileExists(cszPrefPath))
			{
				if(_wrename(cszPrefPath,cszPrefPathDup) == 0)
				{			
					bRetVal = true;
				}
				else
				{
					bRetVal = false;
				}
			}
		}
		return bRetVal;
	}
	catch(...)
	{
		return false;
	}
}
bool CChromePreference::RenamePrefsJS()
{
	try
	{
		bool bRetVal = false;
		bool bRename = false;

		DWORD dwBlockPopVal = 0;
		CRegistry objReg;
		
		CString csMozillaFolderPath;
		CString csAppdataLocalRoming;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"),csAppdataLocalRoming,HKEY_LOCAL_MACHINE);
		CString csProfileIniPath = csAppdataLocalRoming + _T("\\Mozilla\\Firefox\\profiles.ini");
		csAppdataLocalRoming = csAppdataLocalRoming + _T("\\Mozilla\\Firefox\\");
		CString csRegistryValName;
		int iPathLength = 1024*2;
		csRegistryValName = _T("Path");
		GetPrivateProfileString(_T("Profile0"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, csProfileIniPath);
		csAppdataLocalRoming.Replace(_T("\\"),_T("/"));
		CString cs;
		cs.Format(_T("%s%s/prefs.js"),csAppdataLocalRoming,csRegistryValName);
		CString csPrefFilePath = cs;//_T("C:\\Users\\Ravinrdas\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xajsjuli.default\\prefs.js");
		cs.Format(_T("%s%s/prefsDup.js"),csAppdataLocalRoming,csRegistryValName);
		CString csPrefFilePathDup = cs;//_T("C:\\Users\\Ravinrdas\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xajsjuli.default\\prefsDup.js");

		CString csText;
		CStdioFile theFile;
		if(!theFile.Open(csPrefFilePath, CFile::modeReadWrite))
		{
			return false;
		}
		
		while(theFile.ReadString(csText))
		{

			CString csOrgStr = csText;
			if(csText.Find(',') != -1)
			{
				int i = (csText.Find(','));
				csText.Delete(0, csText.Find(',') + 3);
				int j = (csText.Find('\"'));
				i = csText.GetLength();
				i -= j;
				csText.Delete(j, i);
				CString cszFolderName;
				cszFolderName = csText;
				if(cszFolderName.Find(_T("www.")) == -1 && cszFolderName.Find(_T(".com")) == -1)
					continue;
					
				bool bRenameVal = false;
				char m_szWhiteIniFile[MAX_PATH];
				sprintf(m_szWhiteIniFile, "%S", m_csFilePath);
				if(!PathFileExists(m_csFilePath))
				{
					return false;
				}
				CString csRegistryValName,csRegistryName;
				int iPathLength = 1024*2;
				m_nRegistryValueCount = GetPrivateProfileIntA("WHITEURLS","Count",0,m_szWhiteIniFile);
				for(int nCount = 1; nCount <= m_nRegistryValueCount && (!bRenameVal); nCount++ )
				{
					csRegistryValName.Format(_T("%d"),nCount);
					GetPrivateProfileString(_T("WHITEURLS"), csRegistryValName, _T("0"), csRegistryValName.GetBuffer(iPathLength), iPathLength, m_csFilePath);
					int iIndex = 0;
					iIndex =  cszFolderName.Find(csRegistryValName);
					if(iIndex == -1)
					{
						
						// if urls not match then true
						bRenameVal = false;
						bRename = true;
					}
					else
					{
						// if urls  match then false
						bRenameVal = true;
						bRename = false;
					}
				}
			}
		}
		
		

		theFile.Close();
		
		if(bRename)
		{
				if(PathFileExists(csPrefFilePathDup))
					DeleteFile(csPrefFilePathDup);
				if(PathFileExists(csPrefFilePath))
				{
					if(_wrename(csPrefFilePath,csPrefFilePathDup) == 0)
					{
						bRetVal = true;
					}
					else
					{
						bRetVal = false;
					}
				}
		}

		return bRetVal;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::RenamePrefsJS"));
		return false;
	}
}
bool CChromePreference::EnumrateRegKey(CString csKey,HKEY HiveRoot)
{
	try
	{
		CRegistry objReg;
		CStringArray arrKeys;
		//CString csKey = csKey;
		objReg.EnumSubKeys(csKey, arrKeys, HiveRoot);
		INT_PTR nKeyCount = arrKeys.GetCount();
		for(int iCtr = 0; iCtr < nKeyCount; iCtr++)
		{
			CString csKeyInarr = arrKeys.GetAt(iCtr);
			//csKeyInarr = csKeyInarr + _T("\\Software\\Microsoft\\Internet Explorer\\Main");
			//if(objReg.KeyExists(csKeyInarr,HKEY_LOCAL_MACHINE))
			SetToDefaultIE(csKeyInarr,HKEY_USERS);
		}
		DWORD dwVal = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey,_T("IEOffline"),dwVal,HKEY_LOCAL_MACHINE);
		objReg.DeleteValue(CSystemInfo::m_csProductRegKey,_T("IEOffline"),HKEY_LOCAL_MACHINE);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::EnumrateRegKey"));
		return false;
	}
}
bool CChromePreference::SetToDefaultIE(CString csUsers,HKEY HiveRoot)
{
	try
	{ 
		int iLen = csUsers.GetLength();
		int iIEVersion = 0;
		
		DWORD dwVal = 0;
		CString cszRegKey;
		cszRegKey = csUsers + _T("\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("IEOffline"),dwVal,HKEY_LOCAL_MACHINE);
		if(dwVal == 1)
		{
			dwVal = 0;
			OutputDebugString(_T("Setting IE to online mode ") + cszRegKey);
			if(objReg.ValueExists(cszRegKey,_T("GlobalUserOffline"),HiveRoot))
				objReg.Set(cszRegKey,_T("GlobalUserOffline"),dwVal,HiveRoot);
			int i = GetLastError();
			CString csLog;
			csLog.Format(_T("IE Online last error is : %d"),i);
			OutputDebugString(csLog);
		}
		if(iLen<9)
		{
			return false;
		}
		iIEVersion = GetIEVersion();
		//CString cszRegKey;
		cszRegKey = csUsers + _T("\\Software\\Microsoft\\Internet Explorer\\Main");
		if(objReg.KeyExists(cszRegKey,HiveRoot))
		{
			if(iIEVersion == 6)
			{
				OutputDebugString(_T("SPCLSPY>>IE6 INSTALLED"));
				if(objReg.ValueExists(cszRegKey,_T("Default_Page_URL"),HiveRoot))
					objReg.DeleteValue(cszRegKey,_T("Default_Page_URL"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Default_Search_URL"),HiveRoot))
					objReg.DeleteValue(cszRegKey,_T("Default_Search_URL"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Search page"),HiveRoot))
					objReg.Set(cszRegKey,_T("Search Page"),_T("http://go.microsoft.com/fwlink/?LinkId=54896"),HiveRoot); 
				if(objReg.ValueExists(cszRegKey,_T("Start Page"),HiveRoot))
					objReg.Set(cszRegKey,_T("Start Page"),_T("http://go.microsoft.com/fwlink/?LinkId=69157"),HiveRoot); 
			}
			else if(iIEVersion == 7)
			{
				OutputDebugString(_T("SPCLSPY>>IE7 INSTALLED"));
				if(objReg.ValueExists(cszRegKey,_T("Default_Page_URL"),HiveRoot))
					objReg.DeleteValue(cszRegKey,_T("Default_Page_URL"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Default_Search_URL"),HiveRoot))
					objReg.DeleteValue(cszRegKey,_T("Default_Search_URL"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Search page"),HiveRoot))
					objReg.Set(cszRegKey,_T("Search Page"),_T("http://go.microsoft.com/fwlink/?LinkId=54896"),HiveRoot); 
				if(objReg.ValueExists(cszRegKey,_T("Start Page"),HiveRoot))
					objReg.Set(cszRegKey,_T("Start Page"),_T("http://go.microsoft.com/fwlink/?LinkId=69157"),HiveRoot); 
			}
			else if(iIEVersion == 8)
			{
				OutputDebugString(_T("SPCLSPY>>IE8 INSTALLED"));
				objReg.Set(cszRegKey,_T("Start Page Redirect Cache"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Default_Page_URL"),HiveRoot))
					objReg.DeleteValue(cszRegKey,_T("Default_Page_URL"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Default_Search_URL"),HiveRoot))
					objReg.DeleteValue(cszRegKey,_T("Default_Search_URL"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Search Page"),HiveRoot))
					objReg.Set(cszRegKey,_T("Search Page"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot); 
				if(objReg.ValueExists(cszRegKey,_T("Start Page"),HiveRoot))
					objReg.Set(cszRegKey,_T("Start Page"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot); 
			}
			else if(iIEVersion > 8)
			{
				OutputDebugString(_T("SPCLSPY>>IE >8 INSTALLED"));
				objReg.Set(cszRegKey,_T("Default_Page_URL"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot);
				objReg.Set(cszRegKey,_T("Default_Search_URL"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot);
				if(objReg.ValueExists(cszRegKey,_T("Search Page"),HiveRoot))
				objReg.Set(cszRegKey,_T("Search Page"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot); 
				if(objReg.ValueExists(cszRegKey,_T("Start Page"),HiveRoot))
				objReg.Set(cszRegKey,_T("Start Page"),_T("https://www.google.com/?gfe_rd=cr&ei=zqe4Vda_KIv4vQTc0JS4DA&gws_rd=ssl"),HiveRoot); 
			}
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CChromePreference::SetToDefaultIE"));
		return false;
	}
}
void CChromePreference::CleanBrowsers()
{
	CheckInstalledBrowsers();
	if(m_bCleanIE)
	{
		EnumrateRegKey(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),HKEY_LOCAL_MACHINE);
	}
	if(m_bCleanChrome)
	{
		RemoveToolbarFromChrome();
		RemoveExtensionFromChrome();
		RenameSecurePreference();
		RemoveUrl();
	}
	if(m_bCleanFireFox)
	{
		ResetMozillaUsingPrefJS();
		RemoveToolbarFromMozilla();
		RenamePrefsJS();
	}
	if(m_bCleanOpera)
	{
		CleanOpera();
	}
	RemoveCommandLine();
}
void CChromePreference::CleanOpera()
{
	CString csOperaFolderPath;
	CString csAppdataLocalRoming;
	CString cszPreference,cszPreferenceDup;
	CRegistry objReg;
	
	objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"),csAppdataLocalRoming,HKEY_LOCAL_MACHINE);
	csAppdataLocalRoming = csAppdataLocalRoming + _T("\\Opera Software\\Opera Stable\\Extensions");
	EnumrateAndRenameFolder(csAppdataLocalRoming,true,true);
	objReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"),csAppdataLocalRoming,HKEY_LOCAL_MACHINE);
	cszPreference = csAppdataLocalRoming + _T("\\Opera Software\\Opera Stable\\Preferences");
	cszPreferenceDup = csAppdataLocalRoming + _T("\\Opera Software\\Opera Stable\\PreferencesDup");
	if(PathFileExists(cszPreferenceDup))
		DeleteFile(cszPreferenceDup);
	if(PathFileExists(cszPreference))
	{
		_wrename(cszPreference, cszPreferenceDup);
	}
}
int CChromePreference::GetIEVersion()
{
	int iIEVersion = 0;
	CString cszIEVersion;
	CRegistry objReg;
	cszIEVersion = _T("");
	objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer"),_T("Version"),cszIEVersion,HKEY_LOCAL_MACHINE);
	if(!cszIEVersion.IsEmpty())
	{
		cszIEVersion.Delete(1,cszIEVersion.GetLength());
		iIEVersion = _ttoi(cszIEVersion);
	}
	else
	{
		objReg.Get(_T("SOFTWARE\\Microsoft\\Internet Explorer"),_T("W2kVersion"),cszIEVersion,HKEY_LOCAL_MACHINE);
		if(cszIEVersion.IsEmpty())
			iIEVersion = 0;
		cszIEVersion.Delete(1,cszIEVersion.GetLength());
		iIEVersion = _ttoi(cszIEVersion);
	}
	return iIEVersion;
}
void CChromePreference::CheckInstalledBrowsers()
{
	CRegistry objReg;
	CString cszPath,cszRegKey;
	m_bCleanIE = true;
	m_bCleanChrome = false;
	m_bCleanFireFox = false;
	m_bCleanOpera = false;
	cszRegKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE");
	if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
	{
		objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
		if(!cszPath.IsEmpty())
		{
			cszPath.Replace('\"',' ');
			cszPath.TrimLeft();
			cszPath.TrimRight();
			if(PathFileExists(cszPath))
				m_bCleanIE = true;
		}
	}
	else
	{
		cszRegKey = _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE");
		if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
		{
			objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
			if(!cszPath.IsEmpty())
			{
				cszPath.Replace('\"',' ');
				cszPath.TrimLeft();
				cszPath.TrimRight();
				if(PathFileExists(cszPath))
					m_bCleanIE = true;
			}
		}
	}
	cszRegKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe");
	if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
	{
		objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
		if(!cszPath.IsEmpty())
		{
			cszPath.Replace('\"',' ');
			cszPath.TrimLeft();
			cszPath.TrimRight();
			if(PathFileExists(cszPath))
				m_bCleanChrome = true;
		}
	}
	else
	{
		cszRegKey = _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe");
		if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
		{
			objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
			if(!cszPath.IsEmpty())
			{
				cszPath.Replace('\"',' ');
				cszPath.TrimLeft();
				cszPath.TrimRight();
				if(PathFileExists(cszPath))
					m_bCleanChrome = true;
			}
		}
	}
	cszRegKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe");
	if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
	{
		objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
		if(!cszPath.IsEmpty())
		{
			cszPath.Replace('\"',' ');
			cszPath.TrimLeft();
			cszPath.TrimRight();
			if(PathFileExists(cszPath))
				m_bCleanFireFox = true;
		}
	}
	else
	{
		cszRegKey = _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe");
		if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
		{
			objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
			if(!cszPath.IsEmpty())
			{
				cszPath.Replace('\"',' ');
				cszPath.TrimLeft();
				cszPath.TrimRight();
				if(PathFileExists(cszPath))
					m_bCleanFireFox = true;
			}
		}
	}
	cszRegKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\opera.exe");
	if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
	{
		objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
		if(!cszPath.IsEmpty())
		{
			cszPath.Replace('\"',' ');
			cszPath.TrimLeft();
			cszPath.TrimRight();
			if(PathFileExists(cszPath))
				m_bCleanOpera = true;
		}
	}
	else
	{
		cszRegKey = _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\opera.exe");
		if(objReg.KeyExists(cszRegKey,HKEY_LOCAL_MACHINE))
		{
			objReg.Get(cszRegKey,_T(""),cszPath,HKEY_LOCAL_MACHINE);
			if(!cszPath.IsEmpty())
			{
				cszPath.Replace('\"',' ');
				cszPath.TrimLeft();
				cszPath.TrimRight();
				if(PathFileExists(cszPath))
					m_bCleanOpera = true;
			}
		}
	}
}