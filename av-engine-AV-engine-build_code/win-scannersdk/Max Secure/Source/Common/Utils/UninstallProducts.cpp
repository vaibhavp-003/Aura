#include "pch.h"
#include "UninstallProducts.h"
#include "Cpuinfo.h"
#include "EnumProcess.h"

#define DEBUG_MACRO(x)		OutputDebugString((x));
typedef BOOL (WINAPI *LPFN_DISABLEWOW64REDIRECTION)(PVOID *OldValue);
typedef BOOL (WINAPI *LPFN_REVERTWOW64REDIRECTION)(PVOID OlValue);

CUninstallProducts::CUninstallProducts()
{
	m_dwTimeOut = 1000 * 60 * 2;
	m_bKIS2010Done = false;
	m_bKAV2010Done = false;
	m_bKAV2011Done = false;
	m_bKIS2011Done = false;
	m_hProcess = NULL;
}

CUninstallProducts::~CUninstallProducts()
{
	CloseProcessHandle();
}

bool CUninstallProducts::CheckForIncompatProds(CStringArray& csArrProdList)
{
	CRegistry objRegistry;
	HKEY hHive = HKEY_LOCAL_MACHINE;
	bool bMatched = false, bOtherProductFound = false;
	CStringArray csArrKnownProd, csArrKeysListCheck;
	CString csTemp, csKey, csData, csHold, csMainKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

	csArrKnownProd.Add(g_szKaspIS2010);
	csArrKnownProd.Add(g_szNP2010);
	csArrKnownProd.Add(g_szKaspAV2010);
	csArrKnownProd.Add(g_szQHAV);
	csArrKnownProd.Add(g_szQHFWPro);
	csArrKnownProd.Add(g_szQHIS);
	csArrKnownProd.Add(g_szQHTS);
	csArrKnownProd.Add(g_szEScanAV);
	csArrKnownProd.Add(g_szTMISPro);
	csArrKnownProd.Add(g_szAviraPSS);
	csArrKnownProd.Add(g_szSunPFW);
	csArrKnownProd.Add(g_szAvastAV);
	csArrKnownProd.Add(g_szVipre);
	csArrKnownProd.Add(g_szKaspIS2011);
	csArrKnownProd.Add(g_szKaspAV2011);
	csArrKnownProd.Add(g_szNP2011);
	csArrKnownProd.Add(g_szNPManual);
	csArrKnownProd.Add(g_szKaspIS2012);
	csArrKnownProd.Add(g_szTMTitanIS);
	csArrKnownProd.Add(g_szVipreAV2012);
	csArrKnownProd.Add(g_szQHAVPro);
	csArrKnownProd.Add(g_szKaspAV2012);
	csArrKnownProd.Add(g_szNPManual2012);
	csArrKnownProd.Add(g_szNP2012);
	csArrKnownProd.Add(g_szAviraAVP);
	
	csArrKnownProd.Add(g_szMcAfeeIS);
	csArrKnownProd.Add(g_szKaspIS2013);
	csArrKnownProd.Add(g_szAVG2013);
	csArrKnownProd.Add(g_szNortonIS);
	csArrKnownProd.Add(g_szNortonAV);
	csArrKnownProd.Add(g_szNorton360);
	csArrKnownProd.Add(g_szMcAfeeTP);
	csArrKnownProd.Add(g_szMcAfeeAVPlus);
	csArrKnownProd.Add(g_szMcAfeeFP);

	objRegistry.EnumSubKeys(csMainKey, csArrKeysListCheck, HKEY_LOCAL_MACHINE);

	for(int i = 0, iTotalCount = (int)csArrKeysListCheck.GetCount(); i < iTotalCount; i++)
	{
		bMatched = false;
		csData = _T("");

		csKey = csMainKey + _T("\\") + csArrKeysListCheck.GetAt(i);
		objRegistry.Get(csKey, _T("DisplayName"), csData, hHive);
		if(_T("") == csData)
		{
			continue;
		}

		for(int j = 0, iProdCount = (int)csArrKnownProd.GetCount(); j < iProdCount; j++)
		{
			if(0 == csData.CompareNoCase(csArrKnownProd.GetAt(j)))
			{
				bMatched = true;
				break;
			}
		}

		if(bMatched)
		{
			bMatched = false;
			csHold = _T("");

			if(csData == g_szVipre)
			{
				bMatched = true;
			}
			else
			{
				objRegistry.Get(csKey, _T("QuietUninstallString"), csHold, hHive);
				if(_T("") == csHold)
				{
					objRegistry.Get(csKey, _T("UninstallString"), csHold, hHive);
				}

				if((_T("") != csHold) && (_T("") != csData))
				{
					bMatched = true;
				}
			}
		}

		if(bMatched)
		{
			for(int i = 0, iTotal = (int)csArrProdList.GetCount(); i < iTotal; i++)
			{
				if(0 == csData.CompareNoCase(csArrProdList.GetAt(i)))
				{
					bMatched = false;
					break;
				}
			}

			if(bMatched)
			{
				csArrProdList.Add(csData);
				bOtherProductFound = true;
			}
		}
	}

	CCPUInfo objCpu;
	CString strOS = objCpu.GetSystemWow64Dir();
	if(strOS.GetLength())
	{
		if(CheckForIncompatProdsX64(csArrProdList))
		{
			bOtherProductFound = true;
		}
	}

	return bOtherProductFound;
}

BOOL CALLBACK WndEnumChildProc(HWND hWnd, LPARAM lParam)
{
	CUninstallProducts* pUninstallProducts = (CUninstallProducts*)lParam;
	if(NULL == pUninstallProducts)
	{
		return FALSE;
	}

	if(pUninstallProducts->m_iCurChildPos == pUninstallProducts->m_iChildPos)
	{
		CWnd* pWnd = CWnd::FromHandle(hWnd);
		if(pWnd)
		{
			CListBox* pListBox = (CListBox*)pWnd;
			if(pListBox)
			{
				SendMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(60, 120));
				SendMessage(hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(60, 120));
				pUninstallProducts->m_bFoundChild = true;
				return FALSE;
			}
		}
	}

	pUninstallProducts->m_iCurChildPos++;
	return TRUE;
}

void CUninstallProducts::FindAndClick(LPCTSTR szWndTitle, LPCTSTR szWndText, DWORD dwTimeOut, int iCtrlID, int iPos)
{
	{
		CString csStr;
		csStr.Format(_T("Inside %s, %s"), szWndTitle, szWndText);
		DEBUG_MACRO(csStr);
	}

	HWND hMainWnd = 0, hChildWnd = 0;
	DWORD dwCurrent = 0, dwFinish = GetTickCount() + (dwTimeOut ? dwTimeOut : m_dwTimeOut);

	while(m_hProcess && dwCurrent < dwFinish)
	{
		if(WAIT_TIMEOUT != WaitForSingleObject(m_hProcess, 2))
		{
			break;
		}

		hMainWnd = FindWindow(NULL, szWndTitle);
		if(hMainWnd)
		{
			if(ID_CMD_BTN == iCtrlID)
			{
				hChildWnd = FindWindowEx(hMainWnd, 0, 0, szWndText);
				if(hChildWnd)
				{
					PostMessage(hChildWnd, BM_CLICK, 0, 0);
					PostMessage(hChildWnd, BM_CLICK, 0 , 0);
					PostMessage(hChildWnd, WM_LBUTTONDOWN, 0, 0);
					PostMessage(hChildWnd, WM_LBUTTONUP, 0, 0);
					Sleep(100);
					break;
				}
			}
			else if(ID_CHK_BOX == iCtrlID)
			{
				hChildWnd = FindWindowEx(hMainWnd, 0, 0, szWndText);
				if(hChildWnd)
				{
					CWnd* pWnd = CWnd::FromHandle(hMainWnd);
					if(pWnd)
					{
						CButton* pCheckBox = (CButton*)pWnd;
						if(pCheckBox)
						{
							pCheckBox->SetCheck(BST_UNCHECKED);
							Sleep(100);
							break;
						}
					}
				}
			}
			else if(ID_LST_BOX == iCtrlID)
			{
				if(-1 != iPos)
				{
					m_bFoundChild = false;
					m_iChildPos = iPos;
					m_iCurChildPos = 0;

					EnumChildWindows(hMainWnd, WndEnumChildProc, (LPARAM)this);
					if(m_bFoundChild)
					{
						Sleep(100);
						break;
					}
				}
				else
				{
					break;
				}
			}
			else
			{
				break;
			}
		}

		Sleep(10);
		dwCurrent = GetTickCount();
	}

	{
		CString csStr;
		csStr.Format(_T("Leaving %s, %s"), szWndTitle, szWndText);
		DEBUG_MACRO(csStr);
	}
}

void CUninstallProducts::InsertQuotesToFilePath(CString& csUninsString)
{
	int iExtIndex = 0;
	CString csUninsStringDup = csUninsString;

	if(csUninsString.GetAt(0) == _T('\"'))
	{
		return;
	}

	csUninsStringDup.MakeLower();
	iExtIndex = csUninsStringDup.Find(_T(".exe"));
	if(-1 == iExtIndex)
	{
		iExtIndex = csUninsStringDup.Find(_T(".msi"));
		if(-1 == iExtIndex)
		{
			return;
		}
	}

	iExtIndex += 5;
	csUninsString.Insert(0, _T("\""));
	csUninsString.Insert(iExtIndex, _T("\""));
	return;
}

bool CUninstallProducts::ExecuteProcess(LPCTSTR szCommand, LPCTSTR szArguments, DWORD dwWaitSeconds)
{
	STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
	TCHAR szFullCmdLine[MAX_PATH] = {0};
	LPFN_DISABLEWOW64REDIRECTION lpfnDisableWow64BitRedirection = NULL;
	LPFN_REVERTWOW64REDIRECTION lpfnRevert64BitRedirection = NULL;
	HMODULE hModule = NULL;
	hModule = GetModuleHandle(_T("kernel32"));
	PVOID OldValue = NULL;

	m_hProcess = NULL;
	if(hModule)
	{
		lpfnDisableWow64BitRedirection = (LPFN_DISABLEWOW64REDIRECTION)GetProcAddress(hModule, "Wow64DisableWow64FsRedirection");
		lpfnRevert64BitRedirection = (LPFN_REVERTWOW64REDIRECTION)GetProcAddress(hModule, "Wow64RevertWow64FsRedirection");
	}
	if(lpfnDisableWow64BitRedirection)
	{
		lpfnDisableWow64BitRedirection(&OldValue);
	}
	if(szCommand && szArguments)
	{
		_stprintf_s(szFullCmdLine, _countof(szFullCmdLine), _T("%s %s"), szCommand, szArguments);
	}
	else if(szCommand)
	{
		_stprintf_s(szFullCmdLine, _countof(szFullCmdLine), _T("%s"), szCommand);
	}
	else if(szArguments)
	{
		_stprintf_s(szFullCmdLine, _countof(szFullCmdLine), _T("%s"), szArguments);
	}
	else
	{
		return false;
	}

    si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
 
     // Start the child process. 
    if( !CreateProcess( NULL,			// No module name (use command line)
		szFullCmdLine,					// Command line
        NULL,							// Process handle not inheritable
        NULL,							// Thread handle not inheritable
        FALSE,							// Set handle inheritance to FALSE
        CREATE_NO_WINDOW,				// No creation flags
        NULL,							// Use parent's environment block
        NULL,           				// Use parent's starting directory 
        &si,            				// Pointer to STARTUPINFO structure
        &pi )           				// Pointer to PROCESS_INFORMATION structure
    ) 
    {
        return false;
    }

    // Wait until child process exits.

	WaitForSingleObject(pi.hProcess, dwWaitSeconds * 1000);

    // Close process and thread handles. 
    CloseHandle(pi.hThread);
	m_hProcess = pi.hProcess;
	if(lpfnRevert64BitRedirection)
	{
		lpfnRevert64BitRedirection(OldValue);
	}
	return true;
}

void CUninstallProducts::CloseProcessHandle()
{
	if(m_hProcess)
	{
		CloseHandle(m_hProcess);
	}

	m_hProcess = NULL;
}

bool CUninstallProducts::UninsQHAV(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWndsQHAV[] =
	{
		{_T("Quick Heal AntiVirus Uninstaller"), _T("Yes"), 15 * 1000},
		{_T("Quick Heal AntiVirus Uninstaller"), _T("&Yes")},
		{_T("Quick Heal AntiVirus Uninstaller"), _T("OK")},
		{_T("Quick Heal AntiVirus Uninstaller"), _T("OK")},
		{_T("Quick Heal AntiVirus Uninstaller"), _T("Yes")}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsQHAV); i++)
	{
		FindAndClick(UninsWndsQHAV[i].szWndTitle, UninsWndsQHAV[i].szWndText, UninsWndsQHAV[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsQHFWPro(const CString& csUninstallString)
{
	WNDINFO UninsWndsQHFWPro[] =
	{
		{_T("Quick Heal Firewall Pro Uninstall"), _T("&No"), 1000 * 60 * 8},
		{_T("Quick Heal Firewall Pro Uninstall"), _T("No"), 1000}
	};

	ExecuteProcess(csUninstallString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsQHFWPro); i++)
	{
		FindAndClick(UninsWndsQHFWPro[i].szWndTitle, UninsWndsQHFWPro[i].szWndText, UninsWndsQHFWPro[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsQHIS(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWndsQHIS[] =
	{
		{_T("Quick Heal Internet Security Uninstaller"), _T("&Yes")},
		{_T("Quick Heal Internet Security Uninstaller"), _T("&OK")},
		{_T("Quick Heal Internet Security Uninstaller"), _T("OK")},
		{_T("Quick Heal Internet Security Uninstaller"), _T("&No")}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninstallString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsQHIS); i++)
	{
		FindAndClick(UninsWndsQHIS[i].szWndTitle, UninsWndsQHIS[i].szWndText, UninsWndsQHIS[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsQHTS(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWndsQHTS[] =
	{
		{_T("Quick Heal Total Security Uninstaller"), _T("&Yes")},
		{_T("Quick Heal Total Security Uninstaller"), _T("&OK")},
		{_T("Quick Heal Total Security Uninstaller"), _T("OK")},
		{_T("Quick Heal Total Security Uninstaller"), _T("&No")}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninstallString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsQHTS); i++)
	{
		FindAndClick(UninsWndsQHTS[i].szWndTitle, UninsWndsQHTS[i].szWndText, UninsWndsQHTS[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsNP2010M(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWndsNP[] = 
	{
		{_T("NP Uninstall Wizard"), _T("Yes"), 2 * 1000},
		{_T("NP Uninstall Wizard"), _T("&Yes")},
		{_T("Np Installation Wizard"), _T("OK"), 5 * 1000},
		{_T("CleanUninstall"), _T("OK")},
		{_T("Installation Wizard"), _T("OK")},
		{_T("Installation Wizard"), _T("OK"), 1000},
		{_T("Installation Wizard"), _T("OK"), 1000}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsNP); i++)
	{
		FindAndClick(UninsWndsNP[i].szWndTitle, UninsWndsNP[i].szWndText, UninsWndsNP[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsNP2011(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWndsNP[] = 
	{
		{_T("NP Uninstall Wizard"), _T("Yes"), 2 * 1000},
		{_T("NP Uninstall Wizard"), _T("&Yes")},
		{_T("Np Installation Wizard"), _T("OK"), 5 * 1000},
		{_T("CleanUninstall"), _T("OK")},
		{_T("Installation Wizard"), _T("OK")},
		{_T("Installation Wizard"), _T("OK"), 1000},
		{_T("Installation Wizard"), _T("OK"), 1000}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsNP); i++)
	{
		FindAndClick(UninsWndsNP[i].szWndTitle, UninsWndsNP[i].szWndText, UninsWndsNP[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsKIS2010(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("Kaspersky Internet Security 2010"), _T("Remove Installation")},
		{_T("Kaspersky Internet Security 2010"), _T("&Next >")},
		{_T("Kaspersky Internet Security 2010"), _T("&Remove")},
		{_T("Kaspersky Internet Security 2010"), _T("&No"), 1000 * 60 * 10}
	};

	if(m_bKIS2010Done)
	{
		return true;
	}

	m_bKIS2010Done = true;
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText, UninsWnds[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsKAV2010(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("Kaspersky Anti-Virus 2010"), _T("Remove Installation")},
		{_T("Kaspersky Anti-Virus 2010"), _T("&Next >")},
		{_T("Kaspersky Anti-Virus 2010"), _T("&Remove")},
		{_T("Kaspersky Anti-Virus 2010"), _T("&No"), 1000 * 60 * 10}
	};

	if(m_bKAV2010Done)
	{
		return true;
	}

	m_bKAV2010Done = true;
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText, UninsWnds[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsMaxAV(const CString& csUninstallString)
{
	ExecuteProcess(csUninstallString, 0, 60 * 2);
	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsMaxSD(const CString& csUninstallString)
{
	ExecuteProcess(csUninstallString, 0, 60 * 2);
	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsEScanAV(const CString& csUninstallString)
{
	ExecuteProcess(csUninstallString, 0, 60 * 5);
	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsTMISPro(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWndsTMISPro[] = 
	{
		{_T("Trend Micro Internet Security Pro Installer"), _T("&Uninstall")},
		{_T("Trend Micro Internet Security Pro Installer"), _T("Restart &Later"), 1000 * 60 * 5}
	};

	if(0 == _tcsnicmp(csUninstallString, _T("MsiExec"), 7))
	{
		return false;
	}

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWndsTMISPro); i++)
	{
		FindAndClick(UninsWndsTMISPro[i].szWndTitle, UninsWndsTMISPro[i].szWndText, UninsWndsTMISPro[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsAviraPSS(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO Wnds[] = 
	{
		{_T("Setup of Avira Premium Security Suite"), _T("&Yes")},
		{_T("Setup of Avira Premium Security Suite"), _T("&No")},
		{_T("Avira Premium Security Suite"), _T("&Restart computer"), 0, ID_CHK_BOX},
		{_T("Avira Premium Security Suite"), _T("Finish")}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(Wnds); i++)
	{
		FindAndClick(Wnds[i].szWndTitle, Wnds[i].szWndText, Wnds[i].dwTimeOut, Wnds[i].iCtrlID);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsSunPFW(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("Windows Installer"), _T("&Yes")},
		{_T("Sunbelt Personal Firewall"), _T("&No")}
	};

	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText, UninsWnds[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsAvastAV(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("avast! Antivirus Setup"), _T(""), 0, ID_LST_BOX, 3},
		{_T("avast! Antivirus Setup"), _T("&Next >")},
		{_T("avast! Antivirus Setup"), _T("Restart &later")},
		{_T("avast! Antivirus Setup"), _T("&Finish")}
	};

	InsertQuotesToFilePath(csUninsString);
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText, UninsWnds[i].dwTimeOut, UninsWnds[i].iCtrlID, UninsWnds[i].iPos);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsVipre(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("VIPRE Antivirus + Antispyware"), _T("&Yes")},
		{_T("VIPRE Antivirus + Antispyware"), _T("&Next >")},
		{_T("VIPRE Antivirus + Antispyware"), _T("&Remove")}
	};

	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsKAV2011(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("Kaspersky Anti-Virus 2011"), _T("Remove Installation")},
		{_T("Kaspersky Anti-Virus 2011"), _T("&Next >")},
		{_T("Kaspersky Anti-Virus 2011"), _T("&Remove")},
		{_T("Kaspersky Anti-Virus 2011"), _T("&No"), 1000 * 60 * 10}
	};

	if(m_bKAV2011Done)
	{
		return true;
	}

	m_bKAV2011Done = true;
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText, UninsWnds[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::UninsKIS2011(const CString& csUninstallString)
{
	CString csUninsString = csUninstallString;
	WNDINFO UninsWnds[] = 
	{
		{_T("Kaspersky Internet Security 2011"), _T("Remove Installation")},
		{_T("Kaspersky Internet Security 2011"), _T("&Next >")},
		{_T("Kaspersky Internet Security 2011"), _T("&Remove")},
		{_T("Kaspersky Internet Security 2011"), _T("&No"), 1000 * 60 * 15}
	};

	if(m_bKIS2011Done)
	{
		return true;
	}

	m_bKIS2011Done = true;
	ExecuteProcess(csUninsString, 0, 2);

	for(int i = 0; i < _countof(UninsWnds); i++)
	{
		FindAndClick(UninsWnds[i].szWndTitle, UninsWnds[i].szWndText, UninsWnds[i].dwTimeOut);
	}

	CloseProcessHandle();
	return true;
}

bool CUninstallProducts::ExecuteUninstaller(const CString& csDisplayName, const CString& csUninstallString)
{
	ExecuteProcess(csUninstallString, 0, 2);
	WaitForSingleObject(m_hProcess, 1000 * 60 * 30);
	CloseProcessHandle();

	if(0 == _tcsnicmp(csDisplayName, _T("Quick Heal"), 10))
	{
		DWORD dwWaitInSecs = 0;
		CEnumProcess objEnumProc;
		TCHAR szUninsTempPath[MAX_PATH] = {0}, szUninsTempPath_[MAX_PATH] = {0};

		GetTempPath(_countof(szUninsTempPath_), szUninsTempPath_);
		if(szUninsTempPath_[0])
		{
			GetLongPathName(szUninsTempPath_, szUninsTempPath, _countof(szUninsTempPath));
			_tcscat_s(szUninsTempPath, _countof(szUninsTempPath), _T("QHUINST\\UNINST.EXE"));
		}

		while(true)
		{
			if(objEnumProc.IsProcessRunning(szUninsTempPath, false, true, false))
			{
				dwWaitInSecs += 15;
				Sleep(1000 * 15);
			}
			else
			{
				break;
			}

			if(dwWaitInSecs >= 60 * 30)
			{
				break;
			}
		}
	}

	return true;
}

bool CUninstallProducts::CheckForIncompatProdsX64(CStringArray& csArrProdList)
{
	CRegistry objRegistry;
	HKEY hHive = HKEY_LOCAL_MACHINE;
	bool bMatched = false, bOtherProductFound = false;
	CStringArray csArrKnownProd, csArrKeysListCheck;
	CString csTemp, csKey, csData, csHold;

#ifdef WIN64
	CString csMainKey = _T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");	
#else
	CString csMainKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");		
#endif

	csArrKnownProd.Add(g_szKaspIS2010);
	csArrKnownProd.Add(g_szNP2010);
	csArrKnownProd.Add(g_szKaspAV2010);
	csArrKnownProd.Add(g_szQHAV);
	csArrKnownProd.Add(g_szQHFWPro);
	csArrKnownProd.Add(g_szQHIS);
	csArrKnownProd.Add(g_szQHTS);
	csArrKnownProd.Add(g_szEScanAV);
	csArrKnownProd.Add(g_szTMISPro);
	csArrKnownProd.Add(g_szAviraPSS);
	csArrKnownProd.Add(g_szSunPFW);
	csArrKnownProd.Add(g_szAvastAV);
	csArrKnownProd.Add(g_szVipre);
	csArrKnownProd.Add(g_szKaspIS2011);
	csArrKnownProd.Add(g_szKaspAV2011);
	csArrKnownProd.Add(g_szNP2011);
	csArrKnownProd.Add(g_szNPManual);
	csArrKnownProd.Add(g_szKaspIS2012);
	csArrKnownProd.Add(g_szTMTitanIS);
	csArrKnownProd.Add(g_szVipreAV2012);
	csArrKnownProd.Add(g_szQHAVPro);
	csArrKnownProd.Add(g_szKaspAV2012);
	csArrKnownProd.Add(g_szNPManual2012);
	csArrKnownProd.Add(g_szNP2012);

	csArrKnownProd.Add(g_szMcAfeeIS);
	csArrKnownProd.Add(g_szKaspIS2013);
	csArrKnownProd.Add(g_szAVG2013);
	csArrKnownProd.Add(g_szNortonIS);
	csArrKnownProd.Add(g_szNortonAV);
	csArrKnownProd.Add(g_szNorton360);
	csArrKnownProd.Add(g_szMcAfeeTP);
	csArrKnownProd.Add(g_szMcAfeeAVPlus);
	csArrKnownProd.Add(g_szMcAfeeFP);


#ifndef WIN64
	objRegistry.SetWow64Key(true);
#endif

	objRegistry.EnumSubKeys(csMainKey, csArrKeysListCheck, HKEY_LOCAL_MACHINE);

	for(int i = 0, iTotalCount = (int)csArrKeysListCheck.GetCount(); i < iTotalCount; i++)
	{
		bMatched = false;
		csData = _T("");

		csKey = csMainKey + _T("\\") + csArrKeysListCheck.GetAt(i);
		objRegistry.Get(csKey, _T("DisplayName"), csData, hHive);
		if(_T("") == csData)
		{
			continue;
		}

		for(int j = 0, iProdCount = (int)csArrKnownProd.GetCount(); j < iProdCount; j++)
		{
			if(0 == csData.CompareNoCase(csArrKnownProd.GetAt(j)))
			{
				bMatched = true;
				break;
			}
		}

		if(bMatched)
		{
			bMatched = false;
			csHold = _T("");

			if(csData == g_szVipre)
			{
				bMatched = true;
			}
			else
			{
				objRegistry.Get(csKey, _T("QuietUninstallString"), csHold, hHive);
				if(_T("") == csHold)
				{
					objRegistry.Get(csKey, _T("UninstallString"), csHold, hHive);
				}

				if((_T("") != csHold) && (_T("") != csData))
				{
					bMatched = true;
				}
			}
		}

		if(bMatched)
		{
			for(int i = 0, iTotal = (int)csArrProdList.GetCount(); i < iTotal; i++)
			{
				if(0 == csData.CompareNoCase(csArrProdList.GetAt(i)))
				{
					bMatched = false;
					break;
				}
			}

			if(bMatched)
			{
				csArrProdList.Add(csData);
				bOtherProductFound = true;
			}
		}
	}

	return bOtherProductFound;
}