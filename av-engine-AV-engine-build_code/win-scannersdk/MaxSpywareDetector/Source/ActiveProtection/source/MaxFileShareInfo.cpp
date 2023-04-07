#include "pch.h"
#include "MaxFileShareInfo.h"

CMaxFileShareInfo::CMaxFileShareInfo(void)
{
	m_hModuleNtDll = NULL;
	/*
	m_LpnfRtlIpv4StringToAddressW = NULL;
	m_LpnfRtlIpv6StringToAddressW = NULL;
	m_hModuleNtDll	= LoadLibrary(L"NtDll.dll");
	if (m_hModuleNtDll != NULL)
	{
		m_LpnfRtlIpv4StringToAddressW = (LPFN_RtlIpv4StringToAddressW)GetProcAddress(m_hModuleNtDll,"RtlIpv4StringToAddressW");
		m_LpnfRtlIpv6StringToAddressW = (LPFN_RtlIpv6StringToAddressW)GetProcAddress(m_hModuleNtDll,"RtlIpv6StringToAddressW");
	}
	*/
	m_LpfnInetPtonW = NULL;
	m_hModuleNtDll	= LoadLibrary(L"Ws2_32.dll");
	if (m_hModuleNtDll != NULL)
	{
		m_LpfnInetPtonW = (LPFN_InetPtonW)GetProcAddress(m_hModuleNtDll,"InetPtonW");
	}
}

CMaxFileShareInfo::~CMaxFileShareInfo(void)
{
	FreeLibrary(m_hModuleNtDll);
	m_hModuleNtDll = NULL;
}


BOOL CMaxFileShareInfo::GetIP4FromCompName(LPTSTR pszCompName,LPTSTR pszIpAddress)
{
	BOOL		bRetValue = FALSE;
	WSADATA		wsaData = {0};
	int			iResult = 0;
	u_short		port = 27015;
	TCHAR		szIpAddress[MAX_PATH] = {0x00};
	DWORD		dwpbufferlength = MAX_PATH;
	DWORD		dwRetval = 0x00;

	/*
	ADDRINFOW	*result = NULL;
    ADDRINFOW	*ptr = NULL;
    ADDRINFOW	hints;
	LPSOCKADDR	sockaddr_ip;
	*/
	ADDRINFOA	*result = NULL;
    ADDRINFOA	*ptr = NULL;
    ADDRINFOA	hints;
	LPSOCKADDR	sockaddr_ip;
   	
	if (pszIpAddress == NULL || pszCompName == NULL)
	{
		return bRetValue;
	}

	char	strCompName[MAX_PATH] = {0x00};	

	GetAnsiString(pszCompName,&strCompName[0x00]);

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0x00)
	{
		return bRetValue;
	}

	ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
	
	dwRetval = getaddrinfo(strCompName, NULL, &hints, &result);
	//dwRetval = GetAddrInfoW(pszCompName, NULL, &hints, &result);
    if ( dwRetval != 0 )
	{
        return bRetValue;
    }

	for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) 
	{
		if (ptr->ai_family == AF_INET)
		{
			sockaddr_ip = (LPSOCKADDR) ptr->ai_addr;
			dwpbufferlength = 46;
			int iRetval = WSAAddressToString(sockaddr_ip, (DWORD) ptr->ai_addrlen, NULL, szIpAddress, &dwpbufferlength);
		}
	}

	_tcscpy(pszIpAddress,szIpAddress);
	//FreeAddrInfoW(result);
	freeaddrinfo(result);
    WSACleanup();
	return bRetValue;
}

//getnameinfo
BOOL CMaxFileShareInfo::GetSuspComputerName(LPTSTR pszIpAddress, LPTSTR pszCompName, BOOL *bIsIPV6, LPTSTR pszIPV4Address)
{
	BOOL		bRetValue = FALSE;
	WSADATA		wsaData = {0};
	int			iResult = 0;
	u_short		port = 27015;
	TCHAR		szComputerName[MAX_PATH] = {0x00};
	TCHAR		szServerName[1024] = {0x00};
	BOOL		bIs64=FALSE;
	TCHAR		szNewIPAddress[MAX_PATH] = {0x00};

	
	if (pszIpAddress == NULL || pszCompName == NULL)
	{
		return 0x00;
	}

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0x00)
	{
		return bRetValue;
	}

	/*
	if (m_LpnfRtlIpv4StringToAddressW == NULL || m_LpnfRtlIpv6StringToAddressW == NULL)
	{
		return 0x00;
	}
	*/
	_tcscpy(szNewIPAddress,pszIpAddress);

	if (_tcsstr(szNewIPAddress,L"[") != NULL || _tcsstr(szNewIPAddress,L"::") != NULL)
	{
		CString	csDummy(szNewIPAddress);

		csDummy.Replace(L"[",L"");
		csDummy.Replace(L"]",L"");

		_tcscpy(szNewIPAddress,csDummy.GetBuffer());
		csDummy.ReleaseBuffer();

		bIs64=TRUE;
		if (bIsIPV6 != NULL)
		{
			*bIsIPV6 = TRUE;
		}
	}

	//PCWSTR pszTerm = NULL;
	PCWSTR pszTerm;
	DWORD dwError = 0x00;

	char	strNewIPAddress[MAX_PATH] = {0x00};
	char	strComputerName[MAX_PATH] = {0x00};
	char	strServerName[1024] = {0x00};

	GetAnsiString(&szNewIPAddress[0x00],&strNewIPAddress[0x00]);
	
	if (!bIs64)
	{
		struct		sockaddr_in		saGNI;
		saGNI.sin_family = AF_INET;
		saGNI.sin_addr.S_un.S_addr = inet_addr(&strNewIPAddress[0x00]);
		//RtlIpv4StringToAddressW(&szNewIPAddress[0x00],true,&pszTerm,&saGNI.sin_addr);
		//m_LpnfRtlIpv4StringToAddressW(&szNewIPAddress[0x00],true,&pszTerm,&saGNI.sin_addr);
		saGNI.sin_port = htons(port);

		getnameinfo((const SOCKADDR *)&saGNI,sizeof (struct sockaddr),&strComputerName[0x00],MAX_PATH,&strServerName[0x00],1024,NI_NUMERICSERV);
		//GetNameInfoW((struct sockaddr *) &saGNI,sizeof (struct sockaddr),&szComputerName[0x00], MAX_PATH, &szServerName[0x00], 1024, NI_NUMERICSERV);
	}
	else
	{
		struct		sockaddr_in6		saGNI;
		saGNI.sin6_family = AF_INET6;
		//m_LpnfRtlIpv6StringToAddressW(&szNewIPAddress[0x00],&pszTerm,&saGNI.sin6_addr);
		//saGNI.sin6_addr = inet_addr(&strNewIPAddress[0x00]);
		m_LpfnInetPtonW(AF_INET6,&szNewIPAddress[0x00],&saGNI.sin6_addr);
		saGNI.sin6_port = htons(port);

		//dwError = GetNameInfoW((struct sockaddr *) &saGNI,sizeof (struct sockaddr_in6),&szComputerName[0x00], MAX_PATH, &szServerName[0x00], 1024, NI_NUMERICSERV);
		getnameinfo((const SOCKADDR *)&saGNI,sizeof (struct sockaddr_in6),&strComputerName[0x00],MAX_PATH,&strServerName[0x00],1024,NI_NUMERICSERV);
		
	}
	
	bRetValue = TRUE;

	GetUnicodeString(&strComputerName[0x00],&szComputerName[0x00]);
	_tcscpy(pszCompName,szComputerName);

	if (!bIs64)
	{
		_tcscpy(pszIPV4Address,szNewIPAddress);
	}
	else
	{
		if (_tcslen(szComputerName) > 0x00)
		{
			TCHAR	szIpV4Address[MAX_PATH] = {0x00};
			GetIP4FromCompName(szComputerName,&szIpV4Address[0x00]);
			
			if (pszIPV4Address != NULL)
			{
				_tcscpy(pszIPV4Address,szIpV4Address);
			}
		}
	}

	WSACleanup();
	return bRetValue;
}

/*
BOOL CMaxFileShareInfo::GetSuspComputerName(LPTSTR pszIpAddress, LPTSTR pszCompName, BOOL *bIsIPV6, LPTSTR pszIPV4Address)
{
	BOOL		bRetValue = FALSE;
	WSADATA		wsaData = {0};
	int			iResult = 0;
	u_short		port = 27015;
	TCHAR		szComputerName[MAX_PATH] = {0x00};
	TCHAR		szServerName[1024] = {0x00};
	BOOL		bIs64=FALSE;
	TCHAR		szNewIPAddress[MAX_PATH] = {0x00};

	
	if (pszIpAddress == NULL || pszCompName == NULL)
	{
		return 0x00;
	}

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0x00)
	{
		return bRetValue;
	}

	
	if (m_LpnfRtlIpv4StringToAddressW == NULL || m_LpnfRtlIpv6StringToAddressW == NULL)
	{
		return 0x00;
	}
	
	_tcscpy(szNewIPAddress,pszIpAddress);

	if (_tcsstr(szNewIPAddress,L"[") != NULL || _tcsstr(szNewIPAddress,L"::") != NULL)
	{
		CString	csDummy(szNewIPAddress);

		csDummy.Replace(L"[",L"");
		csDummy.Replace(L"]",L"");

		_tcscpy(szNewIPAddress,csDummy.GetBuffer());
		csDummy.ReleaseBuffer();

		bIs64=TRUE;
		if (bIsIPV6 != NULL)
		{
			*bIsIPV6 = TRUE;
		}
	}

	//PCWSTR pszTerm = NULL;
	PCWSTR pszTerm;
	DWORD dwError = 0x00;
	
	if (!bIs64)
	{
		struct		sockaddr_in		saGNI;
		saGNI.sin_family = AF_INET;
		//RtlIpv4StringToAddressW(&szNewIPAddress[0x00],true,&pszTerm,&saGNI.sin_addr);
		//m_LpnfRtlIpv4StringToAddressW(&szNewIPAddress[0x00],true,&pszTerm,&saGNI.sin_addr);
		saGNI.sin_port = htons(port);

		GetNameInfoW((struct sockaddr *) &saGNI,sizeof (struct sockaddr),&szComputerName[0x00], MAX_PATH, &szServerName[0x00], 1024, NI_NUMERICSERV);
	}
	else
	{
		struct		sockaddr_in6		saGNI;
		saGNI.sin6_family = AF_INET6;
		//m_LpnfRtlIpv6StringToAddressW(&szNewIPAddress[0x00],&pszTerm,&saGNI.sin6_addr);
		saGNI.sin6_port = htons(port);

		dwError = GetNameInfoW((struct sockaddr *) &saGNI,sizeof (struct sockaddr_in6),&szComputerName[0x00], MAX_PATH, &szServerName[0x00], 1024, NI_NUMERICSERV);
		if (_tcslen(szComputerName) > 0x00)
		{
			TCHAR	szIpV4Address[MAX_PATH] = {0x00};
			GetIP4FromCompName(szComputerName,&szIpV4Address[0x00]);
			
			if (pszIPV4Address != NULL)
			{
				_tcscpy(pszIPV4Address,szIpV4Address);
			}
		}
	}
	
	bRetValue = TRUE;
	_tcscpy(pszCompName,szComputerName);
	WSACleanup();
	return bRetValue;
}
*/

BOOL CMaxFileShareInfo::EnumSharesOfUser(LPCTSTR pszUserName, LPCTSTR pszFile2Watch)
{
	BOOL	bRetValue = FALSE;

	NET_API_STATUS	fStatus;
    LPFILE_INFO_3	pFile = NULL;
	LPFILE_INFO_3	pFileInfo = NULL;
    LPFILE_INFO_3	pTmpFile;
	DWORD			dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD			dwEntriesRead = 0;
    DWORD			dwTotalEntries = 0;
    DWORD			dwResumeHandle = 0;
    DWORD			dwI;
	TCHAR			szUserName[MAX_PATH] = {0x00};
	TCHAR			szFilePath[1024] = {0x00};
	TCHAR			szUserNm2Watch[1024] = {0x00};
	TCHAR			szFile2Watch[1024] = {0x00};

	/*
	CString	csDummy(pszUserName);
	csDummy.Replace(L"[",L"");
	csDummy.Replace(L"]",L"");
	_stprintf(szUserNm2Watch,L"\\\\%s",csDummy); 
	*/

	if (pszFile2Watch == NULL)
	{
		return bRetValue;
	}

	_stprintf(szFile2Watch,pszFile2Watch);
	_tcslwr(szFile2Watch);
	_stprintf(szUserNm2Watch,pszUserName); 
	do
	{
		//fStatus = NetFileEnum(NULL,NULL,NULL,3,(LPBYTE*)&pFile,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,&dwResumeHandle);
		fStatus = NetFileEnum(NULL,NULL,szUserNm2Watch,3,(LPBYTE*)&pFile,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,NULL);
		if ((fStatus == NERR_Success) || (fStatus == ERROR_MORE_DATA))
        {
			if (pFile != NULL)
			{
				pTmpFile = pFile;
				for (dwI = 0x00; dwI < dwEntriesRead; dwI++)
				{
					if (pTmpFile == NULL)
					{
						break;
					}
					
					_stprintf(szUserName,L"%s",pTmpFile->fi3_username);
					
					_stprintf(szFilePath,L"%s",pTmpFile->fi3_pathname);
					_tcslwr(szFilePath);

					if (_tcsstr(szFilePath,szFile2Watch) != NULL)
					{
						bRetValue = TRUE;
						break;
					}
					
					/*
					//_stprintf(szFilePath,L"%s[%d]",pTmpFile->fi3_pathname,pTmpFile->fi3_id);
					//m_lstShareInfo.InsertItem(0x00,szFilePath);
					//m_lstShareInfo.SetItemText(0x00,0x01,szUserName);
					NetFileGetInfo(NULL,pTmpFile->fi3_id,3,(LPBYTE*)&pFileInfo);
					if (pFileInfo != NULL)
					{
						_stprintf(szFileDetails,L"[%d][%d]",pFileInfo->fi3_permissions,pFileInfo->fi3_num_locks);
						m_lstShareInfo.SetItemText(0x00,0x02,szFileDetails);

						NetApiBufferFree(pFileInfo);
						pFile = NULL;
					}
					*/
					dwTotalEntries++;
					pTmpFile++;
				}
				if (bRetValue == TRUE)
				{
					break;
				}
			}
		}
		if (pFile != NULL)
        {
            NetApiBufferFree(pFile);
            pFile = NULL;
        }

	}
	while (fStatus == ERROR_MORE_DATA);
    
	if (pFile != NULL)
	{
		NetApiBufferFree(pFile);
	}

	return bRetValue;
}

BOOL CMaxFileShareInfo::GetSharedFileInfo(LPCTSTR pszFile2Check, LPTSTR pszUserName, LPTSTR pszComputerName, LPTSTR pszIPV4Address, LPTSTR pszIPV6Address)
{
	BOOL	bFoundShareInfo = FALSE;


	NET_API_STATUS		fStatus;
	LPSESSION_INFO_502	pSession = NULL;
	LPSESSION_INFO_502	pTmpSession = NULL;
	DWORD				dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD				dwEntriesRead = 0;
    DWORD				dwTotalEntries = 0;
    DWORD				dwResumeHandle = 0;
    DWORD				dwI = 0x00;
	//TCHAR				szUserName[MAX_PATH] = {0x00};
	//TCHAR				szFilePath[1024] = {0x00};
	TCHAR				szNoofRes[1024] = {0x00};
	//TCHAR				szSessionCName[MAX_PATH] = {0x00},szSessionUName[MAX_PATH] = {0x00};
	
	try
	{

		do
		{
			//fStatus = NetFileEnum(NULL,NULL,NULL,3,(LPBYTE*)&pFile,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,&dwResumeHandle);
			fStatus = NetSessionEnum(NULL,NULL,NULL,502,(LPBYTE*)&pSession,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,NULL);
			if ((fStatus == NERR_Success) || (fStatus == ERROR_MORE_DATA))
			{
				if (pSession != NULL)
				{
					pTmpSession = pSession;
					for (dwI = 0x00; dwI < dwEntriesRead; dwI++)
					{
						if (pTmpSession == NULL)
						{
							break;
						}
						
						TCHAR	szCompName[MAX_PATH] = {0x00};
						BOOL	bIsIpV6 = FALSE;
						TCHAR	szIpv4Addr[MAX_PATH] = {0x00};


						if (EnumSharesOfUser(pTmpSession->sesi502_username,pszFile2Check) == TRUE)
						{

							GetSuspComputerName(pTmpSession->sesi502_cname,&szCompName[0x00],&bIsIpV6,&szIpv4Addr[0x00]);

							/*
							_stprintf(szUserName,L"%s[%s]",pTmpSession->sesi502_cname,szCompName);
							_stprintf(szFilePath,L"%s",pTmpSession->sesi502_username);
							_stprintf(szNoofRes,L"%d",pTmpSession->sesi502_num_opens);
							m_lstShareInfo.InsertItem(0x00,szFilePath);
							m_lstShareInfo.SetItemText(0x00,0x01,szUserName);
							m_lstShareInfo.SetItemText(0x00,0x02,szNoofRes);
							*/

							//_tcscpy(szSessionCName,pTmpSession->sesi502_cname);
							//_tcscpy(szSessionUName,pTmpSession->sesi502_cname);

							if (pszComputerName != NULL)
							{
								_tcscpy(pszComputerName,szCompName);
							}
							if (pszUserName != NULL)
							{
								_tcscpy(pszUserName,pTmpSession->sesi502_cname);
							}
							if (pszUserName != NULL)
							{
								_tcscpy(pszUserName,pTmpSession->sesi502_username);
							}
							if (pszIPV6Address != NULL && bIsIpV6 == TRUE)
							{
								_tcscpy(pszIPV6Address,pTmpSession->sesi502_cname);
							}
							if (pszIPV4Address != NULL)
							{
								_tcscpy(pszIPV4Address,szIpv4Addr);
							}
							bFoundShareInfo = TRUE;
							break;
						}
						
						dwTotalEntries++;
						pTmpSession++;
					}
					if (bFoundShareInfo == TRUE)
					{
						break;
					}
				}
			}
			if (pSession != NULL)
			{
				NetApiBufferFree(pSession);
				pSession = NULL;
			}
		}
		while (fStatus == ERROR_MORE_DATA);
	    
		if (pSession != NULL)
		{
			NetApiBufferFree(pSession);
		}
	}
	catch(...)
	{
		if (pSession != NULL)
		{
			NetApiBufferFree(pSession);
			pSession = NULL;
		}
	}

	/*
	if (bFoundShareInfo)
	{
		NetSessionDel(NULL,NULL,pszUserName); 
	}
	*/
	return bFoundShareInfo;
}

BOOL CMaxFileShareInfo::DelUserSession(LPCTSTR pszUserName)
{
	BOOL		bRetValue = FALSE;

	NetSessionDel(NULL,NULL,(LPTSTR)pszUserName); 

	return bRetValue;
}

BOOL CMaxFileShareInfo::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
{
	BOOL		bRetValue = FALSE;
	char		szOut[MAX_PATH] = {0x00};		

	if (pszUnicodeIN == NULL || pszAnsiOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);

	if (iRetLen > 0x00)
	{
		strcpy(pszAnsiOUT,szOut);
	}

	return bRetValue;
}
BOOL CMaxFileShareInfo::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	BOOL		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = {0x00};		

	if (pszAnsiIN == NULL || pszUnicodeOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  MultiByteToWideChar(CP_ACP,0,pszAnsiIN,strlen(pszAnsiIN),szOut,MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy(pszUnicodeOUT,szOut);
	}

	return bRetValue;
}