#include "pch.h"
#include "NetWorkUserValidation.h"
#include "winnetwk.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "ws2_32.lib")

CNetWorkUserValidation::CNetWorkUserValidation(void)
{
	iLoopCount = 0;
}

CNetWorkUserValidation::~CNetWorkUserValidation(void)
{
}
BOOL CNetWorkUserValidation::ImpersonateLocalUser(TCHAR *szUsername, TCHAR *szPassword)
{
	HANDLE hToken = NULL;
	LogonUser(szUsername, L"NT AUTHORITY", szPassword, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hToken);
	if(hToken!=NULL)
		if ( !ImpersonateLoggedOnUser( hToken ) )
		{
			return false;
		}
		else
		{			
			return true;
		}	


}
BOOL CNetWorkUserValidation::NetworkValidation(TCHAR *szMachineName,TCHAR *szUsername, TCHAR *szPassword)
{

	USE_INFO_2 ui = {
		0, 0, (PWSTR)szPassword, 0, USE_IPC, 0, MAXDWORD, (PWSTR)szUsername	};	
	ui.ui2_remote = (PWSTR)alloca((wcslen(szMachineName) + 8) *sizeof(WCHAR));

	swprintf(ui.ui2_remote, L"\\\\%s\\IPC$", szMachineName);



	ULONG ulDelErr;
	if(!(ulDelErr = NetUseDel(0,ui.ui2_remote,USE_LOTS_OF_FORCE)))
	{
	}
	else
	{
		DWORD dwResult = WNetCancelConnection2(ui.ui2_remote,CONNECT_UPDATE_PROFILE,true);
	}


	ULONG ParmError, err;
	if (!(err = NetUseAdd(0, 2, (PBYTE)&ui, &ParmError)))   //to validate username paassword
	{					
		return true;
	}
	else
	{		
		if(err != 1219)
		{
			return false;
		}
		else
		{						
			if(NetworkValidation(GetIPAddress(szMachineName), szUsername, szPassword))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}   
	return true;

}
TCHAR* CNetWorkUserValidation::GetIPAddress(TCHAR *szMachinename)
{
	WSADATA wsaData;
    int iResult;

    DWORD dwError;
    int i = 0;

    struct hostent *remoteHost;
    char *host_name;
    struct in_addr addr;
	char **pAlias;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
       // printf("WSAStartup failed: %d\n", iResult);
        return NULL;
    }

	TCHAR szIPaddr[MAX_PATH]={0};
	char chmachinename[MAX_PATH]={0};
	wcstombs(chmachinename,szMachinename,MAX_PATH);
	remoteHost = gethostbyname(chmachinename);
    
    if (remoteHost == NULL) {
        dwError = WSAGetLastError();
        if (dwError != 0) {
            if (dwError == WSAHOST_NOT_FOUND) {
                return NULL;
            } else if (dwError == WSANO_DATA) {
                return NULL;
            } else {
                return NULL;
            }
        }
    } else {
		CString csFormat;
		for (pAlias = remoteHost->h_aliases; *pAlias != 0; pAlias++) {
			csFormat.Format(L"\tAlternate name #%d: %s\n",++i, *pAlias);
            OutputDebugString(csFormat);
        }
        OutputDebugString(L"\tAddress type: ");
        switch (remoteHost->h_addrtype) {
        case AF_INET:
            OutputDebugString(L"AF_INET\n");
            break;
        case AF_NETBIOS:
            OutputDebugString(L"AF_NETBIOS\n");
            break;
        default:
			csFormat.Format(L" %d\n", remoteHost->h_addrtype);
             OutputDebugString(csFormat);           
            break;
        }
		csFormat.Format(L"\tAddress length: %d\n", remoteHost->h_length);
        OutputDebugString(csFormat);

        i = 0;
        if (remoteHost->h_addrtype == AF_INET)
        {
            while (remoteHost->h_addr_list[i] != 0) {
                addr.s_addr = *(u_long *) remoteHost->h_addr_list[i++];
				
				mbstowcs(szIPaddr, inet_ntoa(addr),MAX_PATH);
				csFormat.Format(L"\tIP Address #%d: %s\n", i, szIPaddr);
                 OutputDebugString(csFormat);               
            }
        }
        else if (remoteHost->h_addrtype == AF_NETBIOS)
        {   
            OutputDebugString(L"NETBIOS address was returned\n");
        }   
    }
		return szIPaddr;
}