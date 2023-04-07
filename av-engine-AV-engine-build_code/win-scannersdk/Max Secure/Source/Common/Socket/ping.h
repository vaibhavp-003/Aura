/*======================================================================================
   FILE				: ping.h
   ABSTRACT			: Interface for an MFC wrapper class to encapsulate PING
   DOCUMENTS		: 
   AUTHOR			: 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   NOTE				:
   VERSION HISTORY	: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/
#ifndef __PING_H__
#define __PING_H__


#ifndef __AFXPRIV_H__
#pragma message("The class CPing requires AFXPRIV.H in your PCH")
#endif

#include "ipexport.h"
#ifdef CPING_USE_ICMP

//These defines & structure definitions are taken from the "ipexport.h" and
//"icmpapi.h" header files as provided with the Platform SDK and
//are used internally by the CPing class.Including them here allows
//you to compile the CPing code without the need to have the full
//Platform SDK installed.

typedef unsigned long IPAddr;     // An IP address.

typedef IP_OPTION_INFORMATION FAR* LPIP_OPTION_INFORMATION;
typedef ICMP_ECHO_REPLY FAR* LPICMP_ECHO_REPLY;
typedef HANDLE (WINAPI IcmpCreateFile)(VOID);
typedef IcmpCreateFile* lpIcmpCreateFile;
typedef BOOL (WINAPI IcmpCloseHandle)(HANDLE IcmpHandle);
typedef IcmpCloseHandle* lpIcmpCloseHandle;
typedef DWORD (WINAPI IcmpSendEcho)(HANDLE IcmpHandle, IPAddr DestinationAddress,
									LPVOID RequestData, WORD RequestSize,
									LPIP_OPTION_INFORMATION RequestOptions,
									LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout);
typedef IcmpSendEcho* lpIcmpSendEcho;

#endif //CPING_USE_ICMP


struct CPingReply
{
	in_addr	 Address;  //The IP address of the replier
	unsigned long RTT; //Round Trip time in Milliseconds
};


class CPing
{

public:

#ifdef CPING_USE_ICMP
	BOOL Ping1(LPCTSTR pszHostName, CPingReply& pr, UCHAR nTTL = 10, DWORD dwTimeout = 2000, UCHAR nPacketSize = 8)const;
#endif
#ifdef CPING_USE_WINSOCK2
	BOOL Ping2(LPCTSTR pszHostName, CPingReply& pr, UCHAR nTTL = 10, DWORD dwTimeout = 1000, UCHAR nPacketSize = 8)const;
#endif

protected:
#ifdef CPING_USE_ICMP
	BOOL Initialise1()const;
	static BOOL sm_bAttemptedIcmpInitialise;
	static lpIcmpCreateFile sm_pIcmpCreateFile;
	static lpIcmpSendEcho sm_pIcmpSendEcho;
	static lpIcmpCloseHandle sm_pIcmpCloseHandle;
#endif

#ifdef CPING_USE_WINSOCK2
	BOOL Initialise2()const;
	static BOOL sm_bAttemptedWinsock2Initialise;
	static BOOL sm_bWinsock2OK;
#endif
	static BOOL IsSocketReadible(SOCKET socket, DWORD dwTimeout, BOOL& bReadible);

	static __int64 sm_TimerFrequency;
};
#endif //__PING_H__

