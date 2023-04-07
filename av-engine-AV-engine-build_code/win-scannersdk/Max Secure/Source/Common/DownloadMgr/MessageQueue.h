#pragma once

const int DEFAULT_QUEUE_ITEMS = 1;
#include <string>
#include <queue>
using namespace std;
#include "ThreadSync.h"
#include "MBotConsts.h"
#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif
class CMessageQueue;

#ifndef DOWNLOAD_BOT
enum MA_Protocol_Type
{
	eProtocol_HTTP,
	eProtocol_FTP
};
#else
#include "SockStructures.h"	
#endif

class CMessageQueueItem
{
public:	
	tstring m_strQueueItem;
	int m_nItemType;
	DWORD m_dwDownloadID;
	TCHAR m_szBinLMDT[LMDT_SIZE];
	TCHAR m_szETAG[ETAG_SIZE];
	TCHAR m_szDomainAddress[DOMAIN_SIZE];
	WORD m_wPriority;
	ULONGLONG m_lLastVisited;
	WORD m_wProtcolType;
	DWORD m_dwContentLength;
	DWORD m_dwDomainCategory;
	DWORD m_dwAge;
	CMessageQueueItem();
	CMessageQueueItem& operator=(const CMessageQueueItem &rhs); 
	void ResetData();
};
class CMessageQueue
{
public:
	CMessageQueue(void);
	~CMessageQueue(void);
	std::queue<CMessageQueueItem> m_MsgQueue;
	DWORD m_dwTaskItems;
	DWORD m_dwQueueLength;
	HANDLE m_hQueueEvent;//Do Not Close This handle
	void AddQueueItem(CMessageQueueItem &objQueueItem);
	bool FetchQueueItem(CMessageQueueItem &objQueueItem);
	void AddQueueItem(LPCTSTR szQueueItem, int nItemType);
	void DeleteQueueItem();
};
