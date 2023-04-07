#include "pch.h"
#include "MessageQueue.h"

#ifdef _DEBUG

#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const TCHAR g_szMsgQueSyncObjName[] = _T("MsgQueSyncObjName");

CMessageQueueItem::CMessageQueueItem()
{
	ResetData();
}

void CMessageQueueItem::ResetData()
{
	m_nItemType = 0;
	m_dwDownloadID = 0;
	::ZeroMemory(m_szBinLMDT,sizeof(m_szBinLMDT));
	::ZeroMemory(m_szETAG,sizeof(m_szETAG));
	::ZeroMemory(m_szDomainAddress,sizeof(m_szDomainAddress));
	m_wPriority = 0;
	m_lLastVisited = 0;
	m_wProtcolType = eProtocol_HTTP;
	m_dwContentLength = 0;
	m_dwDomainCategory = 0;
	m_dwAge = 0;
}

CMessageQueueItem& CMessageQueueItem::operator=(const CMessageQueueItem &rhs)
{
	// Check for self-assignment!
    if (this == &rhs)      // Same object?
      return *this;        // Yes, so skip assignment, and just return *this.

    m_strQueueItem = rhs.m_strQueueItem;
	m_nItemType = rhs.m_nItemType;
	_tcscpy_s(m_szBinLMDT,rhs.m_szBinLMDT);
	_tcscpy_s(m_szETAG,rhs.m_szETAG);
	_tcscpy_s(m_szDomainAddress,rhs.m_szDomainAddress);
	m_wPriority = rhs.m_wPriority;
	m_lLastVisited = rhs.m_lLastVisited;
	m_wProtcolType = rhs.m_wProtcolType;
	m_dwContentLength = rhs.m_dwContentLength;
	m_dwDomainCategory = rhs.m_dwDomainCategory;
	m_dwAge = rhs.m_dwAge;
	m_dwDownloadID = rhs.m_dwDownloadID;
    return *this;
}

CMessageQueue::CMessageQueue(void)
{
	m_dwTaskItems = 0; 
	m_dwQueueLength = 0;
	m_hQueueEvent = NULL;
}

CMessageQueue::~CMessageQueue(void)
{
	DeleteQueueItem();
}

void CMessageQueue::AddQueueItem(CMessageQueueItem &objQueueItem)
{
	CAutoThreadSync m_objAutoThreadSync(g_szMsgQueSyncObjName);
	m_MsgQueue.push(objQueueItem);
}

bool CMessageQueue::FetchQueueItem(CMessageQueueItem &objQueueItem)
{
	CAutoThreadSync m_objAutoThreadSync(g_szMsgQueSyncObjName);
	if(!m_MsgQueue.empty())
	{
		objQueueItem.ResetData();
		objQueueItem = m_MsgQueue.front();
		m_MsgQueue.pop();
		return true;
	}
	else
	{
		return false;
	}	
}

void CMessageQueue::AddQueueItem(LPCTSTR szQueueItem,int nItemType)
{
	CAutoThreadSync m_objAutoThreadSync(g_szMsgQueSyncObjName);
	CMessageQueueItem objQueueItem;
	objQueueItem.m_strQueueItem = szQueueItem;
	objQueueItem.m_nItemType = nItemType;
	m_MsgQueue.push(objQueueItem);
}

void CMessageQueue::DeleteQueueItem()
{

}