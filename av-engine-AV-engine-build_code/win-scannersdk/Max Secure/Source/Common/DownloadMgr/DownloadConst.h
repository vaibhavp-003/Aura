#pragma once
#include "pch.h"
#ifndef LIVE_UPDATE
#include <winhttp.h>
#endif
#include <shlwapi.h>
#include "MBotConsts.h"

const int MAX_PATH_LENGTH = MAX_PATH * 2;
const int STATUS_INTERVAL = 3;
const int BLUE_COLOUR = 1;
const int WHITE_COLOUR = 2; 
const int RED_COLOUR = 3; 
const int GE_BLUE_COLOR = 4;

const TCHAR X86OS[] =	_T("32");
const TCHAR X64OS[] =	_T("64");

const TCHAR RUN_KEY[] = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");

const TCHAR DOWNLOAD_MGR_REGVALUE[] = _T("AuDownloadMgr");

const TCHAR SDDATABASE_EXE_NAME[] = _T("AUFDB.exe");

/*************************CONFIGURABLE***********************************************/


#if RELEASE_ULTRA
// Regnow MaxTS link
const TCHAR PRODUCT_URL32[] = L"";	//Product download path X86
const TCHAR PRODUCT_URL64[] = L"";	//Product download path X64
const TCHAR PRODUCT_ID[]	= _T("18");
const TCHAR PRODUCT_EXE_NAME32[] = _T("UltraAV.exe");
const TCHAR PRODUCT_EXE_NAME64[] = _T("UltraAVX64.exe");
const TCHAR DOWNLOADMGR_UI_TITLE[] =	_T("UltraAV Download Manager");
const TCHAR DOWNLOADMGR_UI_MSG[]   =	_T("Downloading UltraAV...");
const TCHAR DOWNLOADMGR_TRAYMSG[]   =	_T("UltraAV Downloading...");
const TCHAR DOWNLOADMGR_INSTANCE_MSG[]   =	_T("Download Manager is already running");
const TCHAR DOWNLOADMGR_GUID[]		= _T("{143B6425-A02C-47e1-975D-A53A36E8DAF0}");
const int DOWNLOADMGR_COLOR = RED_COLOUR;


#endif

const TCHAR DOWNLOADMGR_UI_CONNECTMSG[]   =	_T("Connecting...");
const int DEFAULT_DOWNLOAD_THREAD = 4;
const int INTERNET_CHECK_INTERVAL = 5000;

/*************************CONFIGURABLE************************************************/

const TCHAR DOWNLOAD_STATUS_LOG[] = _T("Audownloader.log");
const TCHAR DOWNLOAD_PRODUCT_FOLDER[] = _T("\\AuDownloader\\");
const TCHAR DOWNLOAD_TEMP_FOLDER[] = _T("AuDownloadTemp\\");


#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

#pragma pack(1)
typedef struct DownloadFileInfo
{
	DWORD dwFileSize;
	DWORD dwDownloadThreadCount;
	TCHAR szMainUrl[URL_SIZE];
	TCHAR szLocalTempDownloadPath[MAX_PATH_LENGTH];
	TCHAR szLocalPath[MAX_PATH_LENGTH];
	TCHAR szSectionName[50];
	TCHAR szFileMD5[MAX_PATH];
	TCHAR szETAG[MAX_PATH];
	bool bCheckMD5;
	bool bCheckETag;
	TCHAR szExeName[MAX_BINARY_SIZE];
	WORD wPriority;
}STRUCT_DOWNLOAD_INFO,*LPSTRUCT_DOWNLOAD_INFO;
#pragma pack()
typedef struct HeaderInfo
{
	DWORD dwFileSize;
	HINTERNET hSession;
	HINTERNET hConnect;
	HINTERNET hRequest;
	TCHAR szHostName[MAX_PATH];
	TCHAR szMainUrl[URL_SIZE];
	TCHAR szBinaryName[MAX_PATH];
	TCHAR szETag[MAX_PATH];
}STRUCT_HEADER_INFO,*LP_STRUCT_HEADER_INFO;

typedef struct UserInfo
{
	DWORD dwThreadCount;	
	TCHAR szMainUrl[URL_SIZE];
}STRUCT_USER_INFO;

enum ConnectionHandle
{
	eSessionHandle = 0,
	eConnectHandle ,
	eRequestHandle 
};