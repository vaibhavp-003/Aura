#include "pch.h"
#include "DBWrapper.h"
#include "sqlite3.h"


CDBWrapper::CDBWrapper(void)
{
	m_pPCSafeDB = NULL;
	m_bEnumStarted = false;
}

CDBWrapper::~CDBWrapper(void)
{
	m_bEnumStarted = false;
	if(m_pPCSafeDB != NULL)
	{
		sqlite3_close(m_pPCSafeDB);
	}
}
bool CDBWrapper::OpenDB(const char *pszDBPath)
{
	
	int iRet = 0x00;


	iRet = sqlite3_open(pszDBPath, &m_pPCSafeDB);
	if(iRet == SQLITE_OK)
	{
		return true;
	}
	else
	{
		m_pPCSafeDB = NULL;
		return false;
	}

}
bool CDBWrapper::InsertDefaultGoogle(const char *pszFilePath)
{
	/*if (IsAlreadyExists(pszFilePath) == true)
	{
		return true;
	}*/

	sqlite3_stmt	*stmInsert;
	char			szQuery[8192] = {0x00};
	char			szPath2Add[512] =  {0x00};
	
	// Table fields
	int				iId = 1;
	char			szShort_name[512] =  {"google"};
	char			szKeyword[512] =  {"google.com"};
	char			szFavicon_url[512] =  {"http://www.google.com/favicon.ico"};//
	char			szUrl[2048] =  {"{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:bookmarkBarPinned}{google:searchClient}{google:sourceId}{google:instantExtendedEnabledParameter}{google:omniboxStartMarginParameter}{google:contextualSearchVersion}ie={inputEncoding}"};
	int				iSafe_for_autoreplace =  1;//
	char			szOriginating_url[512] =  {""};//
	int				iDate_created = 0;
	int				iUsage_count =  0;//
	char			szInput_encodings[512] =  {"UTF-8"};//
	int				iShow_in_default_list =  1;//
	char			szSuggest_url[1024] =  {"{google:baseSuggestURL}search?{google:searchFieldtrialParameter}client={google:suggestClient}&gs_ri={google:suggestRid}&xssi=t&q={searchTerms}&{google:inputType}{google:cursorPosition}{google:currentPageUrl}{google:pageClassification}{google:searchVersion}{google:sessionToken}{google:prefetchQuery}sugkey={google:suggestAPIKeyParameter}"};
	int				iPrepopulate_id =  1;//
	int				iCreated_by_policy =  0;//
	char			szInstant_url[1024] =  {"{google:baseURL}webhp?sourceid=chrome-instant&{google:RLZ}{google:forceInstantResults}{google:instantExtendedEnabledParameter}{google:ntpIsThemedParameter}{google:omniboxStartMarginParameter}ie={inputEncoding}"};
	int				iLast_modified =  0;//
	char			szSync_guid[512] =  {"2010037D-DAE7-4A93-8B08-B91E415F62CC"};
	char			szAlternate_urls[1024] =  {" [\"{google:baseURL}#q={searchTerms}\",\"{google:baseURL}search#q={searchTerms}\",\"{google:baseURL}webhp#q={searchTerms}\",\"{google:baseURL}s#q={searchTerms}\",\"{google:baseURL}s?q={searchTerms}\"] "};
	char			szSearch_terms_replacement_key[512] =  {"espv"};//
	char			szImage_url[512] =  {"{google:baseURL}searchbyimage/upload"};
	char			szSearch_url_post_params[512] =  {""};//
	char			szSuggest_url_post_params[512] =  {""};//
	char			szInstant_url_post_params[512] =  {""};//
	char			szImage_url_post_params[512] =  {"encoded_image={google:imageThumbnail},image_url={google:imageURL},sbisrc={google:imageSearchSource},original_width={google:imageOriginalWidth},original_height={google:imageOriginalHeight}"};
	char			szNew_tab_url[1024] =  {"{google:baseURL}_/chrome/newtab?{google:RLZ}{google:instantExtendedEnabledParameter}{google:ntpIsThemedParameter}ie={inputEncoding}"};
	

	if (pszFilePath == NULL)
	{
		return false;
	}
	strcpy(szPath2Add,pszFilePath);
	strlwr(szPath2Add);
	
	sprintf(szQuery,"INSERT INTO keywords (id,short_name,keyword,favicon_url,url,safe_for_autoreplace,originating_url,date_created,usage_count,input_encodings,show_in_default_list,suggest_url,prepopulate_id,created_by_policy,instant_url,last_modified,sync_guid,alternate_urls,search_terms_replacement_key,image_url,search_url_post_params,suggest_url_post_params,instant_url_post_params,image_url_post_params,new_tab_url) VALUES(%d,'%s','%s','%s','%s',%d,'%s',%d,%d,'%s',%d,'%s',%d,%d,'%s',%d,'%s','%s','%s','%s','%s','%s','%s','%s','%s')",
		iId,szShort_name,szKeyword,szFavicon_url,szUrl,iSafe_for_autoreplace,szOriginating_url,iDate_created,iUsage_count,szInput_encodings,
		iShow_in_default_list,szSuggest_url,iPrepopulate_id,iCreated_by_policy,szInstant_url,iLast_modified,szSync_guid,szAlternate_urls,szSearch_terms_replacement_key,
		szImage_url,szSearch_url_post_params,szSuggest_url_post_params,szInstant_url_post_params,szImage_url_post_params,szNew_tab_url);
	int iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return true;
	}
	
	return false; 
}
bool CDBWrapper::InsertDefaultYahoo(const char *pszFilePath)
{
	/*if (IsAlreadyExists(pszFilePath) == true)
	{
		return true;
	}*/

	sqlite3_stmt	*stmInsert;
	char			szQuery[8192] = {0x00};
	char			szPath2Add[512] =  {0x00};
	
	// Table fields
	int				iId = 2;
	char			szShort_name[512] =  {"Yahoo"};
	char			szKeyword[512] =  {"yahoo.com"};
	char			szFavicon_url[512] =  {"https://search.yahoo.com/favicon.ico"};//
	char			szUrl[2048] =  {"https://search.yahoo.com/search?ei={inputEncoding}&fr=crmas&p={searchTerms}"};
	int				iSafe_for_autoreplace =  1;//
	char			szOriginating_url[512] =  {""};//
	int				iDate_created = 0;
	int				iUsage_count =  0;//
	char			szInput_encodings[512] =  {"UTF-8"};//
	int				iShow_in_default_list =  1;//
	char			szSuggest_url[1024] =  {"https://search.yahoo.com/sugg/chrome?output=fxjson&appid=crmas&command={searchTerms}"};
	int				iPrepopulate_id =  2;//
	int				iCreated_by_policy =  0;//
	char			szInstant_url[1024] =  {""};
	int				iLast_modified =  1433996796;//
	char			szSync_guid[512] =  {"49B36158-4E3F-4397-90B7-DF19C10894CC"};
	char			szAlternate_urls[1024] =  {"[]"};
	char			szSearch_terms_replacement_key[512] =  {""};//
	char			szImage_url[512] =  {""};
	char			szSearch_url_post_params[512] =  {""};//
	char			szSuggest_url_post_params[512] =  {""};//
	char			szInstant_url_post_params[512] =  {""};//
	char			szImage_url_post_params[512] =  {""};
	char			szNew_tab_url[1024] =  {""};
	

	if (pszFilePath == NULL)
	{
		return false;
	}
	strcpy(szPath2Add,pszFilePath);
	strlwr(szPath2Add);
	
	sprintf(szQuery,"INSERT INTO keywords (id,short_name,keyword,favicon_url,url,safe_for_autoreplace,originating_url,date_created,usage_count,input_encodings,show_in_default_list,suggest_url,prepopulate_id,created_by_policy,instant_url,last_modified,sync_guid,alternate_urls,search_terms_replacement_key,image_url,search_url_post_params,suggest_url_post_params,instant_url_post_params,image_url_post_params,new_tab_url) VALUES(%d,'%s','%s','%s','%s',%d,'%s',%d,%d,'%s',%d,'%s',%d,%d,'%s',%d,'%s','%s','%s','%s','%s','%s','%s','%s','%s')",
		iId,szShort_name,szKeyword,szFavicon_url,szUrl,iSafe_for_autoreplace,szOriginating_url,iDate_created,iUsage_count,szInput_encodings,
		iShow_in_default_list,szSuggest_url,iPrepopulate_id,iCreated_by_policy,szInstant_url,iLast_modified,szSync_guid,szAlternate_urls,szSearch_terms_replacement_key,
		szImage_url,szSearch_url_post_params,szSuggest_url_post_params,szInstant_url_post_params,szImage_url_post_params,szNew_tab_url);
	int iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return true;
	}
	
	return false; 
}
bool CDBWrapper::InsertDefaultBing(const char *pszFilePath)
{
	/*if (IsAlreadyExists(pszFilePath) == true)
	{
		return true;
	}*/

	sqlite3_stmt	*stmInsert;
	char			szQuery[8192] = {0x00};
	char			szPath2Add[512] =  {0x00};
	
	// Table fields
	int				iId = 3;
	char			szShort_name[512] =  {"Bing"};
	char			szKeyword[512] =  {"bing.com"};
	char			szFavicon_url[512] =  {"https://www.bing.com/s/a/bing_p.ico"};//
	char			szUrl[2048] =  {"https://www.bing.com/search?q={searchTerms}&PC=U316&FORM=CHROMN"};
	int				iSafe_for_autoreplace =  1;//
	char			szOriginating_url[512] =  {""};//
	int				iDate_created = 0;
	int				iUsage_count =  0;//
	char			szInput_encodings[512] =  {"UTF-8"};//
	int				iShow_in_default_list =  1;//
	char			szSuggest_url[1024] =  {"https://www.bing.com/osjson.aspx?query={searchTerms}&language={language}&PC=U316"};
	int				iPrepopulate_id =  3;//
	int				iCreated_by_policy =  0;//
	char			szInstant_url[1024] =  {""};
	int				iLast_modified =  1433996796;//
	char			szSync_guid[512] =  {"DB743D5E-0ED6-4CEB-8F8C-864B630E0141"};
	char			szAlternate_urls[1024] =  {""};
	char			szSearch_terms_replacement_key[512] =  {""};//
	char			szImage_url[512] =  {""};
	char			szSearch_url_post_params[512] =  {""};//
	char			szSuggest_url_post_params[512] =  {""};//
	char			szInstant_url_post_params[512] =  {""};//
	char			szImage_url_post_params[512] =  {""};
	char			szNew_tab_url[1024] =  {""};
	

	if (pszFilePath == NULL)
	{
		return false;
	}
	strcpy(szPath2Add,pszFilePath);
	strlwr(szPath2Add);
	
	sprintf(szQuery,"INSERT INTO keywords (id,short_name,keyword,favicon_url,url,safe_for_autoreplace,originating_url,date_created,usage_count,input_encodings,show_in_default_list,suggest_url,prepopulate_id,created_by_policy,instant_url,last_modified,sync_guid,alternate_urls,search_terms_replacement_key,image_url,search_url_post_params,suggest_url_post_params,instant_url_post_params,image_url_post_params,new_tab_url) VALUES(%d,'%s','%s','%s','%s',%d,'%s',%d,%d,'%s',%d,'%s',%d,%d,'%s',%d,'%s','%s','%s','%s','%s','%s','%s','%s','%s')",
		iId,szShort_name,szKeyword,szFavicon_url,szUrl,iSafe_for_autoreplace,szOriginating_url,iDate_created,iUsage_count,szInput_encodings,
		iShow_in_default_list,szSuggest_url,iPrepopulate_id,iCreated_by_policy,szInstant_url,iLast_modified,szSync_guid,szAlternate_urls,szSearch_terms_replacement_key,
		szImage_url,szSearch_url_post_params,szSuggest_url_post_params,szInstant_url_post_params,szImage_url_post_params,szNew_tab_url);
	int iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return true;
	}
	
	return false; 
}
bool CDBWrapper::Insert(const char *pszFilePath)
{
		/*sqlite3_stmt *stmt;
		CString str =(CString)filePath;
		const char *sql = "INSERT INTO PCSafe VALUES(" + 0 + "," + str + "," + 0 + ");";
		int retval = sqlite3_prepare(dbSQl, sql, -1, &stmt, NULL);
		sqlite3_step( stmt );
		sqlite3_finalize(stmt);*/

	if (IsAlreadyExists(pszFilePath) == true)
	{
		return true;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szPath2Add[512] =  {0x00};

	if (pszFilePath == NULL)
	{
		return false;
	}
	strcpy(szPath2Add,pszFilePath);
	strlwr(szPath2Add);
	
	sprintf(szQuery,"INSERT INTO EncryptList (szFilePath,szOrgFilePath,iIsFolder) VALUES ('%s','%s',%d)",szPath2Add,pszFilePath,iIsFolder);
	int iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return true;
	}
	
	return false; 
}
bool CDBWrapper::DeleteQuery(const char *pszFilePath)
{
	sqlite3_stmt	*stmInsert;
	int				iId = 2;
	char			szQuery[512] = {0x00};
	char			szPath2Add[512] =  {0x00};

	if (pszFilePath == NULL)
	{
		return false;
	}
	strcpy(szPath2Add,pszFilePath);
	strlwr(szPath2Add);
	
	//sprintf(szQuery,"DELETE FROM keywords WHERE id = %d",iId);
	sprintf(szQuery,"DELETE FROM keywords");
	int iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return true;
	}
	
	return false; 
}
bool CDBWrapper::Delete(const char *pszFilePath)
{
	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szPath2Add[512] =  {0x00};

	if (pszFilePath == NULL)
	{
		return false;
	}
	strcpy(szPath2Add,pszFilePath);
	strlwr(szPath2Add);
	
	sprintf(szQuery,"DELETE FROM EncryptList WHERE szFilePath = '%s'",szPath2Add,iIsFolder);
	int iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return true;
	}
	
	return false; 
}

bool CDBWrapper::GetFullList(char *pszFilePath)
{
	char			szQuery[512] = {0x00};
	int				iRetval = SQLITE_ERROR;

	
	if (pszFilePath == NULL)
	{
		return false;
	}
	
	strcpy(pszFilePath,"");

	if (m_bEnumStarted == false)
	{
		sprintf(szQuery,"SELECT szOrgFilePath FROM EncryptList");
		iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &m_pstmGetList, NULL);
		if (!iRetval)
		{
			m_bEnumStarted = true;
			iRetval = sqlite3_step(m_pstmGetList);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(pszFilePath,(char *)sqlite3_column_text(m_pstmGetList, 0));
				return true;
			}
			else
			{
				m_bEnumStarted = false;
				sqlite3_finalize(m_pstmGetList);
				return false;
			}
			
		}
	}
	else
	{
		iRetval = sqlite3_step(m_pstmGetList);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(pszFilePath,(char *)sqlite3_column_text(m_pstmGetList, 0));
			return true;
		}
		else
		{
			m_bEnumStarted = false;
			sqlite3_finalize(m_pstmGetList);
			return false;
		}
	}
	
	m_bEnumStarted = false;
	return false; 
	
}

//true ==> Already Exists No need to insert again
//false ==> New entry
bool CDBWrapper::IsAlreadyExists(const char *pszFile2Check)
{
	bool			bRet = true;	
	sqlite3_stmt	*stmSearch;
	char			szQuery[512] = {0x00};
	char			szPath2Check[512] =  {0x00};
	int				iRetval = SQLITE_ERROR;


	if (pszFile2Check == NULL)
	{
		return bRet; 
	}
	strcpy(szPath2Check,pszFile2Check);
	strlwr(szPath2Check);

	sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	iRetval = sqlite3_prepare(m_pPCSafeDB, szQuery, -1, &stmSearch, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmSearch);
		if (iRetval == SQLITE_ROW)
		{
			bRet = true;
		}
		else
		{
			
			bRet = false;
		}
		sqlite3_finalize(stmSearch);
	}

	return bRet;
}