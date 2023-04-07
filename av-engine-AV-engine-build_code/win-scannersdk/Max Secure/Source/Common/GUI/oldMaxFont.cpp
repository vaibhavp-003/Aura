#include "StdAfx.h"
#include "MaxFont.h"
#include "CPUInfo.h"

#define DPI	96

int CMaxFont::m_iCurrentLanguage = 0;
DWORD CMaxFont::m_dwDPI = DPI;
CString CMaxFont::m_csOS = _T("");

CMaxFont::CMaxFont(MaxFonts eMaxFont)
{
	m_eMaxFont = eMaxFont;
}

CMaxFont::~CMaxFont()
{
}

void CMaxFont::SetCurrentLanguage(int iLanguageID)
{
	m_iCurrentLanguage = iLanguageID;

	CCPUInfo oCPUInfo;
	m_dwDPI = oCPUInfo.GetDpiValue();
	m_csOS = oCPUInfo.GetOSVerTag();
}

CMaxFont* CMaxFont::GetMaxFont(MaxFonts eMaxFont, MaxSizes eMaxSize, MaxWeight eMaxWeight, MaxTypeofFont eMaxTypeofFont, BOOL bUnderline)
{
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, eMaxWeight, eMaxTypeofFont, bUnderline))
		{
			delete pFont;
			pFont = NULL;
		}
	}

	return pFont;
}

BOOL CMaxFont::CreateMaxFont(MaxFonts eMaxFont, MaxSizes eMaxSize, MaxWeight eMaxWeight, MaxTypeofFont eMaxTypeofFont, BOOL bUnderline)
{
	BOOL bRetVal = FALSE;
	CString csFontName = GetFontName(eMaxFont);
	if(csFontName.IsEmpty())
		return bRetVal;

	if(!IsFontInstalled(csFontName))
	{
		OutputDebugString(L"Font is not Installed on your System :" + csFontName);
		MaxFonts eNewMaxFont = GetAlternativeFont();
		if(eNewMaxFont == OSFONT)
		{
			return bRetVal;
		}
		else
		{
			m_eMaxFont = eNewMaxFont;
			csFontName = GetFontName(eNewMaxFont);
		}
	}

	if(eMaxTypeofFont == PointFont)
	{
		if(CreatePointFont(eMaxSize, csFontName))
			bRetVal = TRUE;
	}
	else
	{
		LOGFONT	lf = {0};
		lf.lfUnderline = (BYTE)bUnderline;
		lf.lfWeight = GetWeight(eMaxWeight);

		if(lf.lfWeight == 1)
		{
			lf.lfWeight = FW_BOLD;
			lf.lfItalic = (BYTE)TRUE;
			lf.lfUnderline = (BYTE)TRUE;
		}
		wcscpy_s(lf.lfFaceName, _countof(lf.lfFaceName), csFontName);
		lf.lfHeight	 = eMaxSize;
		
		if(CreateFontIndirect(&lf))
			bRetVal = TRUE;
	}
	return bRetVal;
}

LONG CMaxFont::GetWeight(MaxWeight eMaxWeight)
{
	LONG lRetVal = FW_NORMAL;
	if(eMaxWeight == Bold)
		lRetVal = FW_BOLD;
	else if(eMaxWeight == Italic) //This change is for Italic style
		lRetVal = 1; 
	
	return lRetVal;
}

CString CMaxFont::GetFontName(MaxFonts eMaxFont)
{
	CString csFontName;
	//LANG		Lang Code
	//ENGLISH,	0
	//GERMAN,	1
	//FRENCH,	2
	//SPANISH,	3
	//RUSSIAN,	4
	//JAPANESE,	5
	//HINDI,	6
	//MARATHI,	7
	//GUJRATI,	8
	//TELGU,	9
	//TAMIL,	10
	//KANNADA,	11
	//BENGALA,	12
	//CHINISE_S,13
	//CHINISE_T,14
	//GREEK		15

	if(eMaxFont == ENGLISH_FONT ||eMaxFont == ARIAL || eMaxFont == MICROSOFT_SANS_SERIF || eMaxFont == VERDANA || eMaxFont == TAHOMA || eMaxFont == NEW_TIMES_ROMAN || eMaxFont == COURIER_NEW)
		csFontName = "Calibri";
	else if(eMaxFont == CRYSTAL)
		csFontName = "Crystal";
	else if(eMaxFont == GERMAN)
		csFontName = "Arial";
	else if(eMaxFont == FRENCH_FONT)
		csFontName = "Arial"/*"French Vogue"*/;
	else if(eMaxFont == SPANISH)
		csFontName = "Arial";
	else if(eMaxFont == RUSSIAN)
		csFontName = "Arial"/*"ArbatDi"*/;
	else if(eMaxFont == JAPANESE_FONT)
		csFontName = "Arial"/*"BMUGAsianFont"*/;
	else if(eMaxFont == HINDI)
		csFontName = "Mangal";
	else if(eMaxFont == MARATHI)
		csFontName = "Mangal";
	else if(eMaxFont == GUJRATI)
		csFontName = "Saumil_guj2";
	else if(eMaxFont == TELGU)
		csFontName = "BRH Telugu RN";
	else if(eMaxFont == TAMIL)
		csFontName = "TAMLKamban";
	else if(eMaxFont == KANNADA)
		csFontName = "BRH Amerikannada";
	else if(eMaxFont == BENGALA)
		csFontName = "Kalpurush";
	else if(eMaxFont == CHINISE_S)
		csFontName = "Arial"/*"FZTTJW"*/;
	else if(eMaxFont == CHINISE_T)
		csFontName = "Arial"/*"Iwata SeichouG Pro"*/;
	else if(eMaxFont == GREEK)
		csFontName = "Arial"/*"AvantGreek"*/;
	
	return csFontName;
}

MaxFonts CMaxFont::GetAlternativeFont()
{
	CString csFont;
	MaxFonts eMaxFont = OSFONT;
	if(m_eMaxFont != ARIAL)
	{
		csFont = GetFontName(ARIAL);
		if(IsFontInstalled(csFont))
			eMaxFont = ARIAL;
	}
	else if(m_eMaxFont != MICROSOFT_SANS_SERIF)
	{
		csFont = GetFontName(MICROSOFT_SANS_SERIF);
		if(IsFontInstalled(csFont))
			eMaxFont = MICROSOFT_SANS_SERIF;
	}
	else if(m_eMaxFont != VERDANA)
	{
		csFont = GetFontName(VERDANA);
		if(IsFontInstalled(csFont))
			eMaxFont = VERDANA;
	}
	else if(m_eMaxFont != TAHOMA)
	{
		csFont = GetFontName(TAHOMA);
		if(IsFontInstalled(csFont))
			eMaxFont = TAHOMA;
	}
	else if(m_eMaxFont != CRYSTAL)
	{
		csFont = GetFontName(CRYSTAL);
		if(IsFontInstalled(csFont))
			eMaxFont = CRYSTAL;
	}
	else if(m_eMaxFont != NEW_TIMES_ROMAN)
	{
		csFont = GetFontName(NEW_TIMES_ROMAN);
		if(IsFontInstalled(csFont))
			eMaxFont = NEW_TIMES_ROMAN;
	}
	else if(m_eMaxFont != COURIER_NEW)
	{
		csFont = GetFontName(COURIER_NEW);
		if(IsFontInstalled(csFont))
			eMaxFont = COURIER_NEW;
	}

	return eMaxFont;
}

int CALLBACK EnumFontFamExProc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme, DWORD FontType, LPARAM lParam)
{
	BOOL *pbRetVal = (BOOL*)lParam;
	*pbRetVal = TRUE;

	return 1;
}

BOOL CMaxFont::IsFontInstalled(CString csFontName, MaxWeight eMaxWeight)
{
	BOOL bIsFontInstalled = FALSE;
	HDC hDC = GetDC(NULL);

	if(eMaxWeight == Bold)
		csFontName += " Bold";

	//Char set should be as per selected language
	LOGFONT lf = { 0, 0, 0, 0, 0, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, 0};
	wcscpy_s(lf.lfFaceName, _countof(lf.lfFaceName), csFontName);
	EnumFontFamiliesEx(GetDC(NULL), &lf, (FONTENUMPROC)EnumFontFamExProc, (LPARAM)&bIsFontInstalled, NULL);

	ReleaseDC(NULL, hDC);

	return bIsFontInstalled;
}

MaxFonts CMaxFont::GetLanguageEnum(DWORD dwLangCode)
{
	MaxFonts eMaxFont = ENGLISH_FONT;
	if(dwLangCode == 0 )
		eMaxFont = ENGLISH_FONT;
	else if(dwLangCode == 1)
		eMaxFont = GERMAN;
	else if(dwLangCode == 2)
		eMaxFont = FRENCH_FONT;
	else if(dwLangCode == 3)
		eMaxFont = SPANISH;
	else if(dwLangCode == 4)
		eMaxFont = RUSSIAN;
	else if(dwLangCode == 5)
		eMaxFont = JAPANESE_FONT;
	else if(dwLangCode == 6)
		eMaxFont = HINDI;
	else if(dwLangCode == 7)
		eMaxFont = MARATHI;
	else if(dwLangCode == 8)
		eMaxFont = GUJRATI;
	else if(dwLangCode == 9)
		eMaxFont = TELGU;
	else if(dwLangCode == 10)
		eMaxFont = TAMIL;
	else if(dwLangCode == 11)
		eMaxFont = KANNADA;
	else if(dwLangCode == 12)
		eMaxFont = BENGALA;
	else if(dwLangCode == 13)
		eMaxFont = CHINISE_S;
	else if(dwLangCode == 14)
		eMaxFont = CHINISE_T;
	else if(dwLangCode == 15)
		eMaxFont = GREEK;

	return eMaxFont;	
}

CMaxFont* CMaxFont::GetTitleFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetTitleSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{		
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetControlsFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetNormalSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBigControlsFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetBigControlSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBigControlsBoldFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetBigControlSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetButtonFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetNormalSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBigButtonFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetBigButtonSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetNumbersNormalFont()
{
	MaxFonts eMaxFont = CRYSTAL;
	
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	
	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, MAXSIZE_18, Normal, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetNumbersBoldFont()
{
	MaxFonts eMaxFont = CRYSTAL;
	
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	
	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, MAXSIZE_18, Bold, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetOptionTabBtnFont()
{
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		return CMaxFont::GetControlsFont();
	}

	return CMaxFont::GetButtonFont();
}

CMaxFont* CMaxFont::GetInnerBoldFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetInnerBoldSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);

	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}

	return pFont;
}

CMaxFont* CMaxFont::GetWebLinkFont()
{
	MaxFonts eMaxFont = ENGLISH_FONT;
	MaxSizes eMaxSize = MAXSIZE_14; 
	CMaxFont* pFont = new CMaxFont(eMaxFont);

	if(m_dwDPI <= DPI)
		eMaxSize = MAXSIZE_14;
	else
		eMaxSize = MAXSIZE_16;

	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, TRUE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}
CMaxFont* CMaxFont::GetEnglishOnlyFont()
{
	MaxFonts eMaxFont = ENGLISH_FONT;
	MaxSizes eMaxSize = MAXSIZE_14; 
	CMaxFont* pFont = new CMaxFont(eMaxFont);

	if(m_dwDPI <= DPI)
		eMaxSize = MAXSIZE_14;
	else
		eMaxSize = MAXSIZE_16;

	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetItalicBoldUnderlineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetNormalSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);

	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Italic, NormalFont, TRUE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldFont()
{
	return CMaxFont::GetButtonFont();
}

CMaxFont* CMaxFont::GetUnderlineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetNormalSize(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);

	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, TRUE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

MaxSizes CMaxFont::GetBigControlSize(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_14;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_16;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if(eMaxFont == BENGALA)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_18;
		else
			eMaxSize = MAXSIZE_20;
	}
	else if(eMaxFont == CHINISE_S || eMaxFont == CHINISE_T)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_14;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if(eMaxFont == TAMIL)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_NEG15;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_16;	
		}
	}
	else if(eMaxFont == GUJRATI)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_NEG15;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_NEG16;	
			else
				eMaxSize = 	MAXSIZE_16;	
		}
	}
	else if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_dwDPI <= DPI)
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_NEG15;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_17;	
		}
	}
	else if(eMaxFont == TELGU || eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_NEG18;	
			else
				eMaxSize = 	MAXSIZE_24;	
		}
		else
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_NEG16;	
			else
				eMaxSize = 	MAXSIZE_NEG18;	
		}
	}
	return eMaxSize;
}

MaxSizes CMaxFont::GetBigButtonSize(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_14;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_18;
		else
			eMaxSize = MAXSIZE_20;
	}
	else if(eMaxFont == BENGALA)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_18;
		else
			eMaxSize = MAXSIZE_20;
	}
	else if(eMaxFont == CHINISE_S || eMaxFont == CHINISE_T)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_14;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if(eMaxFont == TAMIL)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_NEG15;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_16;	
		}
	}
	else if(eMaxFont == GUJRATI)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_NEG15;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_NEG16;	
			else
				eMaxSize = 	MAXSIZE_16;	
		}
	}
	else if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_dwDPI <= DPI)
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_NEG15;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_17;	
		}
	}
	else if(eMaxFont == TELGU || eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_NEG18;	
			else
				eMaxSize = 	MAXSIZE_24;	
		}
		else
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_NEG16;	
			else
				eMaxSize = 	MAXSIZE_NEG18;	
		}
	}
	return eMaxSize;
}

MaxSizes CMaxFont::GetNormalSize(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_14;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_14;
		else
			eMaxSize = MAXSIZE_16;
	}
	else if(eMaxFont == BENGALA)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_18;
		else
			eMaxSize = MAXSIZE_20;
	}
	else if(eMaxFont == CHINISE_S || eMaxFont == CHINISE_T)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_14;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if(eMaxFont == TAMIL)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_NEG15;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_16;	
		}
	}
	else if(eMaxFont == GUJRATI)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_NEG15;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_NEG16;	
			else
				eMaxSize = 	MAXSIZE_16;	
		}
	}
	else if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_dwDPI <= DPI)
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_NEG15;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_17;	
		}
	}
	else if(eMaxFont == TELGU || eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_NEG18;	
			else
				eMaxSize = 	MAXSIZE_24;	
		}
		else
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_NEG16;	
			else
				eMaxSize = 	MAXSIZE_NEG18;	
		}
	}
	return eMaxSize;
}

MaxSizes CMaxFont::GetInnerBoldSize(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_21;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == SPANISH 
		|| eMaxFont == JAPANESE_FONT || eMaxFont == FRENCH_FONT 
		||  eMaxFont == GERMAN || eMaxFont == RUSSIAN) 
	{
		eMaxSize = MAXSIZE_24;
	}
	else if(eMaxFont == CHINISE_S || eMaxFont == CHINISE_T || eMaxFont == GREEK)
	{
		eMaxSize = MAXSIZE_20;
	}
	else if( eMaxFont == GUJRATI)
	{
		eMaxSize = 	MAXSIZE_24;	
	}
	else if(eMaxFont == BENGALA || eMaxFont == TAMIL)
	{
		eMaxSize = 	MAXSIZE_22;	
	}
	else if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
			eMaxSize = 	MAXSIZE_24;	
		else
			eMaxSize = 	MAXSIZE_22;	
	}
	else if(eMaxFont == TELGU)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_24;	
		else
			eMaxSize = 	MAXSIZE_28;	
	}
	else if(eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_28;	
		else
			eMaxSize = 	MAXSIZE_24;	
	}	
	return eMaxSize;
}

MaxSizes CMaxFont::GetTitleSize(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_16;
	if(eMaxFont == GREEK)
	{
		eMaxSize = MAXSIZE_16;
	}
	else if(eMaxFont == ENGLISH_FONT || eMaxFont == SPANISH 
		|| eMaxFont == JAPANESE_FONT || eMaxFont == FRENCH_FONT 
		||  eMaxFont == GERMAN || eMaxFont == RUSSIAN) 
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_16;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if(eMaxFont == CHINISE_S || eMaxFont == CHINISE_T)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_16;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if( eMaxFont == GUJRATI)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_22;	
		else
			eMaxSize = 	MAXSIZE_18;	
	}
	else if(eMaxFont == BENGALA)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_18;	
		else
			eMaxSize = 	MAXSIZE_20;	
	}
	else if(eMaxFont == TAMIL)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_18;	
		else
			eMaxSize = 	MAXSIZE_16;	
	}
	else if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_dwDPI <= DPI)
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_22;	
			else
				eMaxSize = 	MAXSIZE_NEG16;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_22;	
			else
				eMaxSize = 	MAXSIZE_18;	
		}
	}
	else if(eMaxFont == TELGU)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_24;	
		else
			eMaxSize = 	MAXSIZE_28;	
	}
	else if(eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_28;	
		else
			eMaxSize = 	MAXSIZE_24;	
	}
	
	return eMaxSize;
}

void CMaxFont::GetNewsParams(CString &csFontName, int &iHeight)
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = MAXSIZE_22;
	csFontName = CString(_T("Arial"));
		
	if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_NEG11;	
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = MAXSIZE_16;	
			else
				eMaxSize = MAXSIZE_17;
		}
	}
	else if(eMaxFont == GUJRATI)
	{
		if(m_dwDPI <= DPI)
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = MAXSIZE_NEG16;
			else
				eMaxSize = MAXSIZE_15;	
		}
		else
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = MAXSIZE_NEG17;	
			else
				eMaxSize = MAXSIZE_17;
		}
	}
	else if(eMaxFont == TELGU)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = MAXSIZE_NEG15;	
			else
				eMaxSize = MAXSIZE_NEG17;
		}
		else
		{
			if(m_dwDPI <= DPI)
				eMaxSize = MAXSIZE_15;	
			else
				eMaxSize = MAXSIZE_17;
		}
	}
	else if(eMaxFont == TAMIL)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = MAXSIZE_NEG15;	
			else
				eMaxSize = MAXSIZE_NEG17;	
		}
		else
		{
			if(m_dwDPI <= DPI)
				eMaxSize = MAXSIZE_NEG11;	
			else
				eMaxSize = MAXSIZE_17;	
		}
	}
	else if(eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = MAXSIZE_NEG15;	
			else
				eMaxSize = MAXSIZE_NEG17;
		}
		else
		{
			if(m_dwDPI <= DPI)
				eMaxSize = MAXSIZE_15;	
			else
				eMaxSize = MAXSIZE_17;
		}
	}
	else if(eMaxFont == BENGALA)
	{
		csFontName = CString(_T("Kalpurush"));
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_16;
		else
			eMaxSize = MAXSIZE_18;
	}
	else if(eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_14;
		else
			eMaxSize = MAXSIZE_16;
	}
	else
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_NEG11;
		else
			eMaxSize = MAXSIZE_NEG12;
	}
	iHeight = static_cast<int>(eMaxSize);
}

CMaxFont* CMaxFont::GetFeatureLockedTitleFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	//MaxSizes eMaxSize = CMaxFont::GetTitleSize(eMaxFont);

	MaxSizes eMaxSize = MAXSIZE_21;
	if(eMaxFont == GREEK)
	{
		eMaxSize = MAXSIZE_21;
	}
	else if(eMaxFont == ENGLISH_FONT || eMaxFont == SPANISH 
		|| eMaxFont == JAPANESE_FONT || eMaxFont == FRENCH_FONT 
		||  eMaxFont == GERMAN || eMaxFont == RUSSIAN) 
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_21;
		else
			eMaxSize = MAXSIZE_22;
	}
	else if(eMaxFont == CHINISE_S || eMaxFont == CHINISE_T)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_22;
		else
			eMaxSize = MAXSIZE_24;
	}
	else if( eMaxFont == GUJRATI)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_24;	
		else
			eMaxSize = 	MAXSIZE_18;	
	}
	else if(eMaxFont == BENGALA)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_22;	
		else
			eMaxSize = 	MAXSIZE_24;	
	}
	else if(eMaxFont == TAMIL)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_22;	
		else
			eMaxSize = 	MAXSIZE_20;	
	}
	else if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if(m_dwDPI <= DPI)
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_24;	
			else
				eMaxSize = 	MAXSIZE_NEG18;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_24;	
			else
				eMaxSize = 	MAXSIZE_20;	
		}
	}
	else if(eMaxFont == TELGU)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = 	MAXSIZE_24;	
		else
			eMaxSize = 	MAXSIZE_28;	
	}
	else if(eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1) && m_dwDPI > DPI)
			eMaxSize = 	MAXSIZE_28;	
		else
			eMaxSize = 	MAXSIZE_24;	
	}
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{		
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetFeatureLockedSubTitleFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetNormalSize(eMaxFont);
	
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{		
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;

}

CMaxFont* CMaxFont::GetControlsSmallFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = MAXSIZE_13;
	if(eMaxFont == HINDI || eMaxFont == MARATHI)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
			eMaxSize = MAXSIZE_15;
		else
			eMaxSize = MAXSIZE_NEG12;			
	}
	
	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{		
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;

}

CMaxFont* CMaxFont::GetButtonUnderlineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::GetBigControlSize(eMaxFont);

	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, TRUE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

void CMaxFont::GetFixIssuesFontParams(CString &csFontName, int &iHeight)
{
	csFontName = _T("Arial");
	iHeight = 16;
}

CMaxFont* CMaxFont::GetBigWarningFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = MAXSIZE_34;

	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}

CMaxFont* CMaxFont::GetNormalWarningFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = MAXSIZE_28;

	CMaxFont* pFont = new CMaxFont(eMaxFont);
	if(pFont)
	{
		if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
		{
			delete pFont;
			pFont = NULL;
		}
	}
	return pFont;
}
	