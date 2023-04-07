#include "pch.h"
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
	
	if(eMaxFont == MICROSOFT_SANS_SERIF)
		csFontName = "Arial";
	else if(eMaxFont == VERDANA)
		csFontName = "Arial";
	else if(eMaxFont == ENGLISH_FONT ||eMaxFont == ARIAL || /*eMaxFont == MICROSOFT_SANS_SERIF || eMaxFont == VERDANA ||*/ eMaxFont == TAHOMA || eMaxFont == NEW_TIMES_ROMAN || eMaxFont == COURIER_NEW)
		//csFontName = "Calibri";
		csFontName = "Segoe UI";
	else if(eMaxFont == CRYSTAL)
		csFontName = "Crystal";
	else if(eMaxFont == GERMAN)
		csFontName = "Calibri";
	else if(eMaxFont == FRENCH_FONT)
		csFontName = "Calibri"/*"French Vogue"*/;
	else if(eMaxFont == SPANISH)
		csFontName = "Calibri";
	else if(eMaxFont == RUSSIAN)
		csFontName = "Calibri"/*"ArbatDi"*/;
	else if(eMaxFont == JAPANESE_FONT)
		csFontName = "Calibri"/*"BMUGAsianFont"*/;
	else if(eMaxFont == HINDI)
		csFontName = "Kiran";
	else if(eMaxFont == MARATHI)
		csFontName = "Kiran";
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
		csFontName = "Calibri"/*"FZTTJW"*/;
	else if(eMaxFont == CHINISE_T)
		csFontName = "Calibri"/*"Iwata SeichouG Pro"*/;
	else if(eMaxFont == GREEK)
		csFontName = "Calibri"/*"AvantGreek"*/;
	
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
CMaxFont* CMaxFont::GetBoldSize15UnderLineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get16Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, TRUE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize15UnderLineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get16Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, TRUE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize18UnderLineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get18Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, TRUE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize18UnderLineFont()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get18Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, TRUE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize15Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get15Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize15Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	else
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);

	MaxSizes eMaxSize = CMaxFont::Get15Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize16Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get16Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize16Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	else
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);

	MaxSizes eMaxSize = CMaxFont::Get16Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize17Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get17Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize17Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get17Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize18Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont; 
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get18Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize18Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	else
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get18Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize19Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	else
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get19Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize19Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get19Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize20Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get20Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize20Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
//	MaxSizes eMaxSize = CMaxFont::Get20Size(eMaxFont);
	MaxFonts eMaxFont; 
	MaxSizes eMaxSize;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
		eMaxSize = CMaxFont::Get18Size(eMaxFont);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
		eMaxSize = CMaxFont::Get20Size(eMaxFont);
	}
	
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize21Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	else
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get21Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize21Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get21Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize22Font()
{
	MaxFonts eMaxFont;
	MaxSizes eMaxSize ;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
		eMaxSize = CMaxFont::Get22Size(eMaxFont);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
		eMaxSize = CMaxFont::Get22Size(eMaxFont);
	}
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	//MaxSizes eMaxSize = CMaxFont::Get22Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize22Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get22Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize23Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get23Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize23Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get23Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize24Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont; 
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get24Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize24Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get24Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetBoldSize25Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get25Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize25Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get25Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize26Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get26Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize26Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get26Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize27Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get27Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize27Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get27Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize28Font()
{
	//MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxFonts eMaxFont; 
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get28Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize28Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get28Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize29Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get29Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize29Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get29Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetNormalSize12Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get12Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);

	if (!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
	
}

CMaxFont* CMaxFont::GetBoldSize30Font()
{
	MaxFonts eMaxFont;
	//MaxFonts eMaxFont;= CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get30Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize30Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get30Size(eMaxFont);
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
				eMaxSize = 	MAXSIZE_20;	
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
				eMaxSize = 	MAXSIZE_20;	
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
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_20;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_20;	
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

MaxSizes CMaxFont::Get15Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_15;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_15;
		else
			eMaxSize = MAXSIZE_17;
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
				eMaxSize = 	MAXSIZE_15;	
			else
				eMaxSize = 	MAXSIZE_17;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_15;	
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
MaxSizes CMaxFont::Get16Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_16;
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
				eMaxSize = 	MAXSIZE_16;	
			else
				eMaxSize = 	MAXSIZE_18;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_16;	
			else
				eMaxSize = 	MAXSIZE_18;	
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
MaxSizes CMaxFont::Get17Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_17;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_17;
		else
			eMaxSize = MAXSIZE_19;
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
				eMaxSize = 	MAXSIZE_17;	
			else
				eMaxSize = 	MAXSIZE_19;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_17;	
			else
				eMaxSize = 	MAXSIZE_19;	
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
MaxSizes CMaxFont::Get18Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_18;
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
				eMaxSize = 	MAXSIZE_20;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_18;	
			else
				eMaxSize = 	MAXSIZE_20;	
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
MaxSizes CMaxFont::Get19Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_19;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_19;
		else
			eMaxSize = MAXSIZE_21;
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
				eMaxSize = 	MAXSIZE_19;	
			else
				eMaxSize = 	MAXSIZE_21;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_19;	
			else
				eMaxSize = 	MAXSIZE_21;	
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
MaxSizes CMaxFont::Get20Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_20;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_20;
		else
			eMaxSize = MAXSIZE_22;
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
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_22;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_20;	
			else
				eMaxSize = 	MAXSIZE_22;	
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
MaxSizes CMaxFont::Get21Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_21;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_21;
		else
			eMaxSize = MAXSIZE_23;
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
				eMaxSize = 	MAXSIZE_21;	
			else
				eMaxSize = 	MAXSIZE_23;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_21;	
			else
				eMaxSize = 	MAXSIZE_23;	
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
MaxSizes CMaxFont::Get22Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_22;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_22;
		else
			eMaxSize = MAXSIZE_24;
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
				eMaxSize = 	MAXSIZE_22;	
			else
				eMaxSize = 	MAXSIZE_24;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_22;	
			else
				eMaxSize = 	MAXSIZE_24;	
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
MaxSizes CMaxFont::Get23Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_23;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_23;
		else
			eMaxSize = MAXSIZE_25;
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
				eMaxSize = 	MAXSIZE_23;	
			else
				eMaxSize = 	MAXSIZE_25;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_23;	
			else
				eMaxSize = 	MAXSIZE_25;	
		}
	}
	else if(eMaxFont == TELGU || eMaxFont == KANNADA)
	{
		if((m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1))
		{
			if(m_dwDPI <= DPI)
				eMaxSize = 	MAXSIZE_28;	
			else
				eMaxSize = 	MAXSIZE_28;	
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
MaxSizes CMaxFont::Get24Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_24;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_24;
		else
			eMaxSize = MAXSIZE_26;
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
				eMaxSize = 	MAXSIZE_24;	
			else
				eMaxSize = 	MAXSIZE_26;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_24;	
			else
				eMaxSize = 	MAXSIZE_26;	
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
MaxSizes CMaxFont::Get25Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_25;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_25;
		else
			eMaxSize = MAXSIZE_27;
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
				eMaxSize = 	MAXSIZE_25;	
			else
				eMaxSize = 	MAXSIZE_27;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_25;	
			else
				eMaxSize = 	MAXSIZE_27;	
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

MaxSizes CMaxFont::Get26Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_26;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_26;
		else
			eMaxSize = MAXSIZE_28;
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
				eMaxSize = 	MAXSIZE_26;	
			else
				eMaxSize = 	MAXSIZE_28;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_26;	
			else
				eMaxSize = 	MAXSIZE_28;	
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

MaxSizes CMaxFont::Get27Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_27;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_27;
		else
			eMaxSize = MAXSIZE_29;
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
				eMaxSize = 	MAXSIZE_27;	
			else
				eMaxSize = 	MAXSIZE_29;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_27;	
			else
				eMaxSize = 	MAXSIZE_29;	
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

MaxSizes CMaxFont::Get28Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_28;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_28;
		else
			eMaxSize = MAXSIZE_30;
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
				eMaxSize = 	MAXSIZE_28;	
			else
				eMaxSize = 	MAXSIZE_30;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_28;	
			else
				eMaxSize = 	MAXSIZE_30;	
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


MaxSizes CMaxFont::Get12Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_12;
	if (eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if (m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_12;
		else
			eMaxSize = MAXSIZE_14;
	}
	return eMaxSize;
}

MaxSizes CMaxFont::Get29Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_29;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_29;
		else
			eMaxSize = MAXSIZE_31;
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
				eMaxSize = 	MAXSIZE_29;	
			else
				eMaxSize = 	MAXSIZE_31;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_29;	
			else
				eMaxSize = 	MAXSIZE_31;	
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

MaxSizes CMaxFont::Get30Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_30;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_30;
		else
			eMaxSize = MAXSIZE_32;
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
				eMaxSize = 	MAXSIZE_30;	
			else
				eMaxSize = 	MAXSIZE_32;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_30;	
			else
				eMaxSize = 	MAXSIZE_32;	
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
				eMaxSize = MAXSIZE_18;	
			else
				eMaxSize = MAXSIZE_19;
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
			eMaxSize = MAXSIZE_18;
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
	csFontName = _T("Calibri");
	iHeight = 18;
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
	
MaxSizes CMaxFont::Get31Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_31;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_31;
		else
			eMaxSize = MAXSIZE_33;
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
				eMaxSize = 	MAXSIZE_31;	
			else
				eMaxSize = 	MAXSIZE_33;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_31;	
			else
				eMaxSize = 	MAXSIZE_33;	
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
MaxSizes CMaxFont::Get32Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_32;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_32;
		else
			eMaxSize = MAXSIZE_34;
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
				eMaxSize = 	MAXSIZE_32;	
			else
				eMaxSize = 	MAXSIZE_34;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_32;	
			else
				eMaxSize = 	MAXSIZE_34;	
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
MaxSizes CMaxFont::Get33Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_33;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_33;
		else
			eMaxSize = MAXSIZE_35;
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
				eMaxSize = 	MAXSIZE_33;	
			else
				eMaxSize = 	MAXSIZE_35;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_33;	
			else
				eMaxSize = 	MAXSIZE_35;	
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
MaxSizes CMaxFont::Get34Size(MaxFonts eMaxFont)
{
	MaxSizes eMaxSize = MAXSIZE_34;
	if(eMaxFont == ENGLISH_FONT || eMaxFont == JAPANESE_FONT 
		|| eMaxFont == FRENCH_FONT || eMaxFont == GERMAN 
		|| eMaxFont == SPANISH || eMaxFont == RUSSIAN || eMaxFont == GREEK)
	{
		if(m_dwDPI <= DPI)
			eMaxSize = MAXSIZE_34;
		else
			eMaxSize = MAXSIZE_36;
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
				eMaxSize = 	MAXSIZE_34;	
			else
				eMaxSize = 	MAXSIZE_36;	
		}
		else 
		{
			if(m_csOS.Find(WVISTA) != -1 || m_csOS.Find(WWIN7) != -1 || m_csOS.Find(WWIN8) != -1)
				eMaxSize = 	MAXSIZE_34;	
			else
				eMaxSize = 	MAXSIZE_36;	
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

CMaxFont* CMaxFont::GetBoldSize31Font()
{
	MaxFonts eMaxFont;
	//MaxFonts eMaxFont;= CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get31Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize31Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get31Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize32Font()
{
	MaxFonts eMaxFont;
	//MaxFonts eMaxFont;= CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get32Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize32Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get32Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize33Font()
{
	MaxFonts eMaxFont;
	//MaxFonts eMaxFont;= CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get33Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize33Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get33Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}

CMaxFont* CMaxFont::GetBoldSize34Font()
{
	MaxFonts eMaxFont;
	//MaxFonts eMaxFont;= CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
	{
		eMaxFont = CMaxFont::GetLanguageEnum(0);
	}
	else
	{
		eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	}
	MaxSizes eMaxSize = CMaxFont::Get34Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Bold, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}
CMaxFont* CMaxFont::GetNormalSize34Font()
{
	MaxFonts eMaxFont = CMaxFont::GetLanguageEnum(m_iCurrentLanguage);
	MaxSizes eMaxSize = CMaxFont::Get34Size(eMaxFont);
	CMaxFont* pFont = new CMaxFont(eMaxFont);
			
	if(!pFont->CreateMaxFont(eMaxFont, eMaxSize, Normal, NormalFont, FALSE))
	{
		delete pFont;
		pFont = NULL;
	}
	return pFont;
}