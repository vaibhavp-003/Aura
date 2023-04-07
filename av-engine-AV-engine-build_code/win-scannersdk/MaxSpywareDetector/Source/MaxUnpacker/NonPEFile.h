#pragma once
#include "MaxPEFile.h"

class CNonPEFile
{
	bool ExtractMSSZDDFile(TCHAR *szFileName, TCHAR *szExtractedPath);
	bool ExtractCryptCFFFile(TCHAR *szFileName, TCHAR *szExtractedPath);
	bool ExtractMSCHMFile(TCHAR *szFileName, TCHAR *szExtractedPath);
	bool ExtractCabFile(TCHAR *szFileName, TCHAR *szExtractedPath);
	bool ExtractUBFile(TCHAR *szFileName, TCHAR *szExtractedPath);
	bool ExtractDMGFile(TCHAR *szFileName, TCHAR *szExtractedPath);
	
public:
	CNonPEFile();
	~CNonPEFile(void);

	bool ExtractFile(int iFileType, TCHAR *szFileName, TCHAR *szExtractedPath);
};
