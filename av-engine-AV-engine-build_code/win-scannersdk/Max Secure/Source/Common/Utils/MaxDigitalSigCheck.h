#pragma once
class CMaxDigitalSigCheck
{
	
public:
	CMaxDigitalSigCheck(void);
	~CMaxDigitalSigCheck(void);
	
	bool CheckDigitalSign(LPCTSTR pszDBPath);

private :
	bool VerifySignature(LPCWSTR pwszSourceFile);
	
};
