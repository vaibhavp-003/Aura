/*======================================================================================
FILE             : Cryptor.cpp
ABSTRACT         : Source file for Encryption/Decryption
DOCUMENTS        : 
AUTHOR           : Anand Srivastava
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 15/Nov/2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
void CryptData(DWORD *Data, DWORD dwDataSize, char *key = 0, unsigned long keylen = 0);
bool CryptFile(const TCHAR *csFileName, const TCHAR *csCryptFileName);
