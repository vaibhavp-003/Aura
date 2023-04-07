/*======================================================================================
   FILE			: zserial.h 
   ABSTRACT		: header file
   DOCUMENTS	: Refer The Design Folder (FastMap Design.Doc)
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 1/sep/2007
   NOTES		:
   VERSION HISTORY	:
					Version: 19-Jan-08
					Resourec:Darshan
					Description: Added unicode and X64 support
 ======================================================================================*/

#ifndef _zserial_h_
#define _zserial_h_

#ifndef _zlib_h
#include "zlib.h"
#endif


// zSerial - Base class for all classes serializable to standard iostreams.

class EXT_CLASS zSerial
{
public:
    zSerial();
    virtual ~zSerial();

    // serialization using standard streams
    virtual int Store(NQ wostream* ostrm);              // 1 if success, else 0
    virtual int Load(NQ wistream* istrm);               // 1 if success, else 0

protected:    
    // serialization helpers for derived classes
    int streamWrite(NQ wostream* strm, void* addr, long len);   // structs etc.
    int streamWrite(NQ wostream* strm, const TCHAR* addr);       // null-terminated
    int streamRead(NQ wistream* strm, void* buf, long bufSize); // structs etc.
    int streamRead(NQ wistream* strm, TCHAR* buf, long bufSize, long& bytesRead);    // null-terminated
};

#endif
