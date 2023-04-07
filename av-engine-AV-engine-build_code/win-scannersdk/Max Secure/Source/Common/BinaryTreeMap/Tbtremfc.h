/*======================================================================================
   FILE			: tbtremfc.h : 
   ABSTRACT		: header file
   DOCUMENTS	: Reffer The Design Folder (FastMap Design.Doc)
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
					Version: 19-jan-08
					Resourec:Darshan
					Description: Added unicode and X64 support
======================================================================================*/
#ifndef _tbtremfc_h_
#define _tbtremfc_h_

#ifndef _tbtreed_h_
#include "tbtreed.h"
#endif
#pragma warning(disable: 4275)
#pragma warning(disable: 4251)

// MFC Derived tree class: string key, string data
class EXT_CLASS CtStringToString : public CObject, public tStringToString
{
public:
    DECLARE_SERIAL(CtStringToString)
    virtual ~CtStringToString();
    virtual void Serialize(CArchive& ar);
protected:
    virtual int onStore(void* where, POSITION node);
};

// MFC Derived tree class: string key, unsigned long data
class EXT_CLASS CtStringToULong : public CObject, public tStringToULong
{
public:
    DECLARE_SERIAL(CtStringToULong)
    virtual ~CtStringToULong();
    virtual void Serialize(CArchive& ar);
protected:
    virtual int onStore(void* where, POSITION node);
};

// MFC Derived tree class: string key, CObject data
class EXT_CLASS CtStringToCObject : public CObject, public tStringToULong
{
public:
    DECLARE_SERIAL(CtStringToCObject)
    virtual ~CtStringToCObject();
    virtual void Serialize(CArchive& ar);
    
    inline int Set(const TCHAR * key, CObject* data);
    inline CObject* Get(const TCHAR* key);
    inline CObject* GetData(POSITION pos);
    inline int SetData(POSITION pos, CObject* data);
    
protected:
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual int onStore(void* where, POSITION node);
    
    // CObject does not support serialization to streams:
    virtual int Store(NQ ostream* ostrm){return 0;}
    virtual int Load(NQ istream* istrm){return 0;}
};

// MFC Derived tree class: unsigned long key, string data
class EXT_CLASS CtULongToString : public CObject, public tULongToString
{
public:
    DECLARE_SERIAL(CtULongToString)
    virtual ~CtULongToString();
    virtual void Serialize(CArchive& ar);
protected:
    virtual int onStore(void* where, POSITION node);
};

// MFC Derived tree class: unsigned long key, unsigned long data
class EXT_CLASS CtULongToULong : public CObject, public tULongToULong
{
public:
    DECLARE_SERIAL(CtULongToULong)
    virtual ~CtULongToULong();
    virtual void Serialize(CArchive& ar);
protected:
    virtual int onStore(void* where, POSITION node);
};

// MFC Derived tree class: unsigned long key, CObject data
class EXT_CLASS CtULongToCObject : public CObject, public tULongToULong
{
public:
    DECLARE_SERIAL(CtULongToCObject)
    virtual ~CtULongToCObject();
    virtual void Serialize(CArchive& ar);
    
    inline int Set(unsigned long key, CObject* data);
    inline CObject* Get(unsigned long key);
    inline CObject* GetData(POSITION pos);
    inline int SetData(POSITION pos, CObject* data);
    
protected:
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual int onStore(void* where, POSITION node);
    
    // CObject does not support serialization to streams:
    virtual int Store(NQ ostream* ostrm){return 0;}
    virtual int Load(NQ istream* istrm){return 0;}
};

// MFC Derived tree class: long key, string data
class EXT_CLASS CtLongToString : public CObject, public tLongToString
{
public:
    DECLARE_SERIAL(CtLongToString)
    virtual ~CtLongToString();
    virtual void Serialize(CArchive& ar);
protected:
    virtual int onStore(void* where, POSITION node);
};

// MFC Derived tree class: long key, unsigned long data
class EXT_CLASS CtLongToULong : public CObject, public tLongToULong
{
public:
    DECLARE_SERIAL(CtLongToULong)
    virtual ~CtLongToULong();
    virtual void Serialize(CArchive& ar);
protected:
    virtual int onStore(void* where, POSITION node);
};

// MFC Derived tree class: long key, CObject data
class EXT_CLASS CtLongToCObject : public CObject, public tLongToULong
{
public:
    DECLARE_SERIAL(CtLongToCObject)
    virtual ~CtLongToCObject();
    virtual void Serialize(CArchive& ar);
    
    inline int Set(long key, CObject* data);
    inline CObject* Get(long key);
    inline CObject* GetData(POSITION pos);
    inline int SetData(POSITION pos, CObject* data);
    
protected:
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual int onStore(void* where, POSITION node);
    
    // CObject does not support serialization to streams:
    virtual int Store(NQ ostream* ostrm){return 0;}
    virtual int Load(NQ istream* istrm){return 0;}
};

// INLINE members for all classes defined here.

// CtStringToCObject
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: const TCHAR * key - key
					  CObject* data - object
	Out Parameters	: itn - status 1/0
	Purpose			: Set data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int CtStringToCObject::Set(const TCHAR * key, CObject* data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: const char* key - key
	Out Parameters	: CObject* data - object
	Purpose			: get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline CObject* CtStringToCObject::Get(const TCHAR* key)
{
    return (CObject*)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: CObject *  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline CObject* CtStringToCObject::GetData(POSITION pos)
{
    return (CObject*)getData(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  CObject* data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int CtStringToCObject::SetData(POSITION node, CObject* data)
{
    return setData(node, (void*)data);
}


// CtULongToCObject

/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: unsigned long  key - key
					  CObject* data - object
	Out Parameters	: itn - status 1/0
	Purpose			: Set data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int CtULongToCObject::Set(unsigned long key, CObject* data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: unsigned long key - key
	Out Parameters	: CObject* data - object
	Purpose			: get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline CObject* CtULongToCObject::Get(unsigned long key)
{
    return (CObject*)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: CObject *  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline CObject* CtULongToCObject::GetData(POSITION pos)
{
    return (CObject*)getData(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  CObject* data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int CtULongToCObject::SetData(POSITION node, CObject* data)
{
    return setData(node, (void*)data);
}

// CtLongToCObject

/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: long  key - key
					  CObject* data - object
	Out Parameters	: itn - status 1/0
	Purpose			: Set data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int CtLongToCObject::Set(long key, CObject* data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: long key - key
	Out Parameters	: CObject* data - object
	Purpose			: get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline CObject* CtLongToCObject::Get(long key)
{
    return (CObject*)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: CObject *  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline CObject* CtLongToCObject::GetData(POSITION pos)
{
    return (CObject*)getData(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  CObject* data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int CtLongToCObject::SetData(POSITION node, CObject* data)
{
    return setData(node, (void*)data);
}

#endif
