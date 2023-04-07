#pragma once
#define EMU_WRITE_MEM(x,y,z) \
        int writememError = thread.mem->write_virtual_mem(x,y,z); \
        if (writememError != 0)	return writememError;
        
#define EMU_READ_MEM(ptr,x) \
        ptr =(dword*)thread.mem->read_virtual_mem((dword)x); \
        if(ptr == 0)return EXP_INVALIDPOINTER;



#define API_WRITE_MEM(x,y,z) \
        int writememError = thread->mem->write_virtual_mem(x,y,z); \
        if (writememError != 0)return writememError;
        
#define API_READ_MEM(ptr,x) \
        ptr =(dword*)thread->mem->read_virtual_mem((dword)x); \
        if(ptr == 0)return 0;



#define SEH_WRITE_MEM(x,y,z) \
        int writememError = this->mem->write_virtual_mem(x,y,z); \
        if (writememError != 0)return writememError;
        
#define SEH_READ_MEM(ptr,x) \
        ptr=(dword*)this->mem->read_virtual_mem((dword)x); \
        if(ptr == 0)return EXP_INVALIDPOINTER;        

