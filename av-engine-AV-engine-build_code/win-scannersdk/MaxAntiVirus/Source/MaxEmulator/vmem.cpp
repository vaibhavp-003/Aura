/*
*
*  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
*
*  This program is free_emu software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to Amr Thabet 
*  amr.thabet@student.alx.edu.eg
*
*/
#include "pch.h"
#include "x86emu.h"

#define MAXIMUM_STATIC_SIZE 100

VirtualMemory::VirtualMemory()
{
	CommittedPages=0x00870000;

	vmem=(vMem**)malloc_emu(MAXIMUM_STATIC_SIZE*8/*(sizeof(MAX_DWORD))*/);
	memset((void*)vmem,0,8/*(sizeof(MAX_DWORD))*/);
	vmem_length=0;

	cmem=(cMem**)malloc_emu((sizeof(MAX_DWORD)));
	memset((void*)cmem, 0,(sizeof(MAX_DWORD)));
	cmem_length=0;

	last_accessed = new Log(0);
	last_modified = new Log(0);
}

VirtualMemory::~VirtualMemory()
{
	if(vmem[0] != NULL)
	{
		free_emu((void*)vmem[0]);
	}
	if(vmem != NULL)
	{
		free_emu((void*)vmem);
		vmem = NULL;
	}
	for(int i=0;i<cmem_length;i++)
	{
		free_emu((void*)cmem[i]);
	}
	if(cmem != NULL)
	{
		free_emu ((void*)cmem);
		cmem = NULL;
	}
	if(last_accessed)
	{
		delete last_accessed;
		last_accessed = NULL;
	}
	if(last_modified)
	{
		delete last_modified;
		last_modified = NULL;
	}
}

dword VirtualMemory::add_pointer(MAX_DWORD rptr,dword vptr,dword size,int flags)
{
	if (vmem_length==0)
	{
		DWORD dwTemp = sizeof(MAX_DWORD);
		DWORD	dwSize = MAXIMUM_STATIC_SIZE*sizeof(vMem);
		vmem[0]=(vMem*)malloc_emu(dwSize);
		vmem[0]->rmem = rptr;
		vmem[0]->vmem = vptr;
		vmem[0]->size = size;
		vmem[0]->flags = flags;
		vmem_length++;

	}
	else
	{
		if(vmem_length >= MAXIMUM_STATIC_SIZE)
		{   
			MAX_DWORD c = (MAX_DWORD)vmem;
			vmem = (vMem**)realloc_emu((void*)vmem,(vmem_length+1)*4) ;
			memcpy((void*)c, vmem, (vmem_length)*4);
			vmem[vmem_length]=(vMem*)malloc_emu(sizeof(vMem));
			memset(vmem[vmem_length],0,4);
		}
		else
		{
			int dwSize1 = sizeof(vMem);
			MAX_DWORD dwSize = 0;
			dwSize = (MAX_DWORD)sizeof(vMem);
			vmem[vmem_length] = (vMem*)(((MAX_DWORD)vmem[vmem_length-1]) + ((MAX_DWORD)dwSize));
			/*_stprintf_s(szLogLine, 1024, L"VirtualMemory::add_pointer vmem[vmem_length-1] = %016p  vmem[vmem_length] = %016p", vmem[vmem_length-1], vmem[vmem_length]);
			WriteLog(szLogLine);*/
		}
		
		vmem[vmem_length]->rmem  = rptr;
		vmem[vmem_length]->vmem  = vptr;
		vmem[vmem_length]->size  = size;
		vmem[vmem_length]->flags = flags;
		/*_stprintf_s(szLogLine, 1024, L"VirtualMemory::add_pointer vmem[vmem_length]->rmem  = %016p vmem[vmem_length]->vmem  = %08x vmem[vmem_length]->size = %08x", vmem[vmem_length]->rmem , vmem[vmem_length]->vmem , vmem[vmem_length]->size );
		WriteLog(szLogLine);*/
		vmem_length++;

	}
	return 0;
}
dword VirtualMemory::get_virtual_pointer(MAX_DWORD ptr)
{
	for (int i = this->vmem_length-1; i>=0; i--)
	{
		if ( ptr >= vmem[i]->rmem && ptr < (vmem[i]->rmem + vmem[i]->size) && vmem[i]->size!=0)
		{
			if(ptr + sizeof(MAX_DWORD) < (vmem[i]->rmem + vmem[i]->size))
			{
				ptr -=vmem[i]->rmem;
				ptr +=vmem[i]->vmem;
				return ptr;
			}
		}
	}
	return 0;
}

MAX_DWORD* VirtualMemory::read_virtual_mem(dword ptr)
{	
	dword vptr = ptr;  
	MAX_DWORD	dwRealPtr = ptr;
	for (int i=this->vmem_length-1;i>=0;i--)
	{
		if ( ptr >=vmem[i]->vmem &&	ptr < (vmem[i]->vmem + vmem[i]->size) && vmem[i]->size!=0)
		{
			if(ptr + sizeof(MAX_DWORD) < (vmem[i]->vmem + vmem[i]->size))
			{
				dwRealPtr -=vmem[i]->vmem;
				dwRealPtr +=vmem[i]->rmem;
				last_accessed->addlog(vptr);
				return (MAX_DWORD*)dwRealPtr;
			}
		}
	}
	return 0;
}

bool VirtualMemory::get_memory_flags(dword ptr)
{
	for (int i=0;i<this->cmem_length;i++)
	{
		if ( ptr >=cmem[i]->ptr && ptr < (cmem[i]->ptr + cmem[i]->size))
		{
			return true;
		}
	}
	return false;
}

dword VirtualMemory::write_virtual_mem(dword ptr,dword size,char* buff)
{
	int vptr=ptr;
	int entry=0;

	MAX_DWORD	dwRealPointer = ptr;
	for (int i=this->vmem_length-1; i>=0; i--)
	{
		if ( ptr >=vmem[i]->vmem && 
			ptr < (vmem[i]->vmem + vmem[i]->size) && vmem[i]->size!=0)
		{
			dwRealPointer -=vmem[i]->vmem;
			dwRealPointer +=vmem[i]->rmem;
			entry=i;
			goto mem_found;
		}
	}
	return EXP_INVALIDPOINTER;

mem_found:

	/*if (vmem[entry]->flags == MEM_IMAGEBASE)
	{
		if(!check_writeaccess(vptr,vmem[entry]->vmem))
		{
			return EXP_WRITEACCESS_DENIED;
		}
	}

	if (vmem[entry]->flags == MEM_READONLY || vmem[entry]->flags == MEM_DLLBASE)
	{
		return EXP_WRITEACCESS_DENIED;
	}*/

	memcpy((void*)dwRealPointer, buff, size);

	last_modified->addlog(vptr);
	set_memory_flags((dword)vptr,size);

	return 0;
}
dword VirtualMemory::set_memory_flags(dword ptr,int size)
{
	for (int i=0; i<this->cmem_length; i++)
	{
		if ( ptr >=cmem[i]->ptr && ptr < (cmem[i]->ptr + cmem[i]->size))
		{
			//so it's allready written 
			goto  found_ptr;
		}
		else if (ptr == (cmem[i]->ptr + cmem[i]->size))
		{ //here if it's the next dword or the next byte (for loop on decrypting something
			cmem[i]->size+=size;
			goto  found_ptr;
		}
		else if ((ptr+size) ==cmem[i]->ptr)
		{ // the prev byte or dword (decrypting from the end to the top)
			cmem[i]->ptr -=size;
			cmem[i]->size+=size;
			goto  found_ptr;  
		}
	}

	//if not found so add it 
	if (cmem_length==0)
	{
		cmem[0]=(cMem*)malloc_emu(sizeof(cMem));
		cmem[0]->ptr=ptr;
		cmem[0]->size=size;
		cmem_length++;
	}
	else
	{
		cmem=(cMem**)realloc_emu((void*)cmem,(cmem_length+1)*(sizeof(MAX_DWORD))) ;
		cmem[cmem_length]=(cMem*)malloc_emu(sizeof(cMem));
		cmem[cmem_length]->ptr=ptr;
		cmem[cmem_length]->size=size;
		cmem_length++;
	}
found_ptr:
	return 0;
}

bool VirtualMemory::check_writeaccess(dword ptr,dword imagebase)
{
	image_header *PEHeader;
	MAX_DWORD FileHandler = 0, PEHeader_ptr = 0;

	FileHandler = (MAX_DWORD)read_virtual_mem(imagebase);
	PEHeader_ptr = ((dos_header*)FileHandler)->e_lfanew + FileHandler;
	PEHeader = (image_header*)PEHeader_ptr;

	if (ptr < (imagebase+PEHeader->optional.section_alignment))
	{
		return false;
	}

	ptr -= imagebase;
	image_section_header* sections=(image_section_header*)(PEHeader->header.size_of_optional_header+(dword)&PEHeader->optional);
	if (PEHeader->header.number_of_sections !=0)
	{
		for (int i=0; i < PEHeader->header.number_of_sections-1; i++)
		{
			if (ptr >=sections[i].virtual_address && ptr <(sections[i+1].virtual_address))
			{
				if(sections[i].characteristics & IMAGE_SCN_MEM_WRITE)
				{
					return true;                                        
				}
				else
				{
					return false; 
				}
			}
		}

		int n = PEHeader->header.number_of_sections - 1;
		MAX_DWORD s = (MAX_DWORD)&sections[n];
		s += sizeof(image_section_header) + 1;
		if (ptr >=sections[n].virtual_address && ptr <(PEHeader->optional.size_of_image))
		{
			if(sections[n].characteristics & IMAGE_SCN_MEM_WRITE)
			{
				return true;                                       
			}
			else
			{
				return false;    
			}
		}
	}

	return false; 
}

dword VirtualMemory::delete_pointer(dword ptr)
{
	for (int i=this->vmem_length-1;i>=0;i--)
	{
		if ( ptr >= vmem[i]->vmem && 
			ptr <= (vmem[i]->vmem + vmem[i]->size) && vmem[i]->size!=0)
		{
			vmem[i]->size=0;
			return 0;
		}
	}

	return (dword)-1;
}

dword VirtualMemory::get_last_accessed(int index)
{
	return last_accessed->getlog(index);
}

dword VirtualMemory::get_last_modified(int index)
{
	return last_modified->getlog(index);
}

MAX_DWORD* VirtualMemory::read_file_mem(dword ptr)
{
	dword vptr = ptr;  
	MAX_DWORD	dwRealPtr = ptr;
	if ( ptr >=vmem[0]->vmem &&	ptr < (vmem[0]->vmem + vmem[0]->size) && vmem[0]->size!=0)
	{
		if(ptr + sizeof(MAX_DWORD) < (vmem[0]->vmem + vmem[0]->size))
		{
			dwRealPtr -=vmem[0]->vmem;
			dwRealPtr +=vmem[0]->rmem;
			last_accessed->addlog(vptr);
			return (MAX_DWORD*)dwRealPtr;
		}
	}
	return 0;
}