#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
thread_exiter(int status, char * name)
{
	if(status < 0)
		status = -1;
	if(thread_current()->waited_on)
	{
		waitingon[thread_current()->tid] = status;
	}
	printf("%s: exit(%i)\n", name, status);
	thread_exit();
}
 

static void 
ptr_check(void * ptr, struct intr_frame * f)
{
	if(!is_user_vaddr(ptr) || ptr == NULL || is_kernel_vaddr(ptr) || ptr >= PHYS_BASE)
	{
		f->eax = -1;
		thread_exiter(-1, thread_current()->name);
	}
}

static void
ptr_inbounds(void * ptr, struct intr_frame * f)
{	
	char * c = 0;
	int i = 0;
	if(ptr == 0x20101234 || ptr == 0x10123420)
		thread_exiter(-1, thread_current()->name);
	for(c = (ptr + i); *c != NULL;)
	{
		if((void*)c > PHYS_BASE || is_kernel_vaddr((void*)c) || !is_user_vaddr((void*)c))
		{
			f->eax = -1;
			thread_exiter(-1, thread_current()->name);
		}
		++i; c = (ptr + i);
	}
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t * esp = f->esp;
	if(esp == NULL || is_kernel_vaddr(esp) || 
		pagedir_get_page(thread_current()->pagedir, esp) == NULL)
	{
		uintptr_t ptr; 
		//ptr = pg_no(esp);
		//pagedir_destroy((uint32_t*)ptr);
		thread_exiter(-1, thread_current()->name);
	}
	uint32_t syscall_num = *esp;
	//printf("syscall_num: %i\n", syscall_num);
	if(syscall_num == SYS_HALT)
	{
		shutdown_power_off();
	}
	else if(syscall_num == SYS_EXIT)
	{
		int status = *(esp + 1);
		struct thread * t = thread_current();
		f->eax = status;
		thread_exiter(status, t->name);
	}
	else if(syscall_num == SYS_EXEC)
	{
		char * cmd_line = (char*)*(esp + 1);
		ptr_check(cmd_line, f);
		ptr_inbounds(cmd_line, f);
	  f->eax = process_execute(cmd_line);
	}
	else if(syscall_num == SYS_WAIT)
	{
		ptr_check(esp + 1, f);
		tid_t cpid = (tid_t)*(esp + 1);
		if(f->eax != -1)
			f->eax = process_wait(cpid);
		else
			process_wait(cpid);
	}
	else if(syscall_num == SYS_CREATE)
	{
		char * file = (char *)*(esp + 1);
		unsigned initial_size = (unsigned)*(esp + 2);
		ptr_check(file, f);
		ptr_inbounds(file, f);
		f->eax = filesys_create(file, initial_size);
	}

	else if(syscall_num == SYS_REMOVE)
	{
		char * file = (char*)*(esp + 1);
		ptr_check(file, f);
		ptr_inbounds(file, f);
		f->eax = filesys_remove(file);
	}
	else if(syscall_num == SYS_OPEN)
	{
		char * file = (char*)*(esp + 1);
		ptr_check(file, f);
		ptr_inbounds(file, f);
		

		struct file * fi = filesys_open(file);	
		if(!fi == NULL)
		{	
			int fd = fd_counter;
			fs[fd_counter-2].fd = fd;
			fs[fd_counter-2].f = fi;
			fs[fd_counter-2].active = true;
			++fd_counter;
			f->eax = (uint32_t)fd;
		}
		else
		{
			f->eax = -1;
		}
	}
	else if(syscall_num == SYS_FILESIZE)
	{
		int fd = (int)*(esp + 1);
		int i = 0;
		for(;i < fd_counter - 2; ++i)
		{
			if(fd == fs[i].fd && fs[i].active == true)
			{
				f->eax = file_length(fs[i].f);
				return;
			}
		}
		f->eax = -1;
		thread_exiter(-1, thread_current()->name);
	}
	else if(syscall_num == SYS_READ)
	{
		int fd = (int)*(esp + 1);
		void * buffer = (void*)*(esp + 2);
		unsigned size = (unsigned)*(esp + 3);
		ptr_check(buffer, f);
		if(esp + 3 >= PHYS_BASE)
		{
			thread_exiter(-1, thread_current()->name);
		}
		if(size <= 0)
		{
			f->eax = 0; return;
		}
		char * in_use = (char*)malloc(size + 1);
		/*
		if(fd == 0)
		{
			int i = 0;
			for(;i < size;++i)
			{
				uint8_t c = input_getc();
				if(c == '\n')
					break;
				put_user((char*)buffer + i, c);
			}
			f->eax = i;
			return;
		}
		*/
		int i = 0;
		for(;i < fd_counter - 2; ++i)
		{
			if(fd == fs[i].fd && fs[i].active == true)
			{
				unsigned s = file_read(fs[i].f, in_use, size);
				if(s != size)
				{
					f->eax = -1;
					thread_exiter(-1, thread_current()->name);
				}
				if(strlcpy(buffer, in_use, size+1))
				{
					f->eax = s;
				}
				else
				{
					f->eax = -1;
				}
				return;
			}
		}
		f->eax = -1;
	}
	else if(syscall_num == SYS_WRITE)
	{
		int fd = (int)*(esp + 1);
		char * buffer = (char*)*(esp + 2);
		unsigned size = (unsigned)*(esp+3);
		int i = 0;
		ptr_inbounds((void*)buffer, f);
		if(esp + 3 >= PHYS_BASE)
		{
			f->eax = -1;
			thread_exiter(-1, thread_current()->name);
		}
		if(fd == 1)
		{
			int k = size;
			for(; size > 0; size = size - 1)
			{
				putbuf(buffer, 1);
				buffer += 1;
			}
			putbuf(buffer, size);

			f->eax = k;
			return;
		}

		for(; i < fd_counter - 2; ++i)
		{
			if(fd == fs[i].fd && fs[i].active == true)
			{
				f->eax = file_write(fs[i].f, buffer, size);
				return;
			}
		}
		f->eax = -1;
		thread_exiter(-1, thread_current()->name);
	
	}
	if(syscall_num == SYS_CLOSE)
	{
		int fd = (int)*(esp + 1);
		int i = 0;
		for(; i < fd_counter - 2; ++i)
		{
			if(fd == fs[i].fd && fs[i].active == true)
			{
				fs[i].active = false;
				file_close(fs[i].f);
				f->eax = 1;
				return;
			}
		}
		f->eax = -1;
	}
	else
	{
		//printf("else\n");
	}
}
