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

static void syscall_handler (struct intr_frame *);

/*void
halt(void)
{
	shutdown_power_off();
}*/



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //thread_exit ();
	uint32_t * esp = f->esp;
	
	if(esp == NULL || is_kernel_vaddr(esp) || 
		pagedir_get_page(thread_current()->pagedir, esp) == NULL)
	{
		uintptr_t ptr; 
		ptr = pg_no(esp);
		pagedir_destroy((uint32_t*)ptr);
		thread_exit();
	}
	uint32_t syscall_num = *esp;
	printf("syscall_num: %i \n", (int)syscall_num);
	if(syscall_num == SYS_HALT)
	{
		shutdown_power_off();
	}
	else if(syscall_num == SYS_EXIT)
	{
		printf("syscall_exit\n");
		int status = *(esp + 1);
		thread_current()->status = status;
		thread_exit();
	}
	else if(syscall_num == SYS_EXEC)
	{
		char * cmd_line = (char*)*(esp + 1);
		int i = 0;
		char * c = 0;
		for(c = (cmd_line + i); c != NULL; ++i, c = (cmd_line + i))
		{
			if((void*)c >= PHYS_BASE)
			{
				f->eax = -1;
				thread_current()->status = -1;
				thread_exit();
			}
		}
		f->eax = process_execute(cmd_line);
	}
	else if(syscall_num == SYS_WAIT)
	{
		tid_t cpid = (tid_t)*(esp + 1);
		process_wait(cpid);
	}
	else if(syscall_num == SYS_CREATE)
	{
		char * file = (char *)*(esp + 1);
		int i = 0;
		char * c = 0;
		for(c = (file + i); c != NULL;)
		{
			if((void*)c >= PHYS_BASE)
			{
				f->eax = -1;
				thread_exit();
			}
			++i; c = (file + i);
		}
		unsigned initial_size = (unsigned)*(esp + 2);
		f->eax = filesys_create(file, initial_size);
	}
	else if(syscall_num == SYS_REMOVE)
	{
		char * file = (char*)*(esp + 1);
		int i = 0;
		char * c = 0;
		for(c = (file + i); c != NULL;)
		{
			if((void*)c >= PHYS_BASE)
			{
				f->eax = -1;
				thread_exit();
			}
			++i; c = (file + i);
		}
		i = 0;
		//file * fi = NULL;
		//for(; i <= fd_counter - 2; ++i)
		//{
			//if(fs[
		f->eax = filesys_remove(file);
	}
	else if(syscall_num == SYS_OPEN)
	{
		char * file = (char*)*(esp + 1);
		int i = 0;
		char * c = 0;
		for(c = (file + i); c != NULL;)
		{
			if((void*)c >= PHYS_BASE)
				thread_exit();
			++i; c = (file + i);
		}

		struct file * fi = filesys_open(file);
		
		if(fi == NULL)
		{
			f->eax = -1;
			thread_exit();
			return;
		}

		int fd = fd_counter++;
		
		fs[fd_counter-2]->fd = fd;
		fs[fd_counter-2]->f = fi;
		f->eax = (uint32_t)fd;
	}
	else if(syscall_num == SYS_FILESIZE)
	{
		int fd = (int)*(esp + 1);
		int i = 0;
		//char * c = 0;	

		for(;i < fd_counter - 2; ++i)
		{
			if(fd == fs[i]->fd)
			{
				f->eax = file_length(fs[i]->f);
				return;
			}
		}
		f->eax = -1;
		thread_exit();

	}
	else if(syscall_num == SYS_READ)
	{
		int fd = (int)*(esp + 1);
		void * buffer = (void*)*(esp + 1);
		unsigned size = (unsigned)*(esp + 1);
		int i = 0;
		//struct file * fi = NULL;
		for(;i < fd_counter - 2; ++i)
		{
			if(fd == fs[i]->fd)
			{
				f->eax = file_read(fs[i]->f, buffer, size);
				return;
			}
		}
		f->eax = -1;
		thread_exit();
	}
	else if(syscall_num == SYS_WRITE)
	{
		printf("syscall write\n");
		int fd = (int)*(esp + 1);
		void * buffer = (void*)*(esp + 2);
		unsigned size = (unsigned)*(esp+3);
		int i = 0;
		struct file * fi = NULL;
		printf("fd: %i\n", fd);
		if(fd == 1)
		{
			putbuf(buffer, size);
			f->eax = size;
			printf("wrote to console\n");
			return;
		}

		for(; i < fd_counter - 2; ++i)
		{
			if(fd == fs[i]->fd)
			{
				f->eax = file_write(fs[i]->f, buffer, size);
			}
		}
	}



}
