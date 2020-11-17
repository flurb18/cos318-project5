/* Author(s): <Your name here>
 * COS 318, Fall 2019: Project 5 Virtual Memory
 * Implementation of the memory manager for the kernel.
*/

/* memory.c
 *
 * Note: 
 * There is no separate swap area. When a data page is swapped out, 
 * it is stored in the location it was loaded from in the process' 
 * image. This means it's impossible to start two processes from the 
 * same image without screwing up the running. It also means the 
 * disk image is read once. And that we cannot use the program disk.
 *
 */

#include "common.h"
#include "kernel.h"
#include "scheduler.h"
#include "memory.h"
#include "thread.h"
#include "util.h"
#include "interrupt.h"
#include "tlb.h"
#include "usb/scsi.h"

/* Static global variables */
// Keep track of all pages: their vaddr, status, and other properties
static page_map_entry_t page_map[PAGEABLE_PAGES];

// address of the kernel page directory (shared by all kernel threads)
static uint32_t *kernel_pdir;

// allocate the kernel page tables
static uint32_t *kernel_ptabs[N_KERNEL_PTS];

//other global variables...

/* Main API */

/* Use virtual address to get index in page directory. */
uint32_t get_dir_idx(uint32_t vaddr){
  return (vaddr & PAGE_DIRECTORY_MASK) >> PAGE_DIRECTORY_BITS;
}

/* Use virtual address to get index in a page table. */
uint32_t get_tab_idx(uint32_t vaddr){
  return (vaddr & PAGE_TABLE_MASK) >> PAGE_TABLE_BITS;
}

/* TODO: Returns physical address of page number i */
uint32_t* page_addr(int i){
  return (uint32_t *)(MEM_START + i * PAGE_SIZE);
}

/* Set flags in a page table entry to 'mode' */
void set_ptab_entry_flags(uint32_t * pdir, uint32_t vaddr, uint32_t mode){
  uint32_t dir_idx = get_dir_idx((uint32_t) vaddr);
  uint32_t tab_idx = get_tab_idx((uint32_t) vaddr);
  uint32_t dir_entry;
  uint32_t *tab;
  uint32_t entry;

  dir_entry = pdir[dir_idx];
  ASSERT(dir_entry & PE_P); /* dir entry present */
  tab = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  /* clear table[index] bits 11..0 */
  entry = tab[tab_idx] & PE_BASE_ADDR_MASK;

  /* set table[index] bits 11..0 */
  entry |= mode & ~PE_BASE_ADDR_MASK;
  tab[tab_idx] = entry;

  /* Flush TLB because we just changed a page table entry in memory */
  flush_tlb_entry(vaddr);
}

/* Initialize a page table entry
 *  
 * 'vaddr' is the virtual address which is mapped to the physical
 * address 'paddr'. 'mode' sets bit [12..0] in the page table entry.
 *   
 * If user is nonzero, the page is mapped as accessible from a user
 * application.
 */
void init_ptab_entry(uint32_t * table, uint32_t vaddr,
         uint32_t paddr, uint32_t mode){
  int index = get_tab_idx(vaddr);
  table[index] =
    (paddr & PE_BASE_ADDR_MASK) | (mode & ~PE_BASE_ADDR_MASK);
  flush_tlb_entry(vaddr);
}

/* Insert a page table entry into the page directory. 
 *   
 * 'mode' sets bit [12..0] in the page table entry.
 */
void insert_ptab_dir(uint32_t * dir, uint32_t *tab, uint32_t vaddr, 
		       uint32_t mode){

  uint32_t access = mode & MODE_MASK;
  int idx = get_dir_idx(vaddr);

  dir[idx] = ((uint32_t)tab & PE_BASE_ADDR_MASK) | access;
}

/* TODO: Allocate a page. Return page index in the page_map directory.
 * 
 * Marks page as pinned if pinned == TRUE. 
 * Swap out a page if no space is available. 
 */
int page_alloc(int pinned){
  int i;
  for (i = 0; i < PAGEABLE_PAGES; i++) {
    if (page_map[i].is_free) {
      page_map[i].is_free = FALSE;
      page_map[i].pinned = FALSE;
      if (pinned)
        page_map[i].pinned = TRUE;
      bzero((char *)page_addr(i), PAGE_SIZE);
      return i;
    }
  }
  return 0;
}

/* TODO: Set up kernel memory for kernel threads to run.
 *
 * This method is only called once by _start() in kernel.c, and is only 
 * supposed to set up the page directory and page tables for the kernel.
 */
void init_memory(void){
  uint32_t dir_idx;
  uint32_t tab_idx;
  uint32_t addr = 0;
  uint32_t mode;
  kernel_pdir = page_addr(page_alloc(TRUE));
  for (dir_idx = 0; dir_idx < N_KERNEL_PTS; dir_idx++) {
    kernel_ptabs[dir_idx] = page_addr(page_alloc(TRUE));
    insert_ptab_dir(kernel_pdir, kernel_ptabs[dir_idx],
                    (uint32_t) kernel_ptabs[dir_idx], PE_P | PE_RW | PE_US);
    for (tab_idx = 0; addr < MAX_PHYSICAL_MEMORY && tab_idx < PAGE_N_ENTRIES;
         tab_idx++, addr += PAGE_SIZE) {
      mode = PE_P | PE_RW;
      if (addr >= SCREEN_MEM_START && addr < SCREEN_MEM_END)
        mode = mode | PE_US;
      init_ptab_entry(kernel_ptabs[dir_idx], addr, addr, mode);
    }
  }
}


/* TODO: Set up a page directory and page table for a new 
 * user process or thread. */
void setup_page_table(pcb_t * p){
  uint32_t *pdir = page_addr(page_alloc(FALSE));
  uint32_t *ptab;
  uint32_t *page;
  // Round up the number of tables we'll need
  uint32_t num_tabs = (p->swap_size + PTABLE_SPAN - 1) / PTABLE_SPAN;
  uint32_t dir_idx;
  uint32_t vaddr = 0;
  uint32_t tab_idx;
  for (dir_idx = 0; dir_idx < num_tabs; dir_idx++) {
    ptab = page_addr(page_alloc(FALSE));
    insert_ptab_dir(pdir, ptab, vaddr, PE_P | PE_RW | PE_US);
    for (tab_idx = 0; vaddr < p->swap_size && tab_idx < PAGE_N_ENTRIES;
         tab_idx++, vaddr += PAGE_SIZE) {
      page = page_addr(page_alloc(FALSE));
      init_ptab_entry(ptab, vaddr, (uint32_t)page, PE_P | PE_RW | PE_US);
      
    }
  }
  p->page_directory = pdir;
}

/* TODO: Swap into a free page upon a page fault.
 * This method is called from interrupt.c: exception_14(). 
 * Should handle demand paging.
 */
void page_fault_handler(void){
  
}

/* Get the sector number on disk of a process image
 * Used for page swapping. */
int get_disk_sector(page_map_entry_t * page){
  return page->swap_loc +
    ((page->vaddr - PROCESS_START) / PAGE_SIZE) * SECTORS_PER_PAGE;
}

/* TODO: Swap i-th page in from disk (i.e. the image file) */
void page_swap_in(int i){
  
}

/* TODO: Swap i-th page out to disk.
 *   
 * Write the page back to the process image.
 * There is no separate swap space on the USB.
 * 
 */
void page_swap_out(int i){
  
}


/* TODO: Decide which page to replace, return the page number  */
int page_replacement_policy(void){
 
}
