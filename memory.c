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
// pointers for FIFO page_replacement_policy
static int first;
static int last;

/* //uncomment for NRU extra credit
static page_map_entry_t class_zero[PAGEABLE_PAGES];
static page_map_entry_t class_one[PAGEABLE_PAGES];
static page_map_entry_t class_two[PAGEABLE_PAGES];
static page_map_entry_t class_three[PAGEABLE_PAGES];

static int one_last;
static int two_last;
static int three_last; */

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
  int i = page_replacement_policy();
  lock_acquire(&page_map[i].page_lock);
  page_swap_out(i);
  if (pinned)
    page_map[i].pinned = TRUE;
  else
    page_map[i].pinned = FALSE;
  bzero((char *)page_addr(i), PAGE_SIZE);
  page_map[i].is_free = FALSE;
  lock_release(&page_map[i].page_lock);
  return i;
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
  int i;
  for (i = 0; i < PAGEABLE_PAGES; i++) {
    page_map[i].is_free = TRUE;
    page_map[i].pinned = FALSE;
    lock_init(&page_map[i].page_lock);
  }
  kernel_pdir = page_addr(page_alloc(TRUE));
  for (dir_idx = 0; dir_idx < N_KERNEL_PTS; dir_idx++) {
    kernel_ptabs[dir_idx] = page_addr(page_alloc(TRUE));
    insert_ptab_dir(kernel_pdir, kernel_ptabs[dir_idx], addr, PE_P | PE_RW);
    for (tab_idx = 0; addr < MAX_PHYSICAL_MEMORY && tab_idx < PAGE_N_ENTRIES;
         tab_idx++, addr += PAGE_SIZE)
      init_ptab_entry(kernel_ptabs[dir_idx], addr, addr, PE_P | PE_RW);
  }
}


/* TODO: Set up a page directory and page table for a new 
 * user process or thread. */
void setup_page_table(pcb_t * p){
  long eflags = CLI_FL();
  if (p->is_thread) {
    p->page_directory = kernel_pdir;
    STI_FL(eflags);
    return;
  }
  uint32_t *pdir = page_addr(page_alloc(TRUE));
  uint32_t *ptab;
  // Size of process in bytes
  uint32_t proc_size = p->swap_size / SECTORS_PER_PAGE;
  // Round up the number of tables we'll need for the process itself
  uint32_t num_tabs = (proc_size + PTABLE_SPAN - 1) / PTABLE_SPAN;
  uint32_t num_stack_tabs =
    (N_PROCESS_STACK_PAGES + PAGE_N_ENTRIES - 1) / PAGE_N_ENTRIES;
  uint32_t dir_idx;
  uint32_t tab_idx;
  uint32_t mode;
  uint32_t vaddr = 0;
  // Setup kernel/screen pages
  for (dir_idx = 0; dir_idx < N_KERNEL_PTS; dir_idx++) {
    ptab = page_addr(page_alloc(TRUE));
    insert_ptab_dir(pdir, ptab, vaddr, PE_P | PE_RW | PE_US);
    for (tab_idx = 0; vaddr < PROCESS_START && tab_idx < PAGE_N_ENTRIES;
         tab_idx++, vaddr += PAGE_SIZE) {
      mode = PE_P | PE_RW;
      if (vaddr == SCREEN_ADDR)
        mode |= PE_US;
      init_ptab_entry(ptab, vaddr, vaddr, mode);
    }
  }
  // Setup process pages
  vaddr = PROCESS_START;
  for (dir_idx = 0; dir_idx < num_tabs; dir_idx++) {
    ptab = page_addr(page_alloc(TRUE));
    insert_ptab_dir(pdir, ptab, vaddr, PE_P | PE_RW | PE_US);
    for (tab_idx = 0;
         vaddr < PROCESS_START + proc_size && tab_idx < PAGE_N_ENTRIES;
         tab_idx++, vaddr += PAGE_SIZE)
      // Pages will get swapped in as they fault
      init_ptab_entry(ptab, vaddr, 0, PE_RW | PE_US);
  }
  // Setup process stack pages
  vaddr = PROCESS_STACK & PE_BASE_ADDR_MASK;
  int stack_page_n = 0;
  for (dir_idx = 0; dir_idx < num_stack_tabs; dir_idx++) {
    ptab = page_addr(page_alloc(TRUE));
    insert_ptab_dir(pdir, ptab, vaddr, PE_RW | PE_P | PE_US);
    for (tab_idx = 0;
         tab_idx < PAGE_N_ENTRIES && stack_page_n < N_PROCESS_STACK_PAGES;
         tab_idx++, stack_page_n++, vaddr -= PAGE_SIZE)
      // Pages will get swapped in as they fault
      init_ptab_entry(ptab, vaddr, 0, PE_RW | PE_US);
  }
  p->page_directory = pdir;
  STI_FL(eflags);
}

/* TODO: Swap into a free page upon a page fault.
 * This method is called from interrupt.c: exception_14(). 
 * Should handle demand paging.
 */
void page_fault_handler(void){
  int p_idx = page_replacement_policy();
  lock_acquire(&page_map[p_idx].page_lock);
  page_swap_out(p_idx);
  long eflags = CLI_FL();
  current_running->page_fault_count++;
  page_map[p_idx].vaddr = current_running->fault_addr;
  page_map[p_idx].swap_loc = current_running->swap_loc;
  page_map[p_idx].pdir = current_running->page_directory;
  STI_FL(eflags);
  page_swap_in(p_idx);
  lock_release(&page_map[p_idx].page_lock);
}

/* Get the sector number on disk of a process image
 * Used for page swapping. */
int get_disk_sector(page_map_entry_t * page){
  return page->swap_loc +
    ((page->vaddr - PROCESS_START) / PAGE_SIZE) * SECTORS_PER_PAGE;
}

/* NOTE: For both page_swap_in and page_swap_out, it is callers responsibility
   to acquire the page lock first */

/* Swap i-th page in from disk (i.e. the image file) */
void page_swap_in(int i){
  ASSERT2(!page_map[i].pinned, "Attempted to swap pinned page");
  scsi_read(get_disk_sector(&page_map[i]), SECTORS_PER_PAGE,
            (char *)page_addr(i));
  uint32_t dir_idx = get_dir_idx((uint32_t) page_map[i].vaddr);
  uint32_t dir_entry = page_map[i].pdir[dir_idx];
  ASSERT(dir_entry & PE_P);
  init_ptab_entry((uint32_t *) (dir_entry & PE_BASE_ADDR_MASK),
                  page_map[i].vaddr, (uint32_t)page_addr(i),
                  PE_P | PE_RW | PE_US);
  page_map[i].is_free = FALSE;
}

/* TODO: Swap i-th page out to disk.
 *   
 * Write the page back to the process image.
 * There is no separate swap space on the USB.
 * 
 */
void page_swap_out(int i){
  ASSERT2(!page_map[i].pinned, "Attempted to swap pinned page");
  if (page_map[i].is_free)
    return;
  scsi_write(get_disk_sector(&page_map[i]), SECTORS_PER_PAGE,
             (char *)page_addr(i));
  set_ptab_entry_flags(page_map[i].pdir, page_map[i].vaddr, PE_US | PE_RW);
}


/* TODO: Decide which page to replace, return the page number  */
int page_replacement_policy(void){
   int i;
   for (i = 0; i < PAGEABLE_PAGES; i++) {
     if (page_map[i].is_free)
       return i;
   }
   for (i = 0; i < PAGEABLE_PAGES; i++) {
     if (!page_map[i].pinned)
       return i;
   }
   return 0;

   /*
   // uncomment for nru implementation 
   for (i = 0; i < PAGEABLE_PAGES; i++) {
     if (class_zero[i] != NULL) {
       accessed = (class_zero[i]->vaddr & (1 << 5)) >> 5;
       dirty = (class_zero[i]->vaddr & (1 << 6)) >> 6;
       if (accessed && dirty) {
         class_three[i] = class_zero[i];
         class_zero[i] = NULL;
         three_last = i;
       }
       else if (accessed && !dirty) {
         class_two[i] = class_zero[i];
         class_zero[i] = NULL;
         two_last = i;
       }
       else if (!accessed && dirty) {
         class_one[i] = class_zero[i];
         class_zero[i] = NULL;
         one_last = i;
       }
       else {
        if (!class_zero[i]->pinned) return i;
       }
     }
   }
   for (i = 0; i < one_last; i++) {
     if (class_one[i] != NULL) {
       if (!class_one[i]->pinned) return i;
     }
   }
   for (i = 0; i < two_last; i++) {
     if (class_two[i] != NULL) { 
      if (!class_two[i]->pinned) return i;
     }
   }
   for (i = 0; i < three_last; i++) {
     if (class_three[i] != NULL) {
       if (!class_three[i]->pinned) return i;
     } 
   }
   return 0; */
}
