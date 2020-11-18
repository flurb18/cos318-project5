// readme.txt

We began our implemntation with page_addr, which returns the page 
address by taking the address of the start of the memory and adding
the page number times the size of each page. 

To implement page_alloc, we lock, swap out a page if necessary using
page_replacement_policy, mark whether the page is pinned, zero it out, 
mark it as not free, release the lock and return.

For init_memory, we initially set up the page_map array by marking the 
pages as free, not pinned, and initializing their locks. We create the
page table directory for the kernel, and populate the kernel_ptabs 
array and insert the pages into the directory.

Next, we moved on to setup_page_table, where we first check if the 
pcb we're handed belongs to a thread. If so, we set its page directory
to the kernel page directory, set its flags, and return. If not, we
set up the kernel/screen pages and insert them into the directory,
set up the process pages, set up the process stack pages, set the pcb's
directory to the page directory we made, and set the flags.

For page_fault_handler, we lock, swap out a page using page_replacement
policy, set the flags, increase the fault count for the current process,
put the current process in the page_map at the index of the swapped out
page, set the flags, swap in the replaced page, and release the lock.

For swap in, we set the directory index to the directory index of the
given page, the directory entry to the directory entry of the given page,
initialize the page table engry, and mark that the page is not free.

For swap_out, if the page is free, we return. If not, we write it to 
disk and set the entry flags.

For page replacement policy, we used a simple round robin FIFO, where
we return the index of the first non-pinned page.

We attempted both extra credits. For FIFO with second chance,
uncomment lines 290-291 and 300-301, where we check the accessed bit
to see if the page has been accessed since last replacement. For NRU, 
comment out 287-307 and uncomment 42-50 and 308-349. We used four class
arrays and checked the dirty and accessed bit every time we call 
page replacement policy to populate the arrays and remove the first 
unpinned page of the lowest class.
