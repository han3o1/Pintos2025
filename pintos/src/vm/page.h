#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "vm/swap.h"
#include <hash.h>
#include "filesys/off_t.h"

enum page_status {
  ALL_ZERO,
  ON_FRAME,
  ON_SWAP,
  FROM_FILESYS
};

struct supplemental_page_table
  {
    struct hash page_map;
  };

struct supplemental_page_table_entry
  {
    void *upage;
    void *kpage;
    struct hash_elem elem;
    enum page_status status;
    bool dirty;
    swap_index_t swap_index;
    struct file *file;
    off_t file_offset;
    uint32_t read_bytes, zero_bytes;
    bool writable;
  };

struct supplemental_page_table* vm_spt_create (void);
void vm_spt_destroy (struct supplemental_page_table *);

bool vm_spt_install_frame (struct supplemental_page_table *spt, void *upage, void *kpage);
bool vm_spt_install_zeropage (struct supplemental_page_table *spt, void *);
bool vm_spt_set_swap (struct supplemental_page_table *, void *, swap_index_t);
bool vm_spt_install_filesys (struct supplemental_page_table *spt, void *page,
    struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

struct supplemental_page_table_entry* vm_spt_lookup (struct supplemental_page_table *spt, void *);
bool vm_spt_has_entry (struct supplemental_page_table *, void *page);

bool vm_spt_set_dirty (struct supplemental_page_table *spt, void *, bool);

bool vm_load_page(struct supplemental_page_table *spt, uint32_t *pagedir, void *upage);

bool vm_spt_mm_unmap(struct supplemental_page_table *spt, uint32_t *pagedir,
    void *page, struct file *f, off_t offset, size_t bytes);

void vm_pin_page(struct supplemental_page_table *spt, void *page);
void vm_unpin_page(struct supplemental_page_table *spt, void *page);

#endif