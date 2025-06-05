#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"

static unsigned spte_hash_func(const struct hash_elem *elem, void *aux);
static bool     spte_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static void     spte_destroy_func(struct hash_elem *elem, void *aux);

struct supplemental_page_table*
vm_supt_create (void)
{
  struct supplemental_page_table *supt =
    (struct supplemental_page_table*) malloc(sizeof(struct supplemental_page_table));

  hash_init (&supt->page_map, spte_hash_func, spte_less_func, NULL);
  return supt;
}

void
vm_supt_destroy (struct supplemental_page_table *supt)
{
  ASSERT (supt != NULL);

  hash_destroy (&supt->page_map, spte_destroy_func);
  free (supt);
}

bool
vm_supt_install_frame (struct supplemental_page_table *supt, void *upage, void *kpage)
{
  struct supplemental_page_table_entry *spte;
  spte = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

  spte->upage = upage;
  spte->kpage = kpage;
  spte->status = ON_FRAME;
  spte->dirty = false;
  spte->swap_index = -1;

  struct hash_elem *prev_elem;
  prev_elem = hash_insert (&supt->page_map, &spte->elem);
  if (prev_elem == NULL) {
    return true;
  }
  else {
    free (spte);
    return false;
  }
}

bool
vm_supt_install_zeropage (struct supplemental_page_table *supt, void *upage)
{
  struct supplemental_page_table_entry *spte;
  spte = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

  spte->upage = upage;
  spte->kpage = NULL;
  spte->status = ALL_ZERO;
  spte->dirty = false;

  struct hash_elem *prev_elem;
  prev_elem = hash_insert (&supt->page_map, &spte->elem);
  if (prev_elem == NULL) return true;

  PANIC("Duplicated SUPT entry for zeropage");
  return false;
}

bool
vm_supt_set_swap (struct supplemental_page_table *supt, void *page, swap_index_t swap_index)
{
  struct supplemental_page_table_entry *spte;
  spte = vm_supt_lookup(supt, page);
  if(spte == NULL) return false;

  spte->status = ON_SWAP;
  spte->kpage = NULL;
  spte->swap_index = swap_index;
  return true;
}

bool
vm_supt_install_filesys (struct supplemental_page_table *supt, void *upage,
    struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  struct supplemental_page_table_entry *spte;
  spte = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

  spte->upage = upage;
  spte->kpage = NULL;
  spte->status = FROM_FILESYS;
  spte->dirty = false;
  spte->file = file;
  spte->file_offset = offset;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->writable = writable;

  struct hash_elem *prev_elem;
  prev_elem = hash_insert (&supt->page_map, &spte->elem);
  if (prev_elem == NULL) return true;

  PANIC("Duplicated SUPT entry for filesys-page");
  return false;
}

struct supplemental_page_table_entry*
vm_supt_lookup (struct supplemental_page_table *supt, void *page)
{
  struct supplemental_page_table_entry spte_temp;
  spte_temp.upage = page;

  struct hash_elem *elem = hash_find (&supt->page_map, &spte_temp.elem);
  if(elem == NULL) return NULL;
  return hash_entry(elem, struct supplemental_page_table_entry, elem);
}

bool
vm_supt_has_entry (struct supplemental_page_table *supt, void *page)
{
  struct supplemental_page_table_entry *spte = vm_supt_lookup(supt, page);
  if(spte == NULL) return false;

  return true;
}

bool
vm_supt_set_dirty (struct supplemental_page_table *supt, void *page, bool value)
{
  struct supplemental_page_table_entry *spte = vm_supt_lookup(supt, page);
  if (spte == NULL) PANIC("set dirty - the request page doesn't exist");

  spte->dirty = spte->dirty || value;
  return true;
}

static bool vm_load_page_from_filesys(struct supplemental_page_table_entry *, void *);

bool
vm_load_page(struct supplemental_page_table *supt, uint32_t *pagedir, void *upage)
{
  struct supplemental_page_table_entry *spte;
  spte = vm_supt_lookup(supt, upage);
  if(spte == NULL) {
    return false;
  }

  if(spte->status == ON_FRAME) {
    return true;
  }

  void *frame_page = vm_frame_allocate(PAL_USER, upage);
  if(frame_page == NULL) {
    return false;
  }

  bool writable = true;
  switch (spte->status)
  {
  case ALL_ZERO:
    memset (frame_page, 0, PGSIZE);
    break;

  case ON_FRAME:
    break;

  case ON_SWAP:
    vm_swap_in (spte->swap_index, frame_page);
    break;

  case FROM_FILESYS:
    if( vm_load_page_from_filesys(spte, frame_page) == false) {
      vm_frame_free(frame_page);
      return false;
    }

    writable = spte->writable;
    break;

  default:
    PANIC ("unreachable state");
  }

  if(!pagedir_set_page (pagedir, upage, frame_page, writable)) {
    vm_frame_free(frame_page);
    return false;
  }

  spte->kpage = frame_page;
  spte->status = ON_FRAME;

  pagedir_set_dirty (pagedir, frame_page, false);

  vm_frame_unpin(frame_page);

  return true;
}

bool
vm_supt_mm_unmap(
    struct supplemental_page_table *supt, uint32_t *pagedir,
    void *page, struct file *f, off_t offset, size_t bytes)
{
  struct supplemental_page_table_entry *spte = vm_supt_lookup(supt, page);
  if(spte == NULL) {
    PANIC ("munmap - some page is missing; can't happen!");
  }

  if (spte->status == ON_FRAME) {
    ASSERT (spte->kpage != NULL);
    vm_frame_pin (spte->kpage);
  }

  switch (spte->status)
  {
  case ON_FRAME:
    ASSERT (spte->kpage != NULL);

    bool is_dirty = spte->dirty;
    is_dirty = is_dirty || pagedir_is_dirty(pagedir, spte->upage);
    is_dirty = is_dirty || pagedir_is_dirty(pagedir, spte->kpage);
    if(is_dirty) {
      file_write_at (f, spte->upage, bytes, offset);
    }

    vm_frame_free (spte->kpage);
    pagedir_clear_page (pagedir, spte->upage);
    break;

  case ON_SWAP:
    {
      bool is_dirty = spte->dirty;
      is_dirty = is_dirty || pagedir_is_dirty(pagedir, spte->upage);
      if (is_dirty) {
        void *tmp_page = palloc_get_page(0);
        vm_swap_in (spte->swap_index, tmp_page);
        file_write_at (f, tmp_page, PGSIZE, offset);
        palloc_free_page(tmp_page);
      }
      else {
        vm_swap_free (spte->swap_index);
      }
    }
    break;

  case FROM_FILESYS:
    break;

  default:
    PANIC ("unreachable state");
  }

  hash_delete(& supt->page_map, &spte->elem);
  return true;
}


static bool vm_load_page_from_filesys(struct supplemental_page_table_entry *spte, void *kpage)
{
  file_seek (spte->file, spte->file_offset);

  int n_read = file_read (spte->file, kpage, spte->read_bytes);
  if(n_read != (int)spte->read_bytes)
    return false;

  ASSERT (spte->read_bytes + spte->zero_bytes == PGSIZE);
  memset (kpage + n_read, 0, spte->zero_bytes);
  return true;
}

void
vm_pin_page(struct supplemental_page_table *supt, void *page)
{
  struct supplemental_page_table_entry *spte;
  spte = vm_supt_lookup(supt, page);
  if(spte == NULL) {
    return;
  }

  ASSERT (spte->status == ON_FRAME);
  vm_frame_pin (spte->kpage);
}

void
vm_unpin_page(struct supplemental_page_table *supt, void *page)
{
  struct supplemental_page_table_entry *spte;
  spte = vm_supt_lookup(supt, page);
  if(spte == NULL) PANIC ("request page is non-existent");

  if (spte->status == ON_FRAME) {
    vm_frame_unpin (spte->kpage);
  }
}

static unsigned
spte_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);
  return hash_int( (int)entry->upage );
}

static bool
spte_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct supplemental_page_table_entry *a_entry = hash_entry(a, struct supplemental_page_table_entry, elem);
  struct supplemental_page_table_entry *b_entry = hash_entry(b, struct supplemental_page_table_entry, elem);
  return a_entry->upage < b_entry->upage;
}

static void
spte_destroy_func(struct hash_elem *elem, void *aux UNUSED)
{
  struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);

  if (entry->kpage != NULL) {
    ASSERT (entry->status == ON_FRAME);
    vm_frame_remove_entry (entry->kpage);
  }
  else if(entry->status == ON_SWAP) {
    vm_swap_free (entry->swap_index);
  }

  free (entry);
}