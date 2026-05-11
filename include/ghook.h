#pragma once

#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/limits.h>

/* ================= TYPEDEFS ================= */
typedef struct {
  uintptr_t a_s, a_e;
  char perms[5];
  uintptr_t offset;
  char dev[255];
  int inode;
  char pathname[PATH_MAX];
} maps_t;

typedef struct {
  maps_t *maps;
  size_t vma_count;
} maps_container_t;

typedef struct {
  Elf64_Ehdr  header;
  Elf64_Shdr* section_headers;  // dyn
  char*       section_strtable; // dyn

  Elf64_Shdr symtab_header;
  Elf64_Shdr dynamic_header;
  Elf64_Shdr reltab_plt_header;
  Elf64_Shdr reltab_dyn_header;
  Elf64_Shdr strtab_header;
  Elf64_Shdr dynstr_header;
  Elf64_Half reltab_plt_num;   
  Elf64_Half reltab_dyn_num;   
  Elf64_Half symtab_num;  
  Elf64_Half dynamic_num;   

  Elf64_Dyn*  dynamic_section;      // dyn
  Elf64_Rela* relocation_plt_tables; // dyn
  Elf64_Rela* relocation_dyn_tables; // dyn
  Elf64_Sym*  symbol_tables;     // dyn
                                 //
  size_t      libraries_num;
  void**      libraries_handles; // dyn

  char* section_strtab;          // dyn
  char* dynstr;                  // dyn

} elf_data_t;

bool ghook_get_maps(maps_container_t *maps_container);
bool ghook_get_elf_data(char *pathname, elf_data_t *elf_data);
bool ghook_got_hook(elf_data_t *elf_data, maps_container_t *maps_container, char *func, char *lib, uintptr_t replace_addr, uintptr_t *backup_addr);
void ghook_free_elf(elf_data_t *elf_data);
void ghook_free_maps(maps_container_t *maps_container);
void ghook_logger_log(const char *func, const char *fmt, ...);
void ghook_logger_warn(const char *func, const char *fmt, ...);
void ghook_logger_fatal(const char *func, const char *fmt, ...);
