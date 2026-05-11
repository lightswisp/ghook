// gcc -shared -o hook.so -fPIC hook.c
// Maybe i will add dynamic arrays later 
// Also, fread's might slow down the init phase
// 1:17:33
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <elf.h>

#include "../include/ghook.h"

/* ================= DEFINES ================= */
#define LOG_MAX_BUFFER_SIZE 4096
#define LOG_MAX_TIME_BUFFER_SIZE 1024
#define COLOR_START(x) "\033["x"m"
#define COLOR_END      "\033[0m"
#define RED            "31"
#define GREEN          "32"
#define YELLOW         "33"


/* ================= FUNCS ================= */
void ghook_logger_log(const char *func, const char *fmt, ...){
  char buffer[LOG_MAX_BUFFER_SIZE];
  char time_buffer[LOG_MAX_TIME_BUFFER_SIZE];
  time_t now;
  struct tm* tm;
  va_list args;

  now = time(NULL);
  tm  = localtime(&now);
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  strftime(time_buffer, sizeof(time_buffer), "%F %X", tm);
  printf(COLOR_START(GREEN)"[LOG @ %s]"COLOR_START(YELLOW)" %s:"COLOR_END" %s\n", time_buffer, func, buffer);
  va_end(args);
}

void ghook_logger_warn(const char *func, const char *fmt, ...){
  char buffer[LOG_MAX_BUFFER_SIZE];
  char time_buffer[LOG_MAX_TIME_BUFFER_SIZE];
  time_t now;
  struct tm* tm;
  va_list args;

  now = time(NULL);
  tm  = localtime(&now);
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  strftime(time_buffer, sizeof(time_buffer), "%F %X", tm);
  printf(COLOR_START(RED)"[WARN @ %s]"COLOR_START(YELLOW)" %s:"COLOR_END" %s\n", time_buffer, func, buffer);
  va_end(args);
}

void ghook_logger_fatal(const char *func, const char *fmt, ...){
  char buffer[LOG_MAX_BUFFER_SIZE];
  char time_buffer[LOG_MAX_TIME_BUFFER_SIZE];
  time_t now;
  struct tm* tm;
  va_list args;

  now = time(NULL);
  tm  = localtime(&now);
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  strftime(time_buffer, sizeof(time_buffer), "%F %X", tm);
  fprintf(stderr, COLOR_START(RED)"[FATAL @ %s]"COLOR_START(YELLOW)" %s:"COLOR_END" %s\n", time_buffer, func, buffer);
  va_end(args);
}

bool ghook_get_maps(maps_container_t *maps_container){
  FILE *f = NULL;
  char maps_buf[1024];

  f = fopen("/proc/self/maps", "r");
  if(f == NULL){
    ghook_logger_fatal(__func__, strerror(errno)); 
    return false;
  }

  while(fgets(maps_buf, sizeof(maps_buf), f)){
    maps_container->vma_count++;
  }
  rewind(f);
  maps_container->maps = malloc(maps_container->vma_count * sizeof(maps_t));
  if(maps_container->maps == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  size_t i = 0;
  while(fgets(maps_buf, sizeof(maps_buf), f)){

    if(i >= maps_container->vma_count) 
      break;

    sscanf(maps_buf, "%lx-%lx %4s %lx %254s %d %4095s", 
          &maps_container->maps[i].a_s, 
          &maps_container->maps[i].a_e, 
          maps_container->maps[i].perms, 
          &maps_container->maps[i].offset, 
          maps_container->maps[i].dev, 
          &maps_container->maps[i].inode, 
          maps_container->maps[i].pathname);
    i++;
  }

  ghook_logger_log(__func__,"base address: %p", maps_container->maps[0].a_s);
  fclose(f);
  return true;
}

void ghook_free_elf(elf_data_t *elf_data){
  free(elf_data->section_headers);
  free(elf_data->relocation_plt_tables);
  free(elf_data->relocation_dyn_tables);
  free(elf_data->section_strtab);
  free(elf_data->symbol_tables);
  free(elf_data->libraries_handles);
}

void ghook_free_maps(maps_container_t *maps_container){
  free(maps_container->maps);
}

bool ghook_get_elf_data(char *pathname, elf_data_t *elf_data){
  FILE *f = fopen(pathname, "rb");
  if(f == NULL){
    ghook_logger_fatal(__func__, strerror(errno)); 
    return false;
  }

  fread(&elf_data->header, 1, sizeof(Elf64_Ehdr), f);
  ghook_logger_log(__func__,"e_ident: %s", elf_data->header.e_ident);

  elf_data->section_headers = malloc(elf_data->header.e_shnum * sizeof(Elf64_Shdr));
  if(elf_data->section_headers == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  fseek(f, elf_data->header.e_shoff, SEEK_SET);
  /* reading all sections */
  for(Elf64_Half i = 0; i < elf_data->header.e_shnum; i++){
    fread(&elf_data->section_headers[i], 1, elf_data->header.e_shentsize, f);
  }
  /* allocating buffer for strings */
  elf_data->section_strtable = malloc(elf_data->section_headers[elf_data->header.e_shstrndx].sh_size);  
  if(elf_data->section_strtable == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  fseek(f, elf_data->section_headers[elf_data->header.e_shstrndx].sh_offset, SEEK_SET);
  fread(elf_data->section_strtable, 1, elf_data->section_headers[elf_data->header.e_shstrndx].sh_size, f); 

  /* now iterate through all sections */
  for(Elf64_Half i = 0; i < elf_data->header.e_shnum; i++){
    Elf64_Shdr current_section = elf_data->section_headers[i];
    /* skip these sections */
    if(current_section.sh_type == SHT_NULL || 
       current_section.sh_type == SHT_NOBITS)
      continue;

    if(current_section.sh_type == SHT_RELA){
      char *section_name = &elf_data->section_strtable[current_section.sh_name];
      if(strcmp(section_name, ".rela.plt") == 0) 
        elf_data->reltab_plt_header = elf_data->section_headers[i];

      if(strcmp(section_name, ".rela.dyn") == 0) 
        elf_data->reltab_dyn_header = elf_data->section_headers[i];
    }

    if(current_section.sh_type == SHT_DYNAMIC){
      elf_data->dynamic_header = elf_data->section_headers[i]; 
    }

    if(current_section.sh_type == SHT_DYNSYM){
      elf_data->symtab_header = elf_data->section_headers[i];
    }
  }

  free(elf_data->section_strtable);

  elf_data->strtab_header         = elf_data->section_headers[elf_data->symtab_header.sh_link];
  elf_data->dynstr_header         = elf_data->section_headers[elf_data->dynamic_header.sh_link];
  elf_data->dynamic_num           = elf_data->dynamic_header.sh_size / elf_data->dynamic_header.sh_entsize;
  elf_data->reltab_plt_num        = elf_data->reltab_plt_header.sh_size / elf_data->reltab_plt_header.sh_entsize;
  elf_data->reltab_dyn_num        = elf_data->reltab_dyn_header.sh_size / elf_data->reltab_dyn_header.sh_entsize;
  elf_data->symtab_num            = elf_data->symtab_header.sh_size / elf_data->symtab_header.sh_entsize;
  elf_data->relocation_plt_tables = malloc(sizeof(Elf64_Rela) * elf_data->reltab_plt_num);
  elf_data->relocation_dyn_tables = malloc(sizeof(Elf64_Rela) * elf_data->reltab_dyn_num);
  elf_data->symbol_tables         = malloc(sizeof(Elf64_Sym) * elf_data->symtab_num);
  elf_data->dynamic_section       = malloc(sizeof(Elf64_Dyn) * elf_data->dynamic_num);
  elf_data->section_strtab        = malloc(elf_data->strtab_header.sh_size);
  elf_data->dynstr                = malloc(elf_data->dynstr_header.sh_size);

  if(elf_data->relocation_plt_tables == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->relocation_dyn_tables == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->symbol_tables == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->section_strtab == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->dynamic_section == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->dynstr == NULL){
    ghook_logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  fseek(f, elf_data->dynstr_header.sh_offset, SEEK_SET);
  fread(elf_data->dynstr, 1, elf_data->dynstr_header.sh_size, f);

  fseek(f, elf_data->strtab_header.sh_offset, SEEK_SET);
  fread(elf_data->section_strtab, 1, elf_data->strtab_header.sh_size, f);

  fseek(f, elf_data->symtab_header.sh_offset, SEEK_SET);
  /* read all symbol tables */
  for(Elf64_Half i = 0; i < elf_data->symtab_num; i++){
    fread(&elf_data->symbol_tables[i], 1, elf_data->symtab_header.sh_entsize, f);
  }

  fseek(f, elf_data->reltab_plt_header.sh_offset, SEEK_SET);
  for(Elf64_Half i = 0; i < elf_data->reltab_plt_num; i++){
    fread(&elf_data->relocation_plt_tables[i], 1, elf_data->reltab_plt_header.sh_entsize, f);
  }

  fseek(f, elf_data->reltab_dyn_header.sh_offset, SEEK_SET);
  for(Elf64_Half i = 0; i < elf_data->reltab_dyn_num; i++){
    fread(&elf_data->relocation_dyn_tables[i], 1, elf_data->reltab_dyn_header.sh_entsize, f);
  }

  fseek(f, elf_data->dynamic_header.sh_offset, SEEK_SET);
  for(Elf64_Half i = 0; i < elf_data->dynamic_num; i++){
    fread(&elf_data->dynamic_section[i], sizeof(Elf64_Dyn), 1, f);
    if(elf_data->dynamic_section[i].d_tag == DT_NEEDED){
      if(elf_data->libraries_handles == NULL){ 
        elf_data->libraries_handles = malloc(sizeof(void*));
        if(elf_data->libraries_handles == NULL){
          ghook_logger_fatal(__func__, "malloc failed"); 
          return false;
        }
      }
      else{                                    
        elf_data->libraries_handles = realloc(elf_data->libraries_handles, elf_data->libraries_num* sizeof(void*)); 
        if(elf_data->libraries_handles == NULL){
          ghook_logger_fatal(__func__, "realloc failed"); 
          return false;
        }
      }

      const char *path = &elf_data->dynstr[elf_data->dynamic_section[i].d_un.d_val];
      elf_data->libraries_handles[elf_data->libraries_num] = dlopen(path, RTLD_NOW);
      if(elf_data->libraries_handles[elf_data->libraries_num] == NULL){
        ghook_logger_fatal(__func__, "unable to obtain handle for %s", path);
        return false;
      }
      ghook_logger_log(__func__, "got handle for %s = %p", path, elf_data->libraries_handles[elf_data->libraries_num]);
      elf_data->libraries_num++; 
    }
  }

  free(elf_data->dynamic_section);
  free(elf_data->dynstr);

  return true;
}

static bool ghook_get_function_offset(elf_data_t *elf_data, char *func, Elf64_Addr *rel_offset){
  ghook_logger_log(__func__,"[1] reading plt relocation table symbols...");
  for(Elf64_Half i = 0; i < elf_data->reltab_plt_num; i++){
    Elf64_Rela current_relocation = elf_data->relocation_plt_tables[i];
    uint32_t sym_index = ELF64_R_SYM(current_relocation.r_info);
    Elf64_Sym symbol_table = elf_data->symbol_tables[sym_index];
    char *symbol_name = &elf_data->section_strtab[symbol_table.st_name];
    ghook_logger_log(__func__, "checking %s", symbol_name);
    if(strcmp(symbol_name, func) == 0){
      *rel_offset = current_relocation.r_offset; 
      ghook_logger_log(__func__,"%s has offset: %lu", symbol_name, current_relocation.r_offset);
      return true;
    }
  }

  ghook_logger_log(__func__,"[2] reading dyn relocation table symbols...");
  for(Elf64_Half i = 0; i < elf_data->reltab_dyn_num; i++){
    Elf64_Rela current_relocation = elf_data->relocation_dyn_tables[i];
    uint32_t sym_index = ELF64_R_SYM(current_relocation.r_info);
    Elf64_Sym symbol_table = elf_data->symbol_tables[sym_index];
    char *symbol_name = &elf_data->section_strtab[symbol_table.st_name];
    ghook_logger_log(__func__, "checking %s", symbol_name);
    if(strcmp(symbol_name, func) == 0){
      *rel_offset = current_relocation.r_offset; 
      ghook_logger_log(__func__,"%s has offset: %lu", symbol_name, current_relocation.r_offset);
      return true;
    }
  }

  ghook_logger_fatal(__func__, "failed to find an offset");
  return false;
}

static uintptr_t* ghook_get_function_got_address(elf_data_t *elf_data, uintptr_t base, char *func){
  Elf64_Addr rel_offset = 0;
  if(!ghook_get_function_offset(elf_data, func, &rel_offset)){
    ghook_logger_fatal(__func__, "failed to obtain GOT address"); 
    return NULL;
  }
  uintptr_t *got_addr = (uintptr_t*)(base + rel_offset);
  return got_addr;

}

static void* resolve_function_addr(elf_data_t *elf_data, char *func){
  for(size_t i = 0; i < elf_data->libraries_num; i++){
    void* resolved_addr = dlsym(elf_data->libraries_handles[i], func);
    if(resolved_addr != NULL)
      return resolved_addr;
  }
  return NULL;
}

bool ghook_got_hook(elf_data_t *elf_data, maps_container_t *maps_container, char *func, uintptr_t replace_addr, uintptr_t *backup_addr){
  uintptr_t *orig_addr = ghook_get_function_got_address(elf_data, maps_container->maps[0].a_s, func);

  if(orig_addr == NULL){
    ghook_logger_fatal(__func__, "failed to obtain got address for %s", func); 
    return false;
  }

  void* resolved_addr = resolve_function_addr(elf_data, func);
  if(resolved_addr == NULL){
    ghook_logger_fatal(__func__, "unable to resolve %s", func);  
    return false;
  }

  *backup_addr = (uintptr_t)resolved_addr;
  
  for(size_t i = 0; i < maps_container->vma_count; i++){
    if((uintptr_t)orig_addr >= maps_container->maps[i].a_s &&
       (uintptr_t)orig_addr < maps_container->maps[i].a_e){
      /* check perms */
      if(maps_container->maps[i].perms[1] != 'w'){
        /* not writeable */
        size_t pagesize = sysconf(_SC_PAGESIZE);
        if(mprotect((void*)maps_container->maps[i].a_s, pagesize, PROT_READ | PROT_WRITE) != 0){
          ghook_logger_fatal(__func__, "failed to change page protection"); 
          return false;
        }
        ghook_logger_log(__func__, "successfully changed protection for %s page at %p", func, maps_container->maps[i].a_s);
      }
      break;
    }
  }

  ghook_logger_log(__func__,"GOT entry is at: %p", orig_addr);
  ghook_logger_log(__func__,"%s is at: %p", func, *orig_addr);
  *orig_addr = replace_addr;
  ghook_logger_log(__func__,"replaced original GOT with %p", replace_addr);
  ghook_logger_log(__func__,"hooked!");

  return true;
}

