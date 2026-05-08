// gcc -shared -o hook.so -fPIC hook.c
// 1:17:33
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include <linux/limits.h>
#include <pthread.h>
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

/* ================= DEFINES ================= */
#define LOG_MAX_BUFFER_SIZE 4096
#define LOG_MAX_TIME_BUFFER_SIZE 1024
#define COLOR_START(x) "\033["x"m"
#define COLOR_END      "\033[0m"
#define RED            "31"
#define GREEN          "32"
#define YELLOW         "33"

/* ================= TYPEDEFS ================= */
typedef struct {
  uintptr_t a_s, a_e;
  char perms[5];
  uint32_t offset;
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

  Elf64_Half symtab_idx;
  Elf64_Half reltab_plt_idx;
  Elf64_Half reltab_dyn_idx;

  Elf64_Shdr symtab_header;
  Elf64_Shdr reltab_plt_header;
  Elf64_Shdr reltab_dyn_header;
  Elf64_Shdr strtab_header;
  Elf64_Half reltab_plt_num;   
  Elf64_Half reltab_dyn_num;   
  Elf64_Half symtab_num;  

  Elf64_Rela* relocation_plt_tables; // dyn
  Elf64_Rela* relocation_dyn_tables; // dyn
  Elf64_Sym*  symbol_tables;     // dyn

  char* section_strtab;          // dyn

} elf_data_t;

/* ================= GLOBALS ================= */
pthread_t g_thread;
void *__main_thread(void *a);

/* ================= ORIGINAL ADDRS  ================= */
typedef int (*strcmp_sig)(const char*, const char*);
uintptr_t o_strcmp;
typedef int (*printf_sig)(const char *format, ...);
uintptr_t o_printf;


/* ================= FUNCS ================= */
void logger_log(const char *func, const char *fmt, ...){
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

void logger_warn(const char *func, const char *fmt, ...){
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

void logger_fatal(const char *func, const char *fmt, ...){
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

bool get_maps(pid_t pid, maps_container_t *maps_container){
  FILE *f = NULL;
  char path[PATH_MAX] = {0};
  char maps_buf[1024];

  sprintf(path, "/proc/%d/maps", pid);
  f = fopen(path, "r");
  if(f == NULL){
    logger_fatal(__func__, strerror(errno)); 
    return false;
  }

  while(fgets(maps_buf, sizeof(maps_buf), f)){
    maps_container->vma_count++;
  }
  rewind(f);
  maps_container->maps = malloc(maps_container->vma_count * sizeof(maps_t));

  size_t i = 0;
  while(fgets(maps_buf, sizeof(maps_buf), f)){
    sscanf(maps_buf, "%lx-%lx %s %x %s %d %s", 
          &maps_container->maps[i].a_s, 
          &maps_container->maps[i].a_e, 
          maps_container->maps[i].perms, 
          &maps_container->maps[i].offset, 
          maps_container->maps[i].dev, 
          &maps_container->maps[i].inode, 
          maps_container->maps[i].pathname);
    i++;
  }

  logger_log(__func__,"base address: %p", maps_container->maps[0].a_s);
  fclose(f);
  return true;
}

void free_elf(elf_data_t *elf_data){
  free(elf_data->section_headers);
  free(elf_data->section_strtable);
  free(elf_data->relocation_plt_tables);
  free(elf_data->relocation_dyn_tables);
  free(elf_data->section_strtab);
  free(elf_data->symbol_tables);
}

void free_maps(maps_container_t *maps_container){
  free(maps_container->maps);
}

bool get_elf_data(char *pathname, elf_data_t *elf_data){
  FILE *f = fopen(pathname, "rb");
  if(f == NULL){
    logger_fatal(__func__, strerror(errno)); 
    return false;
  }

  fread(&elf_data->header, 1, sizeof(Elf64_Ehdr), f);
  logger_log(__func__,"e_ident: %s", elf_data->header.e_ident);

  elf_data->section_headers = malloc(elf_data->header.e_shnum * sizeof(Elf64_Shdr));
  if(elf_data->section_headers == NULL){
    logger_fatal(__func__, "malloc failed"); 
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
    logger_fatal(__func__, "malloc failed"); 
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
      if(strcmp(section_name, ".rela.plt") == 0) elf_data->reltab_plt_idx = i;
      if(strcmp(section_name, ".rela.dyn") == 0) elf_data->reltab_dyn_idx = i;
    }

    if(current_section.sh_type == SHT_DYNSYM){
      elf_data->symtab_idx = i;
    }
  }

  elf_data->symtab_header         = elf_data->section_headers[elf_data->symtab_idx];
  elf_data->reltab_plt_header     = elf_data->section_headers[elf_data->reltab_plt_idx];
  elf_data->reltab_dyn_header     = elf_data->section_headers[elf_data->reltab_dyn_idx];
  elf_data->strtab_header         = elf_data->section_headers[elf_data->symtab_header.sh_link];
  elf_data->reltab_plt_num        = elf_data->reltab_plt_header.sh_size / elf_data->reltab_plt_header.sh_entsize;
  elf_data->reltab_dyn_num        = elf_data->reltab_dyn_header.sh_size / elf_data->reltab_dyn_header.sh_entsize;
  elf_data->symtab_num            = elf_data->symtab_header.sh_size / elf_data->symtab_header.sh_entsize;
  elf_data->relocation_plt_tables = malloc(sizeof(Elf64_Rela) * elf_data->reltab_plt_num);
  elf_data->relocation_dyn_tables = malloc(sizeof(Elf64_Rela) * elf_data->reltab_dyn_num);
  elf_data->symbol_tables         = malloc(sizeof(Elf64_Sym) * elf_data->symtab_num);

  if(elf_data->relocation_plt_tables == NULL){
    logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->relocation_dyn_tables == NULL){
    logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  if(elf_data->symbol_tables == NULL){
    logger_fatal(__func__, "malloc failed"); 
    return false;
  }

  elf_data->section_strtab = malloc(elf_data->strtab_header.sh_size);
  if(elf_data->section_strtab == NULL){
    logger_fatal(__func__, "malloc failed"); 
    return false;
  }

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

  return true;
}

bool get_function_offset(elf_data_t *elf_data, char *func, Elf64_Addr *rel_offset){
  logger_log(__func__,"[1] reading plt relocation table symbols...");
  for(Elf64_Half i = 0; i < elf_data->reltab_plt_num; i++){
    Elf64_Rela current_relocation = elf_data->relocation_plt_tables[i];
    uint32_t sym_index = ELF64_R_SYM(current_relocation.r_info);
    Elf64_Sym symbol_table = elf_data->symbol_tables[sym_index];
    char *symbol_name = &elf_data->section_strtab[symbol_table.st_name];
    logger_log(__func__, "checking %s", symbol_name);
    if(strcmp(symbol_name, func) == 0){
      *rel_offset = current_relocation.r_offset; 
      logger_log(__func__,"%s has offset: %lu", symbol_name, current_relocation.r_offset);
      return true;
    }
  }

  logger_log(__func__,"[2] reading dyn relocation table symbols...");
  for(Elf64_Half i = 0; i < elf_data->reltab_dyn_num; i++){
    Elf64_Rela current_relocation = elf_data->relocation_dyn_tables[i];
    uint32_t sym_index = ELF64_R_SYM(current_relocation.r_info);
    Elf64_Sym symbol_table = elf_data->symbol_tables[sym_index];
    char *symbol_name = &elf_data->section_strtab[symbol_table.st_name];
    logger_log(__func__, "checking %s", symbol_name);
    if(strcmp(symbol_name, func) == 0){
      *rel_offset = current_relocation.r_offset; 
      logger_log(__func__,"%s has offset: %lu", symbol_name, current_relocation.r_offset);
      return true;
    }
  }

  logger_fatal(__func__, "failed to find an offset");
  return false;
}

uintptr_t* get_function_got_address(elf_data_t *elf_data, uintptr_t base, char *func){
  Elf64_Addr rel_offset = 0;
  if(!get_function_offset(elf_data, func, &rel_offset)){
    logger_fatal(__func__, "failed to obtain GOT address"); 
    return NULL;
  }
  uintptr_t *got_addr = (uintptr_t*)(base + rel_offset);
  return got_addr;
}

bool got_hook(elf_data_t *elf_data, maps_container_t *maps_container, char *func, uintptr_t replace_addr, uintptr_t *backup_addr){
  uintptr_t *orig_addr = get_function_got_address(elf_data, maps_container->maps[0].a_s, func);

  if(orig_addr == NULL){
    logger_fatal(__func__, "failed to set hook for %s", func); 
    return false;
  }
  *backup_addr = *orig_addr;

  for(size_t i = 0; i < maps_container->vma_count; i++){
    if((uintptr_t)orig_addr >= maps_container->maps[i].a_s &&
       (uintptr_t)orig_addr < maps_container->maps[i].a_e){
      /* check perms */
      if(maps_container->maps[i].perms[1] != 'w'){
        /* not writeable */
        size_t pagesize = sysconf(_SC_PAGESIZE);
        if(mprotect((void*)maps_container->maps[i].a_s, pagesize, PROT_READ | PROT_WRITE) != 0){
          logger_fatal(__func__, "failed to change page protection"); 
          return false;
        }
        logger_log(__func__, "successfully changed protection for %s page at %p", func, maps_container->maps[i].a_s);
      }
      break;
    }
  }

  logger_log(__func__,"GOT entry is at: %p", orig_addr);
  logger_log(__func__,"%s is at: %p", func, *orig_addr);
  *orig_addr = replace_addr;
  logger_log(__func__,"replaced original GOT with %p", replace_addr);
  logger_log(__func__,"hooked!");

  return true;
}


__attribute__((constructor)) void __library_startup(){
  pthread_attr_t attr;
  /* start thread detached */
  if (-1 == pthread_attr_init(&attr))
    return;
  if (-1 == pthread_attr_setdetachstate(&attr,
                          PTHREAD_CREATE_DETACHED))
    return;
  /* spawn a thread to do the real work */
  pthread_create(&g_thread, NULL, __main_thread, NULL);
}


/* ================= REPLACED FUNCS ================= */
int strcmp_detour (const char *str1, const char *str2){
  logger_log(__func__, "str1: %s | str2: %s", str1, str2);

  strcmp_sig original_strcmp = (strcmp_sig)o_strcmp;
  return original_strcmp(str1, str2);
}

int printf_detour(const char *format, ...){
    va_list args;
    va_start(args, format);

    logger_log(__func__, "format: %s", format);

    printf_sig original_printf = (printf_sig)o_printf;

    int ret = vprintf(format, args);

    va_end(args);
    return ret;
}

void* __main_thread(void *a __attribute__((unused))){
  /* entry point */
  
  pid_t pid = getpid();
  logger_log(__func__, "current pid: %d", pid);

  maps_container_t maps_container = {0};

  if(!get_maps(pid, &maps_container)){
    logger_fatal(__func__, "unable to parse mappings");
    return NULL;
  }

  elf_data_t elf_data = {0};
  if(!get_elf_data(maps_container.maps[0].pathname, &elf_data)){
    logger_fatal(__func__, "unable to get elf data");
    return NULL;
  }
  
  got_hook(&elf_data, &maps_container, "strcmp", (uintptr_t)strcmp_detour, &o_strcmp);
  got_hook(&elf_data, &maps_container, "printf", (uintptr_t)printf_detour, &o_printf);

  free_elf(&elf_data);
  free_maps(&maps_container);
  return NULL;
}

__attribute__((destructor)) void __library_shutdown(){}
