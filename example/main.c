#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "../include/ghook.h"

/* ================= GLOBALS ================= */
pthread_t g_thread;
void *__main_thread(void *a);

/* ================= ORIGINAL ADDRS  ================= */
typedef ssize_t (*sendto_sig)(int socket, const void *message, size_t length,
         int flags, const struct sockaddr *dest_addr,
         socklen_t dest_len);
uintptr_t o_sendto;
typedef int (*strcmp_sig)(const char*, const char*);
uintptr_t o_strcmp;
typedef int (*printf_sig)(const char *format, ...);
uintptr_t o_printf;

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
  ghook_logger_log(__func__, "str1: %s | str2: %s", str1, str2);

  strcmp_sig original_strcmp = (strcmp_sig)o_strcmp;
  return original_strcmp(str1, str2);
}

int printf_detour(const char *format, ...){
    va_list args;
    va_start(args, format);

    ghook_logger_log(__func__, "format: %s", format);

    printf_sig original_printf = (printf_sig)o_printf;

    int ret = vprintf(format, args);

    va_end(args);
    return ret;
}

ssize_t sendto_detour(int socket, const void *message, size_t length,
         int flags, const struct sockaddr *dest_addr,
         socklen_t dest_len){
  
  ghook_logger_log(__func__, "[sniffed] socket: %d | message: %s", socket, message);
  sendto_sig original_sendto = (sendto_sig)o_sendto;
  return original_sendto(socket, message, length, flags, dest_addr, dest_len);
}

void* __main_thread(void *a __attribute__((unused))){
  /* entry point */
  
  maps_container_t maps_container = {0};

  if(!ghook_get_maps(&maps_container)){
    ghook_logger_fatal(__func__, "unable to parse mappings");
    return NULL;
  }

  elf_data_t elf_data = {0};
  if(!ghook_get_elf_data(maps_container.maps[0].pathname, &elf_data)){
    ghook_logger_fatal(__func__, "unable to get elf data");
    return NULL;
  }
  
  ghook_got_hook(&elf_data, &maps_container, "strcmp", (uintptr_t)strcmp_detour, &o_strcmp);
  ghook_got_hook(&elf_data, &maps_container, "printf", (uintptr_t)printf_detour, &o_printf);
  ghook_got_hook(&elf_data, &maps_container, "sendto", (uintptr_t)sendto_detour, &o_sendto);

  ghook_free_elf(&elf_data);
  ghook_free_maps(&maps_container);
  return NULL;
}

__attribute__((destructor)) void __library_shutdown(){}
