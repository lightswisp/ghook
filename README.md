# ghook
GHook is a lightweight ELF hooking engine that intercepts dynamically linked function calls by modifying Global Offset Table (GOT) entries. It provides a stable, non-intrusive method for redirecting execution flow without the need for complex instruction-level patching.
## Detailed description
<img width="532" height="380" alt="image" src="https://github.com/user-attachments/assets/7523929e-21aa-466f-a1c2-00e6fa17e70d" />
<hr>
The diagram above illustrates the standard flow of dynamic address resolution, commonly referred to as lazy binding. In this model, the absolute address of a shared library function is resolved by the dynamic linker only upon its first invocation (unless eager binding is explicitly enabled).

GHook intercepts this mechanism by replacing the function pointer within the Global Offset Table (GOT) at a specific offset. Once the hook is active, the execution flow changes as follows:

The Call (1): The application initiates a call to a library function.

The PLT Stub (2): Control is passed to the Procedure Linkage Table (PLT) stub, which acts as a trampoline.

The Redirection (3): The stub performs an indirect jump to the address stored in the GOT. Because GHook has overwritten this entry, the program jumps to your custom hook function instead of the original library code.

## Pros & Cons
<table>
  <thead>
    <tr>
      <th align="left">Pros</th>
      <th align="left">Cons</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Stability & Architectural Independence:</strong> Since we modify pointers in a table rather than patching machine code, there is no need to handle varying instruction sets, opcode lengths, or complex CPU-specific edge cases.</td>
      <td><strong>Limited Scope:</strong> Only works for dynamically linked functions via the PLT. Cannot hook static or internal functions.</td>
    </tr>
    <tr>
      <td><strong>Simple Implementation:</strong> Operates via a basic pointer swap. No need for a complex disassembler engine or trampoline logic.</td>
        <td><strong>Page protection:</strong> Requires <code>mprotect</code> to bypass RELRO (Read-Only Relocations)</td>
    </tr>
  </tbody>
</table>

## How to use
### Clone the repository and build a static library:
```bash
git clone https://github.com/lightswisp/ghook
cd ghook
mkdir build && cd build
cmake .. && make
```

### Integrating it to your own project:
You must initialize the memory mapping container and parse the ELF data of the target process.
#### Initialization
```c
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
```

#### Applying Hooks:
Use ghook_got_hook to redirect PLT entries. You will need the symbol name, your detour function address, and a pointer to store the original function address.
```c
ghook_got_hook(&elf_data, &maps_container, "strcmp", (uintptr_t)strcmp_detour, &o_strcmp);
ghook_got_hook(&elf_data, &maps_container, "printf", (uintptr_t)printf_detour, &o_printf);
ghook_got_hook(&elf_data, &maps_container, "sendto", (uintptr_t)sendto_detour, &o_sendto);
```
#### Dont forget to free at the end:
```c
ghook_free_elf(&elf_data);
ghook_free_maps(&maps_container);
```

#### Final step:
Create your own shared library project and link it against the libghook.a static library produced in the previous step. For a practical implementation refer to the provided source code in the examples/ directory.

## Demo

https://github.com/user-attachments/assets/20e859a6-a298-4cab-9fd3-f55112be2af5

## License 
ghook is distributed under the WTFPL license. See LICENSE file.
