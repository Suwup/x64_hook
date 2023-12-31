/*
  MIT License

  Copyright (c) 2023 Suwup

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
 */

#ifndef X64_HOOK_H
#define X64_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

#define X64_HOOK_VERSION 2

#ifndef WIN32_MEAN_AND_LEAN
#define WIN32_MEAN_AND_LEAN
#endif

#ifndef BDDISASM_NO_FORMAT
#define BDDISASM_NO_FORMAT
#endif

#pragma warning(push, 0)
#include <windows.h>
#include <tlhelp32.h>
#include <bddisasm/bddisasm.h>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 4100) // Unreferenced parameter.
#pragma warning(disable: 4189) // Unreferenced variable.
#pragma warning(disable: 4820) // Padding in struct.
#pragma warning(disable: 4711) // Automatic inline expansion.
#pragma warning(disable: 5045) // Compiler will insert Spectre mitigation.
#pragma warning(disable: 5220) // Cpp move garbage with volatile.

#ifndef X64_HOOK_MAX_HOOKS
#define X64_HOOK_MAX_HOOKS 32
#endif

#ifndef X64_HOOK_ASSERT
#define X64_HOOK_ASSERT(x) ((void)(x))
#endif

#define X64_HOOK_MIN_SIGNED(x) (-(1ll << ((INT64)(x) - 1)) - 0)
#define X64_HOOK_MAX_SIGNED(x) (+(1ll << ((INT64)(x) - 1)) - 1)

typedef struct {
    volatile UINT64 ticket;
    volatile UINT64 serving;
} x64_Hook_Ticket_Mutex;

typedef struct {
    UINT8 *stolen_bytes;
    UINT32 num_stolen_bytes;

    UINT8 *dummy_trampoline;
    UINT8 **trampoline;
    UINT8 *original;
    UINT8 *hook;
    UINT8 *relay;
} x64_Hook;

typedef struct {
    x64_Hook hooks[X64_HOOK_MAX_HOOKS];
    volatile INT32 num_hooks;

    x64_Hook_Ticket_Mutex mutex;
    UINT32 installed;
} x64_Hook_Handle;

#pragma pack(push,1)

typedef struct {
    UINT8 operand_1;
    UINT8 operand_2;
    
    UINT32 rel32;
    UINT64 next;
} Jump_Absolute;

typedef struct {
    UINT8 operand;
    UINT32 rel32;
} Jump_Relative;

#pragma pack(pop)

//
// User api's, you should only call these unless you really know what you are doing.
// You may enumerate over the "hooks" found in x64_Hook_Handle with "num_hooks",
// however in that case you NEED to make sure not to add or install/uninstall
// anything while doing this or you will run into thread-safety issues.
//

static x64_Hook_Handle *x64_hook_allocate(void);
static UINT8 x64_hook_free(x64_Hook_Handle *handle);

// There is no _remove on purpose, just allocate another handle in that case.
static UINT8 x64_hook_add(x64_Hook_Handle *handle, void *in_original, void *in_hook, void **in_trampoline);

static void x64_hook_install(x64_Hook_Handle *handle);
static void x64_hook_uninstall(x64_Hook_Handle *handle);

//
// Internal api's, mainly meant to be used in a specific context by the user api's,
// however you may use them for other things, if you know what you are doing.
//

static void x64_hook_place_jump_absolute(UINT8 *src, UINT8 *dst);
static UINT8 x64_hook_place_jump_relative(UINT8 *src, UINT8 *dst);

static void x64_hook_protect(UINT8 *address, UINT64 size, volatile UINT32 *old_protection);

// Feel free to use these for general synchronization,
// where a lock-free queue is not really possible.

static void x64_hook_begin_ticket_mutex(x64_Hook_Ticket_Mutex *mutex);
static void x64_hook_end_ticket_mutex(x64_Hook_Ticket_Mutex *mutex);

static void x64_hook_relocate_relative(UINT8 *src, UINT8 *dst, UINT32 offset, UINT8 length);
static void x64_hook_maybe_relocate_thread_instruction_pointer(x64_Hook_Handle *handle, HANDLE thread);
static UINT8 *x64_hook_allocate_executable_within_32_bit_address_space(UINT8 *address, UINT64 size);
static void x64_hook_suspend_or_resume_all_other_threads(x64_Hook_Handle *handle, UINT8 suspend);

#ifdef X64_HOOK_IMPLEMENTATION

static
x64_Hook_Handle *x64_hook_allocate(void) {
    x64_Hook_Handle *handle = (x64_Hook_Handle *)VirtualAlloc(NULL, sizeof(x64_Hook_Handle), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    X64_HOOK_ASSERT(handle);
    return handle;
}

static
UINT8 x64_hook_free(x64_Hook_Handle *handle) {
    X64_HOOK_ASSERT(handle);

    UINT8 result = 0;
    x64_hook_begin_ticket_mutex(&handle->mutex);
    
    if (!handle->installed) {
        for (INT32 i = 0; i < handle->num_hooks; i++) {
            x64_Hook *hook = handle->hooks + i;
            VirtualFree(hook->stolen_bytes, 0, MEM_RELEASE);
            VirtualFree(hook->relay, 0, MEM_RELEASE);
            VirtualFree(*hook->trampoline, 0, MEM_RELEASE);
        }
    
        VirtualFree(handle, 0, MEM_RELEASE);
        result = 1;
    } else {
        x64_hook_end_ticket_mutex(&handle->mutex);
    }

    return result;
}

// It's not safe to uninstall while adding on another thread, don't do that, that's just retarded.
static
UINT8 x64_hook_add(x64_Hook_Handle *handle, void *in_original, void *in_hook, void **in_trampoline) {
    UINT8 result = 0;
    
    if (!handle->installed) {
        INT32 index = InterlockedIncrement((volatile LONG *)&handle->num_hooks) - 1;
        X64_HOOK_ASSERT(index < X64_HOOK_MAX_HOOKS);

        x64_Hook *hook   = handle->hooks + index;
        hook->original   = (UINT8 *)in_original;
        hook->hook       = (UINT8 *)in_hook;
        hook->trampoline = (UINT8 **)in_trampoline;
        hook->relay      = x64_hook_allocate_executable_within_32_bit_address_space(hook->original, sizeof(Jump_Absolute));

        // We always need to have a trampoline, for threading reasons.
        if (!hook->trampoline) {
            hook->trampoline = &hook->dummy_trampoline;
        }
    
        X64_HOOK_ASSERT(hook->original);
        X64_HOOK_ASSERT(hook->hook);
        X64_HOOK_ASSERT(hook->relay);

        x64_hook_place_jump_absolute(hook->relay, hook->hook);

        INSTRUX instruction;
        hook->num_stolen_bytes = 0; 
        while (hook->num_stolen_bytes < sizeof(Jump_Relative)) {
            NDSTATUS status = NdDecode(&instruction, hook->original + hook->num_stolen_bytes, ND_CODE_64, ND_DATA_64);
            X64_HOOK_ASSERT(ND_SUCCESS(status));
            hook->num_stolen_bytes += instruction.Length;
        }

        hook->stolen_bytes = (UINT8 *)VirtualAlloc(NULL, hook->num_stolen_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(hook->stolen_bytes, hook->original, hook->num_stolen_bytes);

        *hook->trampoline = x64_hook_allocate_executable_within_32_bit_address_space(hook->original, hook->num_stolen_bytes + sizeof(Jump_Absolute));
        memcpy(*hook->trampoline, hook->stolen_bytes, hook->num_stolen_bytes);

        UINT32 count = 0;
        while (count < hook->num_stolen_bytes) {
            NDSTATUS status = NdDecode(&instruction, *hook->trampoline + count, ND_CODE_64, ND_DATA_64);
            X64_HOOK_ASSERT(ND_SUCCESS(status));

            if (instruction.IsRipRelative) {
                X64_HOOK_ASSERT(instruction.HasDisp || instruction.HasRelOffs);

                if (instruction.HasDisp) {
                    x64_hook_relocate_relative(hook->original, *hook->trampoline, count + instruction.DispOffset, instruction.DispLength);
                }

                if (instruction.HasRelOffs) {
                    x64_hook_relocate_relative(hook->original, *hook->trampoline, count + instruction.RelOffsOffset, instruction.RelOffsLength);
                }
            }

            count += instruction.Length;
        }

        x64_hook_place_jump_absolute(*hook->trampoline + count, hook->original + count);
        result = 1;
    }

    return result;
}

static
void x64_hook_install(x64_Hook_Handle *handle) {
    x64_hook_begin_ticket_mutex(&handle->mutex);
    
    if (!handle->installed) {
        x64_hook_suspend_or_resume_all_other_threads(handle, 1);
        
        for (INT32 i = 0; i < handle->num_hooks; i++) {
            x64_Hook *hook = handle->hooks + i;
            
            UINT32 old_protection = 0;
            x64_hook_protect(hook->original, sizeof(Jump_Relative), &old_protection);
            x64_hook_place_jump_relative(hook->original, hook->relay);
            x64_hook_protect(hook->original, sizeof(Jump_Relative), &old_protection);
            
            // Since we modify the code in memory, the CPU cannot detect the change, and may execute the old code it cached.
            FlushInstructionCache(GetCurrentProcess(), hook->original, sizeof(Jump_Relative));
        }
        
        x64_hook_suspend_or_resume_all_other_threads(handle, 0);
        handle->installed = 1;
    }
    
    x64_hook_end_ticket_mutex(&handle->mutex);
}

static
void x64_hook_uninstall(x64_Hook_Handle *handle) {
    x64_hook_begin_ticket_mutex(&handle->mutex);
    
    if (handle->installed) {
        x64_hook_suspend_or_resume_all_other_threads(handle, 1);
        
        for (INT32 i = 0; i < handle->num_hooks; i++) {
            x64_Hook *hook = handle->hooks + i;
            
            UINT32 old_protection = 0;
            x64_hook_protect(hook->original, sizeof(Jump_Relative), &old_protection);
            memcpy(hook->original, hook->stolen_bytes, hook->num_stolen_bytes);
            x64_hook_protect(hook->original, sizeof(Jump_Relative), &old_protection);
            
            // In the case that we are still in a hook,
            // set the trampoline to the original,
            // so that we won't crash on calling it.
            *hook->trampoline = hook->original;
            
            // Since we modify the code in memory, the CPU cannot detect the change, and may execute the old code it cached.
            FlushInstructionCache(GetCurrentProcess(), hook->original, sizeof(Jump_Relative));
        }
        
        x64_hook_suspend_or_resume_all_other_threads(handle, 0);
        handle->installed = 0;
    }

    x64_hook_end_ticket_mutex(&handle->mutex);
}

static
void x64_hook_place_jump_absolute(UINT8 *src, UINT8 *dst) {
    Jump_Absolute *jump = (Jump_Absolute *)src;
    jump->operand_1 = 0xFF;
    jump->operand_2 = 0x25;
    jump->rel32 = 0; // jmp [rip+rel32] - jump to whatever is in rip, which is jump->next.
    jump->next = (UINT64)dst;
}

static
UINT8 x64_hook_place_jump_relative(UINT8 *src, UINT8 *dst) {
    UINT8 result = 0;
    
    INT64 rel = (INT64)(dst - src);
    if (rel <= INT_MAX && rel >= INT_MIN) {
        Jump_Relative *jump = (Jump_Relative *)src;
        jump->operand = 0xE9;
        jump->rel32 = (INT32)rel - sizeof(Jump_Relative);
        result = 1;
    }

    return result;
}

static
void x64_hook_protect(UINT8 *address, UINT64 size, volatile UINT32 *old_protection) {
    // We need to set the PAGE_EXECUTE_READWRITE protection or we will get an DEP fault in optimized builds.
    UINT8 ok = VirtualProtect(address, size, *old_protection ? *old_protection : PAGE_EXECUTE_READWRITE, (DWORD *)old_protection) != 0;
    X64_HOOK_ASSERT(ok);
}
    
static
void x64_hook_begin_ticket_mutex(x64_Hook_Ticket_Mutex *mutex) {
    UINT64 ticket = (UINT64)InterlockedIncrement64((volatile LONG64 *)&mutex->ticket) - 1;
    while (ticket != mutex->serving) {_mm_pause();}
}

static
void x64_hook_end_ticket_mutex(x64_Hook_Ticket_Mutex *mutex) {
    InterlockedIncrement64((volatile LONG64 *)&mutex->serving);
}

#define X64_HOOK_ASSERT_SIGNED_INTEGER_ADD(dst, src, width) \
    {                                                                   \
        X64_HOOK_ASSERT(*(INT##width  *)dst + (INT##width)src <= X64_HOOK_MAX_SIGNED(width) && \
                        *(INT##width  *)dst + (INT##width)src >= X64_HOOK_MIN_SIGNED(width)); \
        *(INT##width  *)dst += (INT##width)src;                         \
    }

static
void x64_hook_relocate_relative(UINT8 *src, UINT8 *dst, UINT32 offset, UINT8 length) {
    void *rel_address = (void *)(dst + offset);
    INT64 adjustment = src - dst;

    switch (length) {
    case 1: X64_HOOK_ASSERT_SIGNED_INTEGER_ADD(rel_address, adjustment, 8);  break;
    case 2: X64_HOOK_ASSERT_SIGNED_INTEGER_ADD(rel_address, adjustment, 16); break;
    case 4: X64_HOOK_ASSERT_SIGNED_INTEGER_ADD(rel_address, adjustment, 32); break;
    }
}

// This is a very specific macro, not needed anywhere else...
#undef X64_HOOK_ASSERT_SIGNED_INTEGER_ADD

static
void x64_hook_maybe_relocate_thread_instruction_pointer(x64_Hook_Handle *handle, HANDLE thread) {
    if (handle) {
        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;
    
        BOOL ok = GetThreadContext(thread, &context);
        X64_HOOK_ASSERT(ok);

        UINT8 *old_instruction_pointer = (UINT8 *)context.Rip;
        UINT8 *new_instruction_pointer = NULL;
    
        for (INT32 i = 0; i < handle->num_hooks; i++) {
            x64_Hook *hook = handle->hooks + i;
            if (hook->original <= old_instruction_pointer && old_instruction_pointer < hook->original + hook->num_stolen_bytes) {
                new_instruction_pointer = *hook->trampoline + (old_instruction_pointer - hook->original);
                break;
            }

            if (hook->relay == old_instruction_pointer) {
                new_instruction_pointer = hook->original;
                break;
            }

            // Less than or equal since we might be at the jump instruction, after the stolen bytes.
            if (*hook->trampoline <= old_instruction_pointer && old_instruction_pointer <= *hook->trampoline + hook->num_stolen_bytes) {
                new_instruction_pointer = hook->original + (old_instruction_pointer - *hook->trampoline);
                break;
            }
        }

        if (new_instruction_pointer) {
            context.Rip = (UINT64)new_instruction_pointer;
            ok = SetThreadContext(thread, &context);
            X64_HOOK_ASSERT(ok);
        }
    }
}

static
UINT8 *x64_hook_allocate_executable_within_32_bit_address_space(UINT8 *address, UINT64 size) {
    if (!address || !size) return NULL;
    
    SYSTEM_INFO info;
    GetSystemInfo(&info);

    // Round down to allocation granularity, like VirtualAlloc will do, so we query the correct pages.
    UINT64 allocation_granularity = info.dwAllocationGranularity;
    UINT64 aligned_origin = (UINT64)address & ~(allocation_granularity-1);

    UINT64 address_range = 4ull * 1024ull * 1024ull * 1024ull;

    // Ignore first slot, since it's most likely taken & skip last
    // slot on both sides since it could be out of reach for us.

    for (UINT64 i = 2; i < (address_range / allocation_granularity) - 1; i++) {
        UINT64 relative = (i/2) * allocation_granularity;
        
        void *address_to_try;
        if (i % 2) address_to_try = (void *)(aligned_origin + relative);
        else address_to_try = (void *)(aligned_origin - relative);
        
        UINT8 *result = (UINT8 *)VirtualAlloc(address_to_try, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result) return result;
    }
    
    return NULL;
}

static
void x64_hook_suspend_or_resume_all_other_threads(x64_Hook_Handle *handle, UINT8 suspend) {
    HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    X64_HOOK_ASSERT(thread_snapshot != INVALID_HANDLE_VALUE);

    THREADENTRY32 thread_entry = {sizeof(thread_entry)};
    BOOL ok = Thread32First(thread_snapshot, &thread_entry);
    X64_HOOK_ASSERT(ok);
    
    UINT32 current_proccess_id = GetCurrentProcessId();
    UINT32 current_thread_id   = GetCurrentThreadId();

    do {
        if (thread_entry.th32OwnerProcessID == current_proccess_id &&
            thread_entry.th32ThreadID       != current_thread_id) {
            DWORD access = THREAD_SUSPEND_RESUME;
            if (suspend) access |= THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
            
            HANDLE thread = OpenThread(access, 0, thread_entry.th32ThreadID);
            if (thread) {
                if (suspend) {
                    if (SuspendThread(thread) != 0xFFFFFFFF) {
                        x64_hook_maybe_relocate_thread_instruction_pointer(handle, thread);
                    } 
                } else {
                    ResumeThread(thread);
                }

                CloseHandle(thread);
            }
        }
    } while (Thread32Next(thread_snapshot, &thread_entry));

    CloseHandle(thread_snapshot);
}

// We need to implement this for bddisasm.
EXTERN_C void* nd_memset(void *s, int c, size_t n) {
    return memset(s, c, n);
}
    
#endif // X64_HOOK_IMPLEMENTATION

#pragma warning(pop)

#ifdef __cplusplus
}
#endif

#endif // X64_HOOK_H
