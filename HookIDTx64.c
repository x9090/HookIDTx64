#include <ntifs.h>
#include <intrin.h>
#include "distorm3/include/distorm.h"

#pragma warning(disable: 4305)

#define MAX_CPUS		(32)
#define MAX_INSTR		(15)
#define _MAX_PATH		1024
#ifdef _X86_
// mov eax, cr4
#define CR4_TO_EAX		__asm _emit 0x0F \
						__asm _emit 0x20 \
						__asm _emit 0xE0

// mov cr4, eax
#define EAX_TO_CR4		__asm _emit 0x0F \
						__asm _emit 0x22 \
						__asm _emit 0xE0

// Set TSD
#define SET_TSD_EAX		__asm or	eax, 4

// Unset TSD
#define CLR_TSD_EAX		__asm and	eax, 0xFFFFFFFB

#define ENABLE_TSD		CR4_TO_EAX	\
						SET_TSD_EAX \
						EAX_TO_CR4

#define CLEAR_TSD		CR4_TO_EAX	\
						CLR_TSD_EAX \
						EAX_TO_CR4
#else
VOID FORCEINLINE enable_tsd() {
    //
    // Read the current value of CR4
    //
    unsigned long long cr4 = __readcr4();

    //
    // Set the TSD flag (bit 2) in CR4
    //
    cr4 |= (1ULL << 2);

    //
    // Write the modified value back to CR4
    //
    __writecr4(cr4);
    return;
}
VOID FORCEINLINE disable_tsd() {
    //
    // Read the current value of CR4
    //
    unsigned long long cr4 = __readcr4();

    //
    // Clear the TSD flag (bit 2) in CR4
    //
    cr4 &= ~(1ULL << 2);

    //
    // Write the modified value back to CR4
    //
    __writecr4(cr4);
    return;
}
#define ENABLE_TSD enable_tsd()
#define CLEAR_TSD disable_tsd()
#endif

//
// Data structure definitions
// 
#pragma pack(push)
#pragma pack(1)
#ifdef _AMD64_
typedef struct
{
    USHORT lowOffset;
    USHORT segSelector;
    USHORT flags;
    USHORT highOffset;
    ULONG hightOffsetExtended;
    ULONG reserved;
} IDT_ENTRY, * PIDT_ENTRY;
#else
typedef struct
{
    USHORT lowOffset;
    USHORT segSelector;
    USHORT flags;
    USHORT highOffset;
} IDT_ENTRY, * PIDT_ENTRY;
#endif
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _INTERRUPT_DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Unused0;
    PIDT_ENTRY InterruptDescriptorTable;
} INTERRUPT_DESCRIPTOR_TABLE_REGISTER, * PINTERRUPT_DESCRIPTOR_TABLE_REGISTER;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(push, 8)
// valid for all exceptions with an associated error code (see Intel manuals Vol.3A, 5.13)
// (see Intel combined manuals Vol.3A, 6.14)
#ifdef _X86_
typedef struct
{
    ULONG errorCode;
    ULONG eip;
    ULONG cs;
    ULONG eflags;
    ULONG esp;
    ULONG ss;
} STACK_WITHERR;
#else
typedef struct
{
    ULONG64 errorCode;
    ULONG64 rip;
    ULONG64 cs;
    ULONG64 rflags;
    ULONG64 rsp;
    ULONG64 ss;
} STACK_WITHERR;
#endif

#ifdef _X86_
typedef struct
{
    ULONG eip;
    ULONG cs;
    ULONG eflags;
    ULONG esp;
    ULONG ss;
} STACK_WOERR;
#else
typedef struct
{
    ULONG64 rip;
    ULONG64 cs;
    ULONG64 rflags;
    ULONG64 rsp;
    ULONG64 ss;
}STACK_WOERR;
;
#endif

// integer register context and segment selectors
typedef struct
{
#ifdef _X86_
    ULONG gs;
    ULONG fs;
    ULONG es;
    ULONG ds;
    ULONG edi;
    ULONG esi;
    ULONG ebp;
    //ULONG esp;
    ULONG ebx;
    ULONG edx;
    ULONG ecx;
    ULONG eax;
#else
    ULONG64 r15;
    ULONG64 r14;
    ULONG64 r13;
    ULONG64 r12;
    ULONG64 r11;
    ULONG64 r10;
    ULONG64 r9;
    ULONG64 r8;
    ULONG64 rdi;
    ULONG64 rsi;
    ULONG64 rbp;
    ULONG64 rdx;
    ULONG64 rcx;
    ULONG64 rbx;
    ULONG64 rax;
    ULONG64 rflags;
    ULONG fs;
#endif
} CTX_SEL;
#pragma pack(pop)

// represents the stack layout at interrupt handler entry after all registers and segment
// selectors have been saved
typedef struct
{
    CTX_SEL context;
    STACK_WITHERR origHandlerStack;
} STACK_WITHCTX, *PSTACK_WITHCTX;

typedef struct
{
    CTX_SEL context;
    STACK_WOERR origHandlerStack;
} STACK_WITHCTX_NOERR, *PSTACK_WITHCTX_NOERR;

// Define the read spinlock structure
typedef struct _READ_SPINLOCK {
    KSPIN_LOCK SpinLock;
    LONG ReadersCount;
} READ_SPINLOCK, * PREAD_SPINLOCK;


// 
// Function definitions
//
typedef NTSTATUS(NTAPI* _KeSetAffinityThread)(
    IN PKTHREAD Thread,
    IN KAFFINITY Affinity
    );

//
// Global variables
//
_KeSetAffinityThread KeSetAffinityThread;

UINT_PTR origHandlers[MAX_CPUS];
extern PVOID hookGPStub;
extern PVOID hookDVStub;
READ_SPINLOCK readSpinLock;

// Initialize the read spinlock
VOID InitializeReadSpinLock(PREAD_SPINLOCK ReadSpinLock) {
    KeInitializeSpinLock(&ReadSpinLock->SpinLock);
    ReadSpinLock->ReadersCount = 0;
}

// Acquire the read spinlock
VOID AcquireReadSpinLock(PREAD_SPINLOCK ReadSpinLock) {
    KIRQL irql;

    KeAcquireSpinLock(&ReadSpinLock->SpinLock, &irql);
    InterlockedIncrement(&ReadSpinLock->ReadersCount);
    KeReleaseSpinLock(&ReadSpinLock->SpinLock, irql);
}

// Release the read spinlock
VOID ReleaseReadSpinLock(PREAD_SPINLOCK ReadSpinLock) {
    InterlockedDecrement(&ReadSpinLock->ReadersCount);
}

// returns length of instruction if it has been identified as RDTSC
ULONG isRDTSC(PVOID address)
{
    __try
    {
        _DecodedInst instructions[MAX_INSTR];
        unsigned int instructionCount;
#ifdef _X86_
        _DecodeResult res = distorm_decode(0, (const unsigned char*)address, MAX_INSTR, Decode32Bits, instructions, MAX_INSTR, &instructionCount);
#else
        _DecodeResult res = distorm_decode(0, (const unsigned char*)address, MAX_INSTR, Decode64Bits, instructions, MAX_INSTR, &instructionCount);
#endif
        if (res)
        {
            return strcmp((const char*)instructions[0].mnemonic.p, "RDTSC") == 0 || strcmp((const char*)instructions[0].mnemonic.p, "RDTSCP") == 0 ? instructions[0].size : 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ASSERT(FALSE);
    }
    return 0;
}

// returns length of instruction if it has been identified as RDTSC
ULONG isDivision(PVOID address)
{
    __try
    {
        _DecodedInst instructions[MAX_INSTR];
        unsigned int instructionCount;
#ifdef _X86_
        _DecodeResult res = distorm_decode(0, (const unsigned char*)address, MAX_INSTR, Decode32Bits, instructions, MAX_INSTR, &instructionCount);
#else
        _DecodeResult res = distorm_decode(0, (const unsigned char*)address, MAX_INSTR, Decode64Bits, instructions, MAX_INSTR, &instructionCount);
#endif
        if (res)
        {
            return strcmp((const char*)instructions[0].mnemonic.p, "DIV") == 0 || strcmp((const char*)instructions[0].mnemonic.p, "IDIV") == 0  ? instructions[0].size : 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ASSERT(FALSE);
    }
    return 0;
}

VOID hookInterrupt(PVOID newHandler, ULONG number, PUINT_PTR oldHandler)
{
    INTERRUPT_DESCRIPTOR_TABLE_REGISTER idtRegister;
    PIDT_ENTRY idt = NULL;

    UNREFERENCED_PARAMETER(newHandler);

    __sidt((void*)&idtRegister);
    idt = idtRegister.InterruptDescriptorTable;

    //
    // Disable interrupt
    //
    _disable();

    //
    // Raise IRQL
    //
    KIRQL  oldIrql = KeRaiseIrqlToDpcLevel();

    //
    // Read the CR0 value
    //
    const ULONGLONG cr0 = __readcr0();

    //
    // Set the 16th bit (write-protection) to zero
    //
    __writecr0(cr0 & 0xfffeffffUL);

#ifdef _X86_
    UINT_PTR origHandler = (ULONG)(idt[number].highOffset) << 16 | idt[number].lowOffset;
    USHORT OffsetLow = (USHORT)newHandler;
    USHORT OffsetHigh = (USHORT)((UINT_PTR)newHandler >> 16);
    idt[number].lowOffset = OffsetLow;
    idt[number].highOffset = OffsetHigh;
#else
    UINT_PTR origHandler = (UINT_PTR)((UINT_PTR)idt[number].hightOffsetExtended << 32 | (UINT_PTR)idt[number].highOffset << 16 | (UINT_PTR)idt[number].lowOffset);
    USHORT OffsetLow = (USHORT)newHandler & 0xFFFF;
    USHORT OffsetMiddle = (USHORT)((UINT_PTR)newHandler >> 16);
    ULONG OffsetHigh = (ULONG)((UINT_PTR)newHandler >> 32);
    idt[number].lowOffset = OffsetLow;
    idt[number].highOffset = OffsetMiddle;
    idt[number].hightOffsetExtended = OffsetHigh;
#endif
    if (oldHandler) *oldHandler = origHandler;

    //
    // Restore the processor state
    //
    __writecr0(cr0);

    //
    // Enable interrupt
    //
    _enable();

    //
    // Restore IRQL
    // 
    KeLowerIrql(oldIrql);
}

VOID switchToCPU(CCHAR cpu)
{
    KeSetAffinityThread(KeGetCurrentThread(), 1ULL << cpu);
}

BOOLEAN __stdcall hookDivideErrorImpl(STACK_WITHCTX_NOERR stackLayout)
{
    UINT_PTR ip = 0;
    ULONG length = 0;
#ifdef _X86_
    ip = stackLayout->origHandlerStack.eip;
#else
    ip = stackLayout.origHandlerStack.rip;
#endif
    DbgPrint("[%s] Caller RIP: 0x%llx\n", __FUNCTION__, ip);

    length = isDivision((PVOID)ip);
    if (length)
    {
        ip += length;
#ifdef _X86_
        stackLayout.origHandlerStack.eip = ip;
#else
        stackLayout.origHandlerStack.rip = ip;
#endif
        return TRUE; // Handled the interrupt
    }

    return FALSE;
}

NTSTATUS DriverEntry(__in PDRIVER_OBJECT  pDriverObject, __in PUNICODE_STRING  pRegistryPath)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    UNICODE_STRING ustrKeSetAffinityThread;

    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);
    KdPrint(("%s: DriverEntry\n", __FUNCTION__));

    RtlInitUnicodeString(&ustrKeSetAffinityThread, L"KeSetAffinityThread");
    KeSetAffinityThread = (_KeSetAffinityThread)MmGetSystemRoutineAddress(&ustrKeSetAffinityThread);

    InitializeReadSpinLock(&readSpinLock);

    __try 
    {
        // Enable "timestamp disable" flag at CR4 ->
        // Call RDTSC from UM -> raised #GP (general protection fault) exception ->
        // IDT handler@#13 will be triggered ->
        // Call our replaced IDT handler -> *END*
        // load CR4 register into EAX, set TSD flag and update CR4 from EAX
        for (CCHAR i = 0; i < KeNumberProcessors; ++i)
        {
            switchToCPU(i);
            hookInterrupt(hookDVStub, 0, &origHandlers[i]);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ASSERT(FALSE);
    }

    return NtStatus;
}