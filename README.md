# TrueSightDemolisher
## What
Uses the Microsoft-signed truesight.sys to give you SeDebugPrivilege:)

## How
The driver is dumb.
```c
char WriteIoctl(ULONGLONG *UserControlled, unsigned int AlsoUserControlled, ULONGLONG UserControlledToo)
{
  ULONGLONG *v3; // rax

  if ( !UserControlled || AlsoUserControlled > 0x1D )
    return 0;
  if ( AlsoUserControlled == 28 ) // weird logic in those next few lines. still vuln tho
    v3 = UserControlled + 12;
  else
    v3 = AlsoUserControlled == 29 ? UserControlled + 13 : &UserControlled[AlsoUserControlled + 14];
  if ( !v3 )
    return 0;
  *v3 = UserControlledToo;
  return 1;
}
```
And don't forget
```c
NT_STATUS __fastcall MapMemory(PVOID VirtualAddress, ULONG OutputLength, PVOID OutputBuffer)
{
  status = STATUS_SUCCESS;
  if ( !VirtualAddress )
    return STATUS_INVALID_PARAMETER;
  if ( !MmIsAddressValid(VirtualAddress) )
    return STATUS_INVALID_PARAMETER;
  if ( !OutputBuffer )
    return STATUS_INVALID_PARAMETER;
  if ( !MmIsAddressValid(OutputBuffer) ) // at least you validate _something_
    return STATUS_INVALID_PARAMETER;
  Mdl = IoAllocateMdl(VirtualAddress, OutputLength, 0, 0, nullptr);
  if ( !Mdl )
    return STATUS_INVALID_PARAMETER;
  MmProbeAndLockPages(Mdl, 0, IoReadAccess);
  if ( (Mdl->MdlFlags & 5) != 0 )
    MappedSystemVa = Mdl->MappedSystemVa;
  else
    MappedSystemVa = MmMapLockedPagesSpecifyCache(
                       Mdl,
                       KernelMode,
                       MmCached,
                       nullptr,
                       0,
                       cMdlMappingNoExecute | NormalPagePriority);
  if ( MappedSystemVa )
    memcpy(OutputBuffer, MappedSystemVa, OutputLength);
  else
    status = STATUS_INVALID_PARAMETER;
  MmUnlockPages(Mdl);
  IoFreeMdl(Mdl);
  return status;
}
```
Among the other IOCTLs you'll find:
 - (0x22E048) Recursive enumeration of a registry key, just because you can
 - (0x22E018) The ability to get the stack trace of all the system threads, if you need another KASLR leak
 - (See [this awesome project](https://github.com/MaorSabag/TrueSightKiller)) Terminating _any_ process
 - (0x22E04C) Opening _any_ existing file and setting it to be deleted on close (which seems interesting🙃)
 - Possibly other things

## Caveats
Although the driver is clearly not written with security in mind, you still need to be in `BUILTIN\Administrators` to actually send IOCTLs to this thing.

## Thanks
A lot of thanks for Maor Sabag's [TrueSightKiller](https://github.com/MaorSabag/TrueSightKiller), for revealing this gem of a driver😊

## TODOs and Technical Details
Techincally, this is pretty standard - we use the R/W primitive to go over the process list, find our process and change our privileges to include `SeDebugPrivilege`.

Todo:
 - [ ] Dynamically find offsets of symbols and fields (e.g `EPROCESS->ActiveProcessLinks`, `EPROCESS->Token`) instead of hardcoding
