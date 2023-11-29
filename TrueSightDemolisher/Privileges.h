#pragma once

//
// Windows process privilege
//
enum Pviliege {
	SeUnsolicitedInputPrivilege = 1 << 0,
	SeCreateTokenPrivilege = 1 << 2,
	SeAssignPrimaryTokenPrivilege = 1 << 3,
	SeLockMemoryPrivilege = 1 << 4,
	SeIncreaseQuotaPrivilege = 1 << 5,
	SeMachineAccountPrivilege = 1 << 6,
	SeTcbPrivilege = 1 << 7,
	SeSecurityPrivilege = 1 << 8,
	SeTakeOwnershipPrivilege = 1 << 9,
	SeLoadDriverPrivilege = 1 << 10,
	SeSystemProfilePrivilege = 1 << 11,
	SeSystemtimePrivilege = 1 << 12,
	SeProfileSingleProcessPrivilege = 1 << 13,
	SeIncreaseBasePriorityPrivilege = 1 << 14,
	SeCreatePagefilePrivilege = 1 << 15,
	SeCreatePermanentPrivilege = 1 << 16,
	SeBackupPrivilege = 1 << 17,
	SeRestorePrivilege = 1 << 18,
	SeShutdownPrivilege = 1 << 19,
	SeDebugPrivilege = 1 << 20,
	SeAuditPrivilege = 1 << 21,
	SeSystemEnvironmentPrivilege = 1 << 22,
	SeChangeNotifyPrivilege = 1 << 23,
	SeRemoteShutdownPrivilege = 1 << 24,
	SeUndockPrivilege = 1 << 25,
	SeSyncAgentPrivilege = 1 << 26,
	SeEnableDelegationPrivilege = 1 << 27,
	SeManageVolumePrivilege = 1 << 28,
	SeImpersonatePrivilege = 1 << 29,
	SeCreateGlobalPrivilege = 1 << 30,
	SeTrustedCredManAccessPrivilege = 1 << 31,
	SeRelabelPrivilege = 1 << 32,
	SeIncreaseWorkingSetPrivilege = 1 << 33,
	SeTimeZonePrivilege = 1 << 34,
	SeCreateSymbolicLinkPrivilege = 1 << 35,
	// new? is considered a sensitive privillege but not showing anywhere on ntoskrnl
	SeDelegateSessionUserImpersonatePrivilege = 1 << 36
};