#pragma once

#pragma once
#include <unordered_map>
std::unordered_map<const char*, int8_t> syscall_indices = {
	{ "NtAcceptConnectPort", 0x2 },
	{ "NtAccessCheck", 0x0 },
	{ "NtAccessCheckAndAuditAlarm", 0x29 },
	{ "NtAccessCheckByType", 0x63 },
	{ "NtAccessCheckByTypeAndAuditAlarm", 0x59 },
	{ "NtAccessCheckByTypeResultList", 0x64 },
	{ "NtAccessCheckByTypeResultListAndAuditAlarm", 0x65 },
	{ "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", 0x66 },
	{ "NtAcquireCrossVmMutant", 0x67 },
	{ "NtAcquireProcessActivityReference", 0x68 },
	{ "NtAddAtom", 0x47 },
	{ "NtAddAtomEx", 0x69 },
	{ "NtAddBootEntry", 0x6a },
	{ "NtAddDriverEntry", 0x6b },
	{ "NtAdjustGroupsToken", 0x6c },
	{ "NtAdjustPrivilegesToken", 0x41 },
	{ "NtAdjustTokenClaimsAndDeviceGroups", 0x6d },
	{ "NtAlertResumeThread", 0x6e },
	{ "NtAlertThread", 0x6f },
	{ "NtAlertThreadByThreadId", 0x70 },
	{ "NtAllocateLocallyUniqueId", 0x71 },
	{ "NtAllocateReserveObject", 0x72 },
	{ "NtAllocateUserPhysicalPages", 0x73 },
	{ "NtAllocateUserPhysicalPagesEx", 0x74 },
	{ "NtAllocateUuids", 0x75 },
	{ "NtAllocateVirtualMemory", 0x18 },
	{ "NtAllocateVirtualMemoryEx", 0x76 },
	{ "NtAlpcAcceptConnectPort", 0x77 },
	{ "NtAlpcCancelMessage", 0x78 },
	{ "NtAlpcConnectPort", 0x79 },
	{ "NtAlpcConnectPortEx", 0x7a },
	{ "NtAlpcCreatePort", 0x7b },
	{ "NtAlpcCreatePortSection", 0x7c },
	{ "NtAlpcCreateResourceReserve", 0x7d },
	{ "NtAlpcCreateSectionView", 0x7e },
	{ "NtAlpcCreateSecurityContext", 0x7f },
	{ "NtAlpcDeletePortSection", 0x80 },
	{ "NtAlpcDeleteResourceReserve", 0x81 },
	{ "NtAlpcDeleteSectionView", 0x82 },
	{ "NtAlpcDeleteSecurityContext", 0x83 },
	{ "NtAlpcDisconnectPort", 0x84 },
	{ "NtAlpcImpersonateClientContainerOfPort", 0x85 },
	{ "NtAlpcImpersonateClientOfPort", 0x86 },
	{ "NtAlpcOpenSenderProcess", 0x87 },
	{ "NtAlpcOpenSenderThread", 0x88 },
	{ "NtAlpcQueryInformation", 0x89 },
	{ "NtAlpcQueryInformationMessage", 0x8a },
	{ "NtAlpcRevokeSecurityContext", 0x8b },
	{ "NtAlpcSendWaitReceivePort", 0x8c },
	{ "NtAlpcSetInformation", 0x8d },
	{ "NtApphelpCacheControl", 0x4c },
	{ "NtAreMappedFilesTheSame", 0x8e },
	{ "NtAssignProcessToJobObject", 0x8f },
	{ "NtAssociateWaitCompletionPacket", 0x90 },
	{ "NtCallEnclave", 0x91 },
	{ "NtCallbackReturn", 0x5 },
	{ "NtCancelIoFile", 0x5d },
	{ "NtCancelIoFileEx", 0x92 },
	{ "NtCancelSynchronousIoFile", 0x93 },
	{ "NtCancelTimer", 0x61 },
	{ "NtCancelTimer2", 0x94 },
	{ "NtCancelWaitCompletionPacket", 0x95 },
	{ "NtClearEvent", 0x3e },
	{ "NtClose", 0xf },
	{ "NtCloseObjectAuditAlarm", 0x3b },
	{ "NtCommitComplete", 0x96 },
	{ "NtCommitEnlistment", 0x97 },
	{ "NtCommitRegistryTransaction", 0x98 },
	{ "NtCommitTransaction", 0x99 },
	{ "NtCompactKeys", 0x9a },
	{ "NtCompareObjects", 0x9b },
	{ "NtCompareSigningLevels", 0x9c },
	{ "NtCompareTokens", 0x9d },
	{ "NtCompleteConnectPort", 0x9e },
	{ "NtCompressKey", 0x9f },
	{ "NtConnectPort", 0xa0 },
	{ "NtContinue", 0x43 },
	{ "NtContinueEx", 0xa1 },
	{ "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", 0xa2 },
	{ "NtCreateCrossVmEvent", 0xa3 },
	{ "NtCreateCrossVmMutant", 0xa4 },
	{ "NtCreateDebugObject", 0xa5 },
	{ "NtCreateDirectoryObject", 0xa6 },
	{ "NtCreateDirectoryObjectEx", 0xa7 },
	{ "NtCreateEnclave", 0xa8 },
	{ "NtCreateEnlistment", 0xa9 },
	{ "NtCreateEvent", 0x48 },
	{ "NtCreateEventPair", 0xaa },
	{ "NtCreateFile", 0x55 },
	{ "NtCreateIRTimer", 0xab },
	{ "NtCreateIoCompletion", 0xac },
	{ "NtCreateJobObject", 0xad },
	{ "NtCreateJobSet", 0xae },
	{ "NtCreateKey", 0x1d },
	{ "NtCreateKeyTransacted", 0xaf },
	{ "NtCreateKeyedEvent", 0xb0 },
	{ "NtCreateLowBoxToken", 0xb1 },
	{ "NtCreateMailslotFile", 0xb2 },
	{ "NtCreateMutant", 0xb3 },
	{ "NtCreateNamedPipeFile", 0xb4 },
	{ "NtCreatePagingFile", 0xb5 },
	{ "NtCreatePartition", 0xb6 },
	{ "NtCreatePort", 0xb7 },
	{ "NtCreatePrivateNamespace", 0xb8 },
	{ "NtCreateProcess", 0xb9 },
	{ "NtCreateProcessEx", 0x4d },
	{ "NtCreateProfile", 0xba },
	{ "NtCreateProfileEx", 0xbb },
	{ "NtCreateRegistryTransaction", 0xbc },
	{ "NtCreateResourceManager", 0xbd },
	{ "NtCreateSection", 0x4a },
	{ "NtCreateSectionEx", 0xbe },
	{ "NtCreateSemaphore", 0xbf },
	{ "NtCreateSymbolicLinkObject", 0xc0 },
	{ "NtCreateThread", 0x4e },
	{ "NtCreateThreadEx", 0xc1 },
	{ "NtCreateTimer", 0xc2 },
	{ "NtCreateTimer2", 0xc3 },
	{ "NtCreateToken", 0xc4 },
	{ "NtCreateTokenEx", 0xc5 },
	{ "NtCreateTransaction", 0xc6 },
	{ "NtCreateTransactionManager", 0xc7 },
	{ "NtCreateUserProcess", 0xc8 },
	{ "NtCreateWaitCompletionPacket", 0xc9 },
	{ "NtCreateWaitablePort", 0xca },
	{ "NtCreateWnfStateName", 0xcb },
	{ "NtCreateWorkerFactory", 0xcc },
	{ "NtDebugActiveProcess", 0xcd },
	{ "NtDebugContinue", 0xce },
	{ "NtDelayExecution", 0x34 },
	{ "NtDeleteAtom", 0xcf },
	{ "NtDeleteBootEntry", 0xd0 },
	{ "NtDeleteDriverEntry", 0xd1 },
	{ "NtDeleteFile", 0xd2 },
	{ "NtDeleteKey", 0xd3 },
	{ "NtDeleteObjectAuditAlarm", 0xd4 },
	{ "NtDeletePrivateNamespace", 0xd5 },
	{ "NtDeleteValueKey", 0xd6 },
	{ "NtDeleteWnfStateData", 0xd7 },
	{ "NtDeleteWnfStateName", 0xd8 },
	{ "NtDeviceIoControlFile", 0x7 },
	{ "NtDirectGraphicsCall", 0xd9 },
	{ "NtDisableLastKnownGood", 0xda },
	{ "NtDisplayString", 0xdb },
	{ "NtDrawText", 0xdc },
	{ "NtDuplicateObject", 0x3c },
	{ "NtDuplicateToken", 0x42 },
	{ "NtEnableLastKnownGood", 0xdd },
	{ "NtEnumerateBootEntries", 0xde },
	{ "NtEnumerateDriverEntries", 0xdf },
	{ "NtEnumerateKey", 0x32 },
	{ "NtEnumerateSystemEnvironmentValuesEx", 0xe0 },
	{ "NtEnumerateTransactionObject", 0xe1 },
	{ "NtEnumerateValueKey", 0x13 },
	{ "NtExtendSection", 0xe2 },
	{ "NtFilterBootOption", 0xe3 },
	{ "NtFilterToken", 0xe4 },
	{ "NtFilterTokenEx", 0xe5 },
	{ "NtFindAtom", 0x14 },
	{ "NtFlushBuffersFile", 0x4b },
	{ "NtFlushBuffersFileEx", 0xe6 },
	{ "NtFlushInstallUILanguage", 0xe7 },
	{ "NtFlushInstructionCache", 0xe8 },
	{ "NtFlushKey", 0xe9 },
	{ "NtFlushProcessWriteBuffers", 0xea },
	{ "NtFlushVirtualMemory", 0xeb },
	{ "NtFlushWriteBuffer", 0xec },
	{ "NtFreeUserPhysicalPages", 0xed },
	{ "NtFreeVirtualMemory", 0x1e },
	{ "NtFreezeRegistry", 0xee },
	{ "NtFreezeTransactions", 0xef },
	{ "NtFsControlFile", 0x39 },
	{ "NtGetCachedSigningLevel", 0xf0 },
	{ "NtGetCompleteWnfStateSubscription", 0xf1 },
	{ "NtGetContextThread", 0xf2 },
	{ "NtGetCurrentProcessorNumber", 0xf3 },
	{ "NtGetCurrentProcessorNumberEx", 0xf4 },
	{ "NtGetDevicePowerState", 0xf5 },
	{ "NtGetMUIRegistryInfo", 0xf6 },
	{ "NtGetNextProcess", 0xf7 },
	{ "NtGetNextThread", 0xf8 },
	{ "NtGetNlsSectionPtr", 0xf9 },
	{ "NtGetNotificationResourceManager", 0xfa },
	{ "NtGetWriteWatch", 0xfb },
	{ "NtImpersonateAnonymousToken", 0xfc },
	{ "NtImpersonateClientOfPort", 0x1f },
	{ "NtImpersonateThread", 0xfd },
	{ "NtInitializeEnclave", 0xfe },
	{ "NtInitializeNlsFiles", 0xff },
	{ "NtInitializeRegistry", 0x100 },
	{ "NtInitiatePowerAction", 0x101 },
	{ "NtIsProcessInJob", 0x4f },
	{ "NtIsSystemResumeAutomatic", 0x102 },
	{ "NtIsUILanguageComitted", 0x103 },
	{ "NtListenPort", 0x104 },
	{ "NtLoadDriver", 0x105 },
	{ "NtLoadEnclaveData", 0x106 },
	{ "NtLoadKey", 0x107 },
	{ "NtLoadKey2", 0x108 },
	{ "NtLoadKey3", 0x1d6 },
	{ "NtLoadKeyEx", 0x109 },
	{ "NtLockFile", 0x10a },
	{ "NtLockProductActivationKeys", 0x10b },
	{ "NtLockRegistryKey", 0x10c },
	{ "NtLockVirtualMemory", 0x10d },
	{ "NtMakePermanentObject", 0x10e },
	{ "NtMakeTemporaryObject", 0x10f },
	{ "NtManageHotPatch", 0x110 },
	{ "NtManagePartition", 0x111 },
	{ "NtMapCMFModule", 0x112 },
	{ "NtMapUserPhysicalPages", 0x113 },
	{ "NtMapUserPhysicalPagesScatter", 0x3 },
	{ "NtMapViewOfSection", 0x28 },
	{ "NtMapViewOfSectionEx", 0x114 },
	{ "NtModifyBootEntry", 0x115 },
	{ "NtModifyDriverEntry", 0x116 },
	{ "NtNotifyChangeDirectoryFile", 0x117 },
	{ "NtNotifyChangeDirectoryFileEx", 0x118 },
	{ "NtNotifyChangeKey", 0x119 },
	{ "NtNotifyChangeMultipleKeys", 0x11a },
	{ "NtNotifyChangeSession", 0x11b },
	{ "NtOpenDirectoryObject", 0x58 },
	{ "NtOpenEnlistment", 0x11c },
	{ "NtOpenEvent", 0x40 },
	{ "NtOpenEventPair", 0x11d },
	{ "NtOpenFile", 0x33 },
	{ "NtOpenIoCompletion", 0x11e },
	{ "NtOpenJobObject", 0x11f },
	{ "NtOpenKey", 0x12 },
	{ "NtOpenKeyEx", 0x120 },
	{ "NtOpenKeyTransacted", 0x121 },
	{ "NtOpenKeyTransactedEx", 0x122 },
	{ "NtOpenKeyedEvent", 0x123 },
	{ "NtOpenMutant", 0x124 },
	{ "NtOpenObjectAuditAlarm", 0x125 },
	{ "NtOpenPartition", 0x126 },
	{ "NtOpenPrivateNamespace", 0x127 },
	{ "NtOpenProcess", 0x26 },
	{ "NtOpenProcessToken", 0x128 },
	{ "NtOpenProcessTokenEx", 0x30 },
	{ "NtOpenRegistryTransaction", 0x129 },
	{ "NtOpenResourceManager", 0x12a },
	{ "NtOpenSection", 0x37 },
	{ "NtOpenSemaphore", 0x12b },
	{ "NtOpenSession", 0x12c },
	{ "NtOpenSymbolicLinkObject", 0x12d },
	{ "NtOpenThread", 0x12e },
	{ "NtOpenThreadToken", 0x24 },
	{ "NtOpenThreadTokenEx", 0x2f },
	{ "NtOpenTimer", 0x12f },
	{ "NtOpenTransaction", 0x130 },
	{ "NtOpenTransactionManager", 0x131 },
	{ "NtPlugPlayControl", 0x132 },
	{ "NtPowerInformation", 0x5f },
	{ "NtPrePrepareComplete", 0x133 },
	{ "NtPrePrepareEnlistment", 0x134 },
	{ "NtPrepareComplete", 0x135 },
	{ "NtPrepareEnlistment", 0x136 },
	{ "NtPrivilegeCheck", 0x137 },
	{ "NtPrivilegeObjectAuditAlarm", 0x138 },
	{ "NtPrivilegedServiceAuditAlarm", 0x139 },
	{ "NtPropagationComplete", 0x13a },
	{ "NtPropagationFailed", 0x13b },
	{ "NtProtectVirtualMemory", 0x50 },
	{ "NtPssCaptureVaSpaceBulk", 0x13c },
	{ "NtPulseEvent", 0x13d },
	{ "NtQueryAttributesFile", 0x3d },
	{ "NtQueryAuxiliaryCounterFrequency", 0x13e },
	{ "NtQueryBootEntryOrder", 0x13f },
	{ "NtQueryBootOptions", 0x140 },
	{ "NtQueryDebugFilterState", 0x141 },
	{ "NtQueryDefaultLocale", 0x15 },
	{ "NtQueryDefaultUILanguage", 0x44 },
	{ "NtQueryDirectoryFile", 0x35 },
	{ "NtQueryDirectoryFileEx", 0x142 },
	{ "NtQueryDirectoryObject", 0x143 },
	{ "NtQueryDriverEntryOrder", 0x144 },
	{ "NtQueryEaFile", 0x145 },
	{ "NtQueryEvent", 0x56 },
	{ "NtQueryFullAttributesFile", 0x146 },
	{ "NtQueryInformationAtom", 0x147 },
	{ "NtQueryInformationByName", 0x148 },
	{ "NtQueryInformationEnlistment", 0x149 },
	{ "NtQueryInformationFile", 0x11 },
	{ "NtQueryInformationJobObject", 0x14a },
	{ "NtQueryInformationPort", 0x14b },
	{ "NtQueryInformationProcess", 0x19 },
	{ "NtQueryInformationResourceManager", 0x14c },
	{ "NtQueryInformationThread", 0x25 },
	{ "NtQueryInformationToken", 0x21 },
	{ "NtQueryInformationTransaction", 0x14d },
	{ "NtQueryInformationTransactionManager", 0x14e },
	{ "NtQueryInformationWorkerFactory", 0x14f },
	{ "NtQueryInstallUILanguage", 0x150 },
	{ "NtQueryIntervalProfile", 0x151 },
	{ "NtQueryIoCompletion", 0x152 },
	{ "NtQueryKey", 0x16 },
	{ "NtQueryLicenseValue", 0x153 },
	{ "NtQueryMultipleValueKey", 0x154 },
	{ "NtQueryMutant", 0x155 },
	{ "NtQueryObject", 0x10 },
	{ "NtQueryOpenSubKeys", 0x156 },
	{ "NtQueryOpenSubKeysEx", 0x157 },
	{ "NtQueryPerformanceCounter", 0x31 },
	{ "NtQueryPortInformationProcess", 0x158 },
	{ "NtQueryQuotaInformationFile", 0x159 },
	{ "NtQuerySection", 0x51 },
	{ "NtQuerySecurityAttributesToken", 0x15a },
	{ "NtQuerySecurityObject", 0x15b },
	{ "NtQuerySecurityPolicy", 0x15c },
	{ "NtQuerySemaphore", 0x15d },
	{ "NtQuerySymbolicLinkObject", 0x15e },
	{ "NtQuerySystemEnvironmentValue", 0x15f },
	{ "NtQuerySystemEnvironmentValueEx", 0x160 },
	{ "NtQuerySystemInformation", 0x36 },
	{ "NtQuerySystemInformationEx", 0x161 },
	{ "NtQueryTimer", 0x38 },
	{ "NtQueryTimerResolution", 0x162 },
	{ "NtQueryValueKey", 0x17 },
	{ "NtQueryVirtualMemory", 0x23 },
	{ "NtQueryVolumeInformationFile", 0x49 },
	{ "NtQueryWnfStateData", 0x163 },
	{ "NtQueryWnfStateNameInformation", 0x164 },
	{ "NtQueueApcThread", 0x45 },
	{ "NtQueueApcThreadEx", 0x165 },
	{ "NtRaiseException", 0x166 },
	{ "NtRaiseHardError", 0x167 },
	{ "NtReadFile", 0x6 },
	{ "NtReadFileScatter", 0x2e },
	{ "NtReadOnlyEnlistment", 0x168 },
	{ "NtReadRequestData", 0x54 },
	{ "NtReadVirtualMemory", 0x3f },
	{ "NtRecoverEnlistment", 0x169 },
	{ "NtRecoverResourceManager", 0x16a },
	{ "NtRecoverTransactionManager", 0x16b },
	{ "NtRegisterProtocolAddressInformation", 0x16c },
	{ "NtRegisterThreadTerminatePort", 0x16d },
	{ "NtReleaseKeyedEvent", 0x16e },
	{ "NtReleaseMutant", 0x20 },
	{ "NtReleaseSemaphore", 0xa },
	{ "NtReleaseWorkerFactoryWorker", 0x16f },
	{ "NtRemoveIoCompletion", 0x9 },
	{ "NtRemoveIoCompletionEx", 0x170 },
	{ "NtRemoveProcessDebug", 0x171 },
	{ "NtRenameKey", 0x172 },
	{ "NtRenameTransactionManager", 0x173 },
	{ "NtReplaceKey", 0x174 },
	{ "NtReplacePartitionUnit", 0x175 },
	{ "NtReplyPort", 0xc },
	{ "NtReplyWaitReceivePort", 0xb },
	{ "NtReplyWaitReceivePortEx", 0x2b },
	{ "NtReplyWaitReplyPort", 0x176 },
	{ "NtRequestPort", 0x177 },
	{ "NtRequestWaitReplyPort", 0x22 },
	{ "NtResetEvent", 0x178 },
	{ "NtResetWriteWatch", 0x179 },
	{ "NtRestoreKey", 0x17a },
	{ "NtResumeProcess", 0x17b },
	{ "NtResumeThread", 0x52 },
	{ "NtRevertContainerImpersonation", 0x17c },
	{ "NtRollbackComplete", 0x17d },
	{ "NtRollbackEnlistment", 0x17e },
	{ "NtRollbackRegistryTransaction", 0x17f },
	{ "NtRollbackTransaction", 0x180 },
	{ "NtRollforwardTransactionManager", 0x181 },
	{ "NtSaveKey", 0x182 },
	{ "NtSaveKeyEx", 0x183 },
	{ "NtSaveMergedKeys", 0x184 },
	{ "NtSecureConnectPort", 0x185 },
	{ "NtSerializeBoot", 0x186 },
	{ "NtSetBootEntryOrder", 0x187 },
	{ "NtSetBootOptions", 0x188 },
	{ "NtSetCachedSigningLevel", 0x189 },
	{ "NtSetCachedSigningLevel2", 0x18a },
	{ "NtSetContextThread", 0x18b },
	{ "NtSetDebugFilterState", 0x18c },
	{ "NtSetDefaultHardErrorPort", 0x18d },
	{ "NtSetDefaultLocale", 0x18e },
	{ "NtSetDefaultUILanguage", 0x18f },
	{ "NtSetDriverEntryOrder", 0x190 },
	{ "NtSetEaFile", 0x191 },
	{ "NtSetEvent", 0xe },
	{ "NtSetEventBoostPriority", 0x2d },
	{ "NtSetHighEventPair", 0x192 },
	{ "NtSetHighWaitLowEventPair", 0x193 },
	{ "NtSetIRTimer", 0x194 },
	{ "NtSetInformationDebugObject", 0x195 },
	{ "NtSetInformationEnlistment", 0x196 },
	{ "NtSetInformationFile", 0x27 },
	{ "NtSetInformationJobObject", 0x197 },
	{ "NtSetInformationKey", 0x198 },
	{ "NtSetInformationObject", 0x5c },
	{ "NtSetInformationProcess", 0x1c },
	{ "NtSetInformationResourceManager", 0x199 },
	{ "NtSetInformationSymbolicLink", 0x19a },
	{ "NtSetInformationThread", 0xd },
	{ "NtSetInformationToken", 0x19b },
	{ "NtSetInformationTransaction", 0x19c },
	{ "NtSetInformationTransactionManager", 0x19d },
	{ "NtSetInformationVirtualMemory", 0x19e },
	{ "NtSetInformationWorkerFactory", 0x19f },
	{ "NtSetIntervalProfile", 0x1a0 },
	{ "NtSetIoCompletion", 0x1a1 },
	{ "NtSetIoCompletionEx", 0x1a2 },
	{ "NtSetLdtEntries", 0x1a3 },
	{ "NtSetLowEventPair", 0x1a4 },
	{ "NtSetLowWaitHighEventPair", 0x1a5 },
	{ "NtSetQuotaInformationFile", 0x1a6 },
	{ "NtSetSecurityObject", 0x1a7 },
	{ "NtSetSystemEnvironmentValue", 0x1a8 },
	{ "NtSetSystemEnvironmentValueEx", 0x1a9 },
	{ "NtSetSystemInformation", 0x1aa },
	{ "NtSetSystemPowerState", 0x1ab },
	{ "NtSetSystemTime", 0x1ac },
	{ "NtSetThreadExecutionState", 0x1ad },
	{ "NtSetTimer", 0x62 },
	{ "NtSetTimer2", 0x1ae },
	{ "NtSetTimerEx", 0x1af },
	{ "NtSetTimerResolution", 0x1b0 },
	{ "NtSetUuidSeed", 0x1b1 },
	{ "NtSetValueKey", 0x60 },
	{ "NtSetVolumeInformationFile", 0x1b2 },
	{ "NtSetWnfProcessNotificationEvent", 0x1b3 },
	{ "NtShutdownSystem", 0x1b4 },
	{ "NtShutdownWorkerFactory", 0x1b5 },
	{ "NtSignalAndWaitForSingleObject", 0x1b6 },
	{ "NtSinglePhaseReject", 0x1b7 },
	{ "NtStartProfile", 0x1b8 },
	{ "NtStopProfile", 0x1b9 },
	{ "NtSubscribeWnfStateChange", 0x1ba },
	{ "NtSuspendProcess", 0x1bb },
	{ "NtSuspendThread", 0x1bc },
	{ "NtSystemDebugControl", 0x1bd },
	{ "NtTerminateEnclave", 0x1be },
	{ "NtTerminateJobObject", 0x1bf },
	{ "NtTerminateProcess", 0x2c },
	{ "NtTerminateThread", 0x53 },
	{ "NtTestAlert", 0x1c0 },
	{ "NtThawRegistry", 0x1c1 },
	{ "NtThawTransactions", 0x1c2 },
	{ "NtTraceControl", 0x1c3 },
	{ "NtTraceEvent", 0x5e },
	{ "NtTranslateFilePath", 0x1c4 },
	{ "NtUmsThreadYield", 0x1c5 },
	{ "NtUnloadDriver", 0x1c6 },
	{ "NtUnloadKey", 0x1c7 },
	{ "NtUnloadKey2", 0x1c8 },
	{ "NtUnloadKeyEx", 0x1c9 },
	{ "NtUnlockFile", 0x1ca },
	{ "NtUnlockVirtualMemory", 0x1cb },
	{ "NtUnmapViewOfSection", 0x2a },
	{ "NtUnmapViewOfSectionEx", 0x1cc },
	{ "NtUnsubscribeWnfStateChange", 0x1cd },
	{ "NtUpdateWnfStateData", 0x1ce },
	{ "NtVdmControl", 0x1cf },
	{ "NtWaitForAlertByThreadId", 0x1d0 },
	{ "NtWaitForDebugEvent", 0x1d1 },
	{ "NtWaitForKeyedEvent", 0x1d2 },
	{ "NtWaitForMultipleObjects", 0x5b },
	{ "NtWaitForMultipleObjects32", 0x1a },
	{ "NtWaitForSingleObject", 0x4 },
	{ "NtWaitForWorkViaWorkerFactory", 0x1d3 },
	{ "NtWaitHighEventPair", 0x1d4 },
	{ "NtWaitLowEventPair", 0x1d5 },
	{ "NtWorkerFactoryWorkerReady", 0x1 },
	{ "NtWriteFile", 0x8 },
	{ "NtWriteFileGather", 0x1b },
	{ "NtWriteRequestData", 0x57 },
	{ "NtWriteVirtualMemory", 0x3a },
	{ "NtYieldExecution", 0x46 },
};