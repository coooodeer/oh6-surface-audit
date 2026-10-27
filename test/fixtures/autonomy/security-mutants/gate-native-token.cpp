int32_t SandboxManagerService::UnSetPolicy()
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!IsFileManagerCalling(callingTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d)", callingTokenId);
        return PERMISSION_DENIED;
    }
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}
