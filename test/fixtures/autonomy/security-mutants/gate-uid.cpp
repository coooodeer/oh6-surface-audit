int32_t SandboxManagerService::UnSetPolicy()
{
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        return PERMISSION_DENIED;
    }
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}
