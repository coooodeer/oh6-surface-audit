int32_t SandboxManagerService::UnSetPolicy()
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}
