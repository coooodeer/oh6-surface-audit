int32_t SandboxManagerService::SetPolicy()
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        LogDenied();
    }
    int32_t ret = 0;
    ret = PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, policyFlag, result, timestamp);
    return ret;
}
