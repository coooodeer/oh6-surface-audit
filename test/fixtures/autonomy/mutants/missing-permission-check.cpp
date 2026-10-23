int32_t SandboxManagerService::SetPolicy()
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = 0;
    ret = PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, policyFlag, result, timestamp);
    return ret;
}
