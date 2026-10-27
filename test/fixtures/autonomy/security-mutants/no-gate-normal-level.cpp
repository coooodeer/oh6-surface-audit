int32_t SandboxManagerService::UnSetPolicy()
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}
