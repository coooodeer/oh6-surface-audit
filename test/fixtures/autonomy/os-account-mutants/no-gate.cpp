// Controlled mutant family: no-gate.
// No caller permission check at all before the operation. The expected policy is
// documented (Builder-mapped) but the permission is ACL-enabled, so the security
// proposition is capped at candidate rather than promoted to a finding.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
