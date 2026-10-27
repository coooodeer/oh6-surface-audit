// Controlled mutant family: weakened-use-idm.
// The documented contract for OpenSession is MANAGE_USER_IDM, but the implementation
// checks the sibling USE_USER_IDM permission. A subject that holds only MANAGE_USER_IDM
// is rejected by the actual gate; the deviation itself is contract-level, not a finding.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(PERMISSION_USE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
