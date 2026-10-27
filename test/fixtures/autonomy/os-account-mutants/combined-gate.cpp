// Controlled mutant family: combined-gate.
// Two permission checks are combined with && on one line. The bounded recognizer does
// not guess combined semantics and must register combined-gate-unsupported.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(callingTokenId, PERMISSION_MANAGE_USER_IDM) && !CheckPermission(callingTokenId, PERMISSION_USE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
