// Controlled mutant family: subject-mismatch.
// The direct CheckPermission call checks the target user id rather than the caller
// token, so it does not constrain the calling subject.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(userId, PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
