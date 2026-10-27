// Controlled mutant family: non-early-return.
// The permission check exists but the failure branch only logs and falls through
// to the operation. The gate is recognized as non-blocking, not as a complete denial.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        ACCOUNT_LOGE("permission check failed");
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
