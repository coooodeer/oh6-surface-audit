// Controlled mutant family: compliant-manage-idm.
// The entry checks the documented MANAGE_USER_IDM permission through the service's
// local CheckPermission helper (one-hop delegation to AccountPermissionManager::VerifyPermission)
// and returns before the InnerAccountIAMManager operation.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(PERMISSION_MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
