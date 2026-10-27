// Controlled mutant family: different-stronger.
// The documented contract is MANAGE_USER_IDM; the implementation requires the
// ACCESS_USER_AUTH_INTERNAL permission instead. A subject holding only the documented
// permission is rejected by the actual gate, so the security proposition is scoped-excluded.
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!CheckPermission(PERMISSION_ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
