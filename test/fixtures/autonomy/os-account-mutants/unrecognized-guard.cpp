// Controlled mutant family: unrecognized-guard.
// The caller identity condition uses a helper outside the recognized gate vocabulary.
// The vocabulary miss must stay a named gap, not become "no gate" or "safe".
int32_t AccountIAMService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (!VerifyAuthorized(callingTokenId)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    InnerAccountIAMManager::GetInstance().OpenSession(userId, challenge);
    return ERR_OK;
}
