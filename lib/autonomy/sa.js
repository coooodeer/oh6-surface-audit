'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256File } = require('../facts/ids');

// shortcut: only the CES 3299 profile -> published ICommonEvent stub shape is modeled; add a new recipe after a second real shape is proven.
function resolve(entry, cfg, row, texts, functions) {
  if (!row || row.sourceFile !== cfg.profileFile || row.payload?.saId !== 3299) {
    return { status: 'sa-profile-ambiguous' };
  }
  let profile;
  try { profile = JSON.parse(texts.profile); } catch (_) { return { status: 'sa-profile-invalid' }; }
  const abilities = profile.systemability;
  if (profile.process !== 'foundation' || !Array.isArray(abilities) || abilities.length !== 1 ||
      abilities[0].name !== 3299 || abilities[0].libpath !== 'libcesfwk_services.z.so' ||
      abilities[0]['run-on-create'] !== true || row.payload.library !== abilities[0].libpath) {
    return { status: 'sa-profile-mismatch' };
  }
  if (!texts.profileBuild.includes('ohos_sa_profile("event_sa_profile")') ||
      !texts.profileBuild.includes('sources = [ "3299.json" ]') ||
      !texts.definition.includes('COMMON_EVENT_SERVICE_ID                          = 3299,') ||
      !texts.macro.includes('SystemAbility::MakeAndRegisterAbility(new abilityClassName(systemAbilityId, runOnCreate))')) {
    return { status: 'sa-registration-unresolved' };
  }
  const registration = 'REGISTER_SYSTEM_ABILITY_BY_ID(CommonEventManagerServiceAbility, COMMON_EVENT_SERVICE_ID, true);';
  if (texts.ability.split(registration).length !== 2) return { status: 'sa-registration-ambiguous' };
  const start = texts.ability.split('void CommonEventManagerServiceAbility::OnStart()');
  if (start.length !== 2) return { status: 'sa-publish-unresolved' };
  const body = start[1].split('void CommonEventManagerServiceAbility::OnStop()')[0];
  const publishPath = /service_ = CommonEventManagerService::GetInstance\(\);\s*if \(service_ == nullptr\) \{\s*EVENT_LOGE\([^;]*;\s*return;\s*\}\s*ErrCode errorCode = service_->Init\(\);\s*if \(errorCode != ERR_OK\) \{\s*EVENT_LOGE\([^;]*;\s*return;\s*\}\s*if \(!Publish\(service_\)\) \{/;
  if (!publishPath.test(body) ||
      !texts.serviceHeader.includes('class CommonEventManagerService : public CommonEventStub') ||
      !/ErrCode RemoveStickyCommonEvent\(const std::string& event, int32_t& funcResult\) override;/.test(texts.serviceHeader)) {
    return { status: 'sa-publish-unresolved' };
  }
  if (!texts.serviceBuild.includes('ohos_shared_library("cesfwk_services")') ||
      !texts.serviceBuild.includes('src/common_event_manager_service_ability.cpp') ||
      !texts.serviceBuild.includes('src/common_event_manager_service.cpp') ||
      !texts.serviceBuild.includes('${ces_core_path}:cesfwk_core') ||
      !texts.coreBuild.includes('idl_gen_interface("common_event_interface")') ||
      !texts.coreBuild.includes('sources = [ "ICommonEvent.idl" ]') ||
      !texts.coreBuild.includes('ohos_source_set("common_event_stub")') ||
      !texts.coreBuild.includes('sources = filter_include(output_values, [ "*_stub.cpp" ])') ||
      !texts.coreBuild.includes('":common_event_stub"')) {
    return { status: 'sa-build-unresolved' };
  }
  const targets = functions.filter((fn) => fn.role === 'production' &&
    fn.qualified === 'OHOS::EventFwk::CommonEventManagerService::RemoveStickyCommonEvent' &&
    fn.sourceRange?.file === cfg.serviceFile && fn.quality?.errorNodes === 0);
  if (targets.length !== 1) return { status: 'sa-method-ambiguous', candidateCount: targets.length };
  return { status: 'resolved', profileRef: row.metadataId, serviceFactRef: targets[0].factId,
    registrationFile: cfg.abilityFile, registrationLine: texts.ability.slice(0, texts.ability.indexOf(registration)).split(/\r?\n/).length,
    publishLine: texts.ability.slice(0, texts.ability.indexOf('Publish(service_)')).split(/\r?\n/).length,
    methodLine: targets[0].startLine, buildVariant: 'CES GN standard shared library + generated IDL stub (declared, not built)' };
}

function bridgeOf(facts, entry, cfg, idx) {
  if (entry.kind !== 'idl' || entry.interface !== cfg.interface || entry.method !== cfg.method) return null;
  const rows = idx.metadata.sa.filter((row) => row.payload?.saId === cfg.saId && row.sourceFile === cfg.profileFile);
  if (rows.length !== 1) return { status: 'sa-profile-ambiguous', candidateCount: rows.length };
  const own = [cfg.abilityFile, cfg.serviceHeader];
  if (own.some((file) => !facts.verifyFile(file).ok) ||
      sha256File(path.join(facts.sourceRoot, ...cfg.profileFile.split('/'))) !== rows[0].sha256) {
    return { status: 'sa-source-stale' };
  }
  const texts = {};
  const files = { profile: cfg.profileFile, ability: cfg.abilityFile, serviceHeader: cfg.serviceHeader };
  for (const [key, pinned] of Object.entries(cfg.pinned)) {
    const abs = path.join(facts.sourceRoot, ...pinned.file.split('/'));
    if (!fs.existsSync(abs) || sha256File(abs) !== pinned.sha256) return { status: 'sa-dependency-stale', file: pinned.file };
    files[key] = pinned.file;
  }
  for (const [key, file] of Object.entries(files)) {
    texts[key] = fs.readFileSync(path.join(facts.sourceRoot, ...file.split('/')), 'utf8');
  }
  return resolve(entry, cfg, rows[0], texts, idx.functions);
}

module.exports = { resolve, bridgeOf };
