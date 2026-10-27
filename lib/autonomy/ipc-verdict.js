'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256File } = require('../facts/ids');
const { dispatchOf } = require('./ipc-dispatch');

const compact = (text) => text.replace(/\s+/g, '');
const count = (text, fragment) => text.split(fragment).length - 1;
const contract = { status: 'not-applicable', family: 'not-applicable',
  reason: 'no-published-document-contract' };

function method(text, name) {
  const Parser = require('../../../oh6-framework-want-leak-miner/node_modules/tree-sitter');
  const Cpp = require('../../../oh6-framework-want-leak-miner/node_modules/tree-sitter-cpp');
  const parser = new Parser();
  parser.setLanguage(Cpp);
  const found = [];
  function visit(node) {
    if (node.type === 'function_definition' &&
        node.childForFieldName('declarator')?.text.startsWith(`${name}(`)) found.push(node);
    for (const child of node.namedChildren) visit(child);
  }
  visit(parser.parse(text).rootNode);
  return found.length === 1 && !found[0].hasError ? found[0] : null;
}

function rejects(node, condition, code) {
  if (node?.type !== 'if_statement' ||
      compact(node.childForFieldName('condition')?.text || '') !== condition) return false;
  const statements = node.childForFieldName('consequence')?.namedChildren || [];
  return statements.length === 2 && statements[0].type === 'expression_statement' &&
    /^LOGE\(/.test(statements[0].text) && statements[1].type === 'return_statement' &&
    compact(statements[1].text) === `return${code};`;
}

function identityShape(stub, texts) {
  const native = method(stub, 'TokenSyncManagerStub::IsNativeProcessCalling');
  const root = method(stub, 'TokenSyncManagerStub::IsRootCalling');
  if (!native || !root || !/TOKEN_HAP\s*=\s*0\s*,\s*TOKEN_NATIVE\s*,/.test(texts.tokenHeader) ||
      !/#ifndef ATM_BUILD_VARIANT_USER_ENABLE\s+static const int32_t ROOT_UID = 0;\s+#endif/.test(stub)) return false;
  const ns = native.childForFieldName('body')?.namedChildren || [];
  if (ns.length !== 4 || compact(ns[0].text) !== 'AccessTokenIDtokenCaller=IPCSkeleton::GetCallingTokenID();' ||
      compact(ns[1].text) !== 'uint32_ttype=(reinterpret_cast<AccessTokenIDInner*>(&tokenCaller))->type;' ||
      ns[2].type !== 'expression_statement' || !/^LOGD\(/.test(ns[2].text) ||
      compact(ns[3].text) !== 'returntype==TOKEN_NATIVE;') return false;
  const rs = root.childForFieldName('body')?.namedChildren || [];
  const branches = rs[0]?.namedChildren || [];
  return rs.length === 1 && rs[0].type === 'preproc_ifdef' &&
    rs[0].text.startsWith('#ifndef ATM_BUILD_VARIANT_USER_ENABLE') &&
    branches.length === 5 && branches[0].text === 'ATM_BUILD_VARIANT_USER_ENABLE' &&
    compact(branches[1].text) === 'intcallingUid=IPCSkeleton::GetCallingUid();' &&
    branches[2].type === 'expression_statement' && /^LOGD\(/.test(branches[2].text) &&
    compact(branches[3].text) === 'returncallingUid==ROOT_UID;' &&
    compact(branches[4].text) === '#elsereturnfalse;';
}

function sourceProof(entry, binding, cfg, idx, texts) {
  const unknown = (reason, extra = {}) => ({ status: 'insufficient', reason, contract,
    security: { status: 'insufficient', reason }, ...extra });
  if (entry?.kind !== 'ipc-code' || entry.ipcCode !== cfg.code || entry.method !== cfg.handler ||
      binding?.binding !== 'resolved' || binding.bound?.factId !== entry.factRef) {
    return unknown('ipc-code-binding-unresolved');
  }
  const unique = (qualified, file) => {
    const matches = idx.functions.filter((fn) => fn.role === 'production' && fn.qualified === qualified &&
      fn.sourceRange?.file === file && fn.quality?.errorNodes === 0);
    return matches.length === 1 ? matches[0] : null;
  };
  const owner = 'OHOS::Security::AccessToken::';
  const dispatch = unique(`${owner}TokenSyncManagerStub::OnRemoteRequest`, cfg.stubFile);
  const handler = unique(`${owner}TokenSyncManagerStub::${cfg.handler}`, cfg.stubFile);
  const target = unique(`${owner}TokenSyncManagerService::DeleteRemoteHapTokenInfo`, cfg.serviceFile);
  const call = idx.calls.filter((row) => row.caller === handler?.factId &&
    row.calleeName === 'DeleteRemoteHapTokenInfo' && row.argc === 1);
  if (!dispatch || !handler || !target || call.length !== 1 || entry.dispatchRef !== dispatch.factId ||
      entry.factRef !== handler.factId) return unknown('ipc-operation-binding-unresolved');
  const edges = dispatchOf(dispatch, texts.stub, texts.codeHeader, idx.functions, 'tokensync-enum');
  const edge = edges.edges.find((row) => row.code === cfg.code);
  if (edges.status !== 'parsed' || edges.edges.length !== 3 ||
      edge?.status !== 'resolved-dispatch' || edge.handler.factId !== handler.factId ||
      edge.handlerCallLine !== entry.handlerCallLine ||
      `${cfg.codeHeader}:${edge.defLine}` !== entry.codeDef ||
      edges.defaultLine !== entry.defaultLine) return unknown('ipc-dispatch-drift');
  const operation = { delegateRef: handler.factId, operationRef: target.factId,
    operationCallRef: call[0].factId };
  let profile;
  try { profile = JSON.parse(texts.profile); } catch (_) { return unknown('sa-profile-invalid', operation); }
  const ability = profile.systemability;
  if (profile.process !== 'token_sync_service' || ability?.length !== 1 || ability[0].name !== 3504 ||
      ability[0].libpath !== 'libtoken_sync_manager_service.z.so' || ability[0].distributed !== false ||
      !texts.profileBuild.includes('sources = [ "3504.json" ]') ||
      !texts.serviceBuild.includes('is_standard_system && token_sync_enable == true') ||
      !texts.serviceBuild.includes('ohos_shared_library("token_sync_manager_service")') ||
      !texts.serviceBuild.includes('"src/service/token_sync_manager_stub.cpp"') ||
      !texts.serviceBuild.includes('"src/service/token_sync_manager_service.cpp"') ||
      !texts.serviceBuild.includes('"ipc:ipc_single"') ||
      !texts.serviceBuild.includes('build_variant == "user"') ||
      !texts.serviceBuild.includes('"-DATM_BUILD_VARIANT_USER_ENABLE"') ||
      !texts.stubHeader.includes('class TokenSyncManagerStub : public IRemoteStub<ITokenSyncManager>') ||
      !texts.serviceHeader.includes('class TokenSyncManagerService final : public SystemAbility, public TokenSyncManagerStub') ||
      !texts.interfaceHeader.includes('SA_ID_TOKENSYNC_MANAGER_SERVICE = 3504') ||
      !texts.interfaceHeader.includes('virtual int DeleteRemoteHapTokenInfo(AccessTokenID tokenID) = 0')) {
    return unknown('sa-build-or-ownership-unresolved', operation);
  }
  const start = method(texts.service, 'TokenSyncManagerService::OnStart');
  const serviceOp = method(texts.service, 'TokenSyncManagerService::DeleteRemoteHapTokenInfo');
  const startText = start?.childForFieldName('body')?.text || '';
  const opText = serviceOp?.childForFieldName('body')?.text || '';
  if (!start || !serviceOp ||
      count(texts.service, 'SystemAbility::MakeAndRegisterAbility(DelayedSingleton<TokenSyncManagerService>::GetInstance().get())') !== 1 ||
      count(texts.service, 'SystemAbility(SA_ID_TOKENSYNC_MANAGER_SERVICE, false)') !== 1 ||
      !/if \(!Initialize\(\)\) \{[^}]*return;\s*\}/s.test(startText) ||
      count(startText, 'Publish(DelayedSingleton<TokenSyncManagerService>::GetInstance().get())') !== 1 ||
      !/if \(!ret\) \{[^}]*return;\s*\}/s.test(startText) ||
      !/NewDeleteRemoteTokenCommand\([^;]*tokenID\)/s.test(opText) ||
      !/ExecuteCommand\(\s*device.deviceId.uniqueDeviceId, deleteRemoteTokenCommand\)/.test(opText)) {
    return unknown('sa-publish-or-operation-unresolved', operation);
  }
  const profiles = idx.metadata.sa.filter((row) => row.payload?.saId === 3504 && row.sourceFile === cfg.profileFile &&
    row.payload?.process === profile.process && row.payload?.library === ability[0].libpath);
  const saRegistration = { profileRef: profiles.length === 1 ? profiles[0].metadataId : null,
    serviceFactRef: target.factId, process: profile.process, buildVariant: 'standard/token_sync_enable; user and non-user root branches' };
  if (!saRegistration.profileRef || !texts.ipcSkeleton.includes('return static_cast<uint32_t>(invoker->GetCallerTokenID());') ||
      !/SetStatus\(IRemoteInvoker::ACTIVE_INVOKER\);\s*int32_t error = TargetStubSendRequest/.test(texts.binderInvoker) ||
      !/callerUid_ = tr.sender_euid;[\s\S]*?GetSenderInfo\(callerTokenID_, firstTokenID_, callerRealPid_\);/.test(texts.binderInvoker)) {
    return unknown('ipc-caller-identity-unresolved', { ...operation, saRegistration });
  }
  const onRemote = method(texts.stub, 'TokenSyncManagerStub::OnRemoteRequest');
  const on = onRemote?.childForFieldName('body')?.namedChildren || [];
  if (on.length !== 6 || on[0].type !== 'expression_statement' || !/^LOGI\(/.test(on[0].text) ||
      compact(on[5].text) !== 'returnNO_ERROR;' ||
      !rejects(on[1], '(!IPCSkeleton::IsLocalCalling())', 'ERROR_IPC_REQUEST_FAIL') ||
      compact(on[2].text) !== 'std::u16stringdescriptor=data.ReadInterfaceToken();' ||
      !rejects(on[3], '(descriptor!=ITokenSyncManager::GetDescriptor())', 'ERROR_IPC_REQUEST_FAIL') ||
      on[4].type !== 'switch_statement' || !identityShape(texts.stub, texts)) {
    return unknown('ipc-caller-or-gate-shape-unknown', { ...operation, saRegistration });
  }
  const body = method(texts.stub, `TokenSyncManagerStub::${cfg.handler}`)?.childForFieldName('body');
  const statements = body?.namedChildren || [];
  if (statements.length !== 4 ||
      compact(statements[1].text) !== 'AccessTokenIDtokenID=data.ReadUint32();' ||
      compact(statements[2].text) !== 'intresult=this->DeleteRemoteHapTokenInfo(tokenID);' ||
      compact(statements[3].text) !== 'reply.WriteInt32(result);' ||
      call[0].line !== statements[2].startPosition.row + 1) {
    return unknown('ipc-operation-path-unknown', { ...operation, saRegistration });
  }
  const gate = statements[0];
  const condition = compact(gate.childForFieldName('condition')?.text || '');
  if (gate.type !== 'if_statement' || condition !== '(!IsRootCalling()&&!IsNativeProcessCalling())') {
    return unknown('ipc-identity-gate-unknown', { ...operation, saRegistration });
  }
  const rejected = gate.childForFieldName('consequence')?.namedChildren || [];
  if (rejected.length < 2 || rejected.length > 3 || rejected[0].type !== 'expression_statement' ||
      !/^LOGE\(/.test(rejected[0].text) || compact(rejected[1].text) !== 'reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);') {
    return unknown('ipc-reject-branch-unknown', { ...operation, saRegistration });
  }
  const blocks = rejected.length === 3 && rejected[2].type === 'return_statement' &&
    compact(rejected[2].text) === 'return;';
  if (rejected.length === 3 && !blocks) return unknown('ipc-reject-branch-unknown', { ...operation, saRegistration });
  const subject = { kind: 'hap-process', uid: 'non-root', tokenType: 'TOKEN_HAP',
    description: 'local IPC caller with non-root UID and HAP access token' };
  const proposition = 'This caller can invoke DeleteRemoteHapTokenInfo for the tokenID read from its parcel';
  return { ...operation, status: blocks ? 'excluded' : 'candidate',
    verificationStatus: 'static-only', assurance: 'bounded-analysis', contract, saRegistration,
    security: { status: blocks ? 'excluded' : 'candidate',
      family: blocks ? 'scoped-gate-rejection' : 'gate-non-blocking',
      ...(blocks ? {} : { reason: 'policy-anchor-doc-only' }), subject, proposition,
      rejectingGates: blocks ? ['root-or-native'] : [] },
    gates: [{ kind: 'root-or-native', line: gate.startPosition.row + 1,
      subjectVariable: 'IPCSkeleton::GetCallingTokenID()/GetCallingUid()', blocksOperation: blocks }],
    unanalyzable: [],
    limitation: 'Only the enabled standard TokenSync SA, local IPC, valid descriptor, non-root HAP token, and this code/tokenID; no remote deletion outcome or other callers is proven.' };
}

function analyze(facts, entry, binding, cfg) {
  if (cfg && cfg.shape === 'rust-enum') return require('./rust-verdict').analyze(facts, entry, binding, cfg);
  const texts = {};
  for (const [key, rel] of Object.entries({ stub: cfg.stubFile, stubHeader: cfg.stubHeader,
    service: cfg.serviceFile, serviceHeader: cfg.serviceHeader, interfaceHeader: cfg.interfaceHeader,
    tokenHeader: cfg.tokenHeader,
    codeHeader: facts.scope.ipcDispatch.codeHeader })) {
    if (!facts.verifyFile(rel).ok) return { status: 'insufficient', reason: 'stale-input' };
    texts[key] = fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
  }
  const profiles = facts.index().metadata.sa.filter((row) => row.payload?.saId === 3504 &&
    row.sourceFile === cfg.profileFile);
  const profilePath = path.join(facts.sourceRoot, ...cfg.profileFile.split('/'));
  if (profiles.length !== 1 || !fs.existsSync(profilePath) ||
      sha256File(profilePath) !== profiles[0].sha256) return { status: 'insufficient', reason: 'sa-profile-stale' };
  texts.profile = fs.readFileSync(profilePath, 'utf8');
  for (const [key, pinned] of Object.entries(cfg.pinned)) {
    const abs = path.join(facts.sourceRoot, ...pinned.file.split('/'));
    if (!fs.existsSync(abs) || sha256File(abs) !== pinned.sha256) {
      return { status: 'insufficient', reason: 'ipc-dependency-stale', file: pinned.file };
    }
    texts[key] = fs.readFileSync(abs, 'utf8');
  }
  return sourceProof(entry, binding, cfg, facts.index(), texts);
}

module.exports = { analyze, sourceProof };
