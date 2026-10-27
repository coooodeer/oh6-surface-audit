'use strict';

/**
 * lib/autonomy/rust-verdict.js —— 1.0.23-rust-ipc-code-verdict 的有界证明器（架构指南 §1.0.41）。
 *
 * 仅对 `ipcCodeVerdict.shape === 'rust-enum'` 的固定 Rust enum-code 派发样本成立：
 * 探针（rust-ast-probe）判形 + 固定源码文本形状 + 固定哈希依赖。输出合同与
 * ipc-verdict.js 相同；失败一律返回具名 insufficient，不放宽任何条件。
 */

const fs = require('fs');
const path = require('path');
const { sha256File } = require('../facts/ids');
const { rustDispatchOf, probeRows } = require('./ipc-dispatch');

const compact = (text) => text.replace(/\s+/g, '');
const contract = { status: 'not-applicable', family: 'not-applicable',
  reason: 'no-published-document-contract-for-internal-rust-ipc-code' };

function lineOf(text, fragment) {
  const rows = text.split(/\r?\n/);
  for (let i = 0; i < rows.length; i += 1) if (rows[i].includes(fragment)) return i + 1;
  return null;
}

function sourceProof(entry, binding, cfg, idx, texts, probe) {
  const unknown = (reason, extra = {}) => ({ status: 'insufficient', reason, contract,
    security: { status: 'insufficient', reason }, ...extra });
  if (entry?.kind !== 'ipc-code' || entry.ipcCode !== cfg.code || entry.method !== cfg.handler ||
      binding?.binding !== 'resolved' || binding.bound?.factId !== entry.factRef) {
    return unknown('rust-code-binding-unresolved');
  }
  const dispatch = idx.functions.find((fn) => fn.factId === entry.dispatchRef) || null;
  if (!dispatch || dispatch.language !== 'rust') return unknown('rust-dispatch-binding-unresolved');
  const model = rustDispatchOf(dispatch, probe.stub, probe.enum, idx.functions, cfg);
  const edge = model.edges.find((row) => row.code === cfg.code);
  if (model.status !== 'parsed' || model.edges.length !== (cfg.expectedEnum || []).length ||
      edge?.status !== 'resolved-dispatch' || edge.handler?.factId !== entry.factRef ||
      edge.handlerCallLine !== entry.handlerCallLine ||
      `${cfg.enumFile}:${edge.defLine}` !== entry.codeDef ||
      model.defaultLine !== entry.defaultLine) {
    return unknown('rust-dispatch-drift');
  }

  const operation = { delegateRef: edge.handler.factId, operationRef: null, operationCallRef: null };
  const exec = probe.service.filter((row) => row.kind === 'execute-call' &&
    row.name === `${cfg.handlerOwner}::${cfg.handler}->operations::query` && row.ctx === `${cfg.handlerOwner}::${cfg.handler}`);
  const execFact = idx.calls.filter((row) => row.edgeKind === 'execute-call' && row.caller === edge.handler.factId &&
    row.calleePath === 'operations::query');
  const opFn = idx.functions.filter((fn) => fn.role === 'production' && fn.language === 'rust' &&
    fn.name === 'query' && fn.sourceRange?.file === cfg.operationFile);
  if (exec.length !== 1 || execFact.length !== 1 || opFn.length !== 1) {
    return unknown('rust-execute-edge-unresolved', operation);
  }
  operation.operationRef = opFn[0].factId;
  operation.operationCallRef = execFact[0].factId;

  const svc = compact(texts.service);
  const macroOk = svc.includes('macro_rules!execute{($func:path,$calling_info:expr,$first_arg:expr)=>{{')
    && svc.includes('($func:path,$calling_info:expr,$first_arg:expr,$second_arg:expr)=>{{')
    && svc.includes('create_user_de_dir($calling_info.user_id())?;')
    && svc.includes('upload_system_event($func($calling_info,$first_arg),$calling_info,start,func_name,$first_arg)')
    && svc.includes('fnquery(&self,calling_info:&CallingInfo,query:&AssetMap)->Result<Vec<AssetMap>>{execute!(operations::query,calling_info,query)}');
  if (!macroOk) return unknown('rust-macro-shape-unknown', operation);

  const op = compact(texts.operation);
  const opTry = probe.operation.filter((row) => row.kind === 'try-call' &&
    row.name === 'query->check_arguments' && row.argc === 2);
  const opTail = probe.operation.filter((row) => row.kind === 'tail-call' &&
    row.name === 'check_arguments->common::check_system_permission' && row.argc === 1);
  if (!op.includes('fnquery(calling_info:&CallingInfo,query:&AssetMap)->Result<Vec<AssetMap>>{check_arguments(query,calling_info)?;')
      || !op.includes('common::check_system_permission(attributes)}') || opTry.length !== 1 || opTail.length !== 1) {
    return unknown('rust-operation-chain-unknown', operation);
  }

  const gates = probe.gate.filter((row) => row.kind === 'asset-gate' || row.kind === 'asset-gate-noblock');
  const badGates = probe.gate.filter((row) => row.kind === 'asset-gate-unresolved');
  if (gates.length !== 1 || badGates.length !== 0) return unknown('rust-gate-shape-unknown', operation);
  const blocks = gates[0].kind === 'asset-gate';

  const stub = compact(texts.stub);
  if (!stub.includes('matchdata.read_interface_token(){Ok(interface_token)ifinterface_token==stub.descriptor()=>{},_=>{')
      || !stub.includes('letipc_code=IpcCode::try_from(code).map_err(asset_err_handle)?;')
      || !stub.includes('letcalling_info=CallingInfo::build(map.get(&Tag::UserId).cloned(),&process_info);')
      || !stub.includes('IpcCode::Query=>matchstub.query(&calling_info,&map){')
      || !stub.includes('fndescriptor(&self)->&\'staticstr{SA_NAME}')) {
    return unknown('rust-stub-gate-or-object-unknown', operation);
  }
  const calling = compact(texts.calling);
  if (!calling.includes('ifletSome(Value::Number(specific_user_id))=specific_user_id{user_id=specific_user_id;};')) {
    return unknown('rust-object-link-unknown', operation);
  }
  const proc = compact(texts.process);
  if (!proc.includes('letuid=Skeleton::calling_uid();') || !proc.includes('GetCallingProcessInfo(user_id,uid,&mutprocess_info_ffi)')) {
    return unknown('rust-subject-origin-unknown', operation);
  }

  const ffi = compact(texts.ffi);
  if (!ffi.includes('boolCheckPermission(constchar*permission){autotokenId=IPCSkeleton::GetCallingTokenID();intresult=AccessTokenKit::VerifyAccessToken(tokenId,permission);if(result==PERMISSION_GRANTED){')
      || !ffi.includes('boolCheckSystemHapPermission(void){autotokenId=IPCSkeleton::GetCallingTokenID();ATokenTypeEnumtokenType=AccessTokenKit::GetTokenTypeFlag(tokenId);return(tokenType==ATokenTypeEnum::TOKEN_HAP)?CheckSystemApp():true;')
      || !ffi.includes('boolCheckSystemApp(void){autoaccessTokenId=IPCSkeleton::GetCallingFullTokenID();boolisSystemApp=TokenIdKit::IsSystemAppByFullTokenID(accessTokenId);')
      || !texts.ffiHeader.includes('extern "C"')) {
    return unknown('rust-ffi-identity-unknown', operation);
  }

  let profile;
  try { profile = JSON.parse(texts.profile); } catch (_) { return unknown('rust-sa-profile-invalid', operation); }
  const ability = profile.systemability;
  if (profile.process !== 'asset_service' || ability?.length !== 1 || ability[0].name !== 8100 ||
      ability[0].libpath !== 'libasset_service.dylib.so' || ability[0].distributed !== false) {
    return unknown('rust-sa-profile-unresolved', operation);
  }
  const regOk = svc.includes('#[link_section=".init_array"]')
    && svc.includes('letSome(sa)=AssetAbility.build_system_ability(SA_ID,true)else{')
    && svc.includes('sa.register();')
    && svc.includes('if!handler.publish(AssetService::new(handler.clone())){')
    && compact(texts.enum).includes('pubconstSA_ID:i32=8100;')
    && compact(texts.enum).includes('pubconstSA_NAME:&str="security_asset_service";')
    && texts.serviceBuild.includes('ohos_rust_shared_library("asset_service")')
    && texts.serviceBuild.includes('"src/lib.rs"')
    && texts.serviceBuild.includes('"ipc:ipc_rust"')
    && texts.serviceBuild.includes('"../os_dependency:asset_os_dependency"')
    && texts.serviceBuild.includes('crate_type = "dylib"')
    && texts.serviceBuild.includes('subsystem_name = "security"')
    && texts.serviceBuild.includes('part_name = "asset"');
  if (!regOk) return unknown('rust-sa-registration-unknown', operation);

  const startFn = idx.functions.filter((fn) => fn.role === 'production' && fn.language === 'rust' &&
    fn.name === 'start_service' && fn.sourceRange?.file === cfg.serviceFile);
  const profiles = idx.metadata.sa.filter((row) => row.payload?.saId === 8100 && row.sourceFile === cfg.profileFile);
  const saRegistration = {
    profileRef: profiles.length === 1 ? profiles[0].metadataId : null,
    serviceFactRef: startFn.length === 1 ? startFn[0].factId : null,
    process: profile.process,
    buildVariant: 'standard shared library (ohos_rust_shared_library asset_service, crate_type=dylib); declared build only'
  };
  if (!saRegistration.profileRef || !saRegistration.serviceFactRef) {
    return unknown('rust-sa-registration-unknown', { ...operation, saRegistration });
  }
  if (!texts.ipcSkeleton.includes('return static_cast<uint32_t>(invoker->GetCallerTokenID());') ||
      !/SetStatus\(IRemoteInvoker::ACTIVE_INVOKER\);\s*int32_t error = TargetStubSendRequest/.test(texts.binderInvoker) ||
      !/callerUid_ = tr.sender_euid;[\s\S]*?GetSenderInfo\(callerTokenID_, firstTokenID_, callerRealPid_\);/.test(texts.binderInvoker)) {
    return unknown('rust-caller-identity-unknown', { ...operation, saRegistration });
  }

  const gateLines = [
    { fragment: 'ErrCode::NotSystemApplication', label: 'system-hap-or-app' },
    { fragment: 'ErrCode::PermissionDenied', label: 'interact-across-local-accounts' },
    { fragment: 'ErrCode::AccessDenied', label: 'caller-user-range' }
  ].map((site) => ({ kind: 'cross-user-system-hap-permission', site: site.label,
    line: lineOf(texts.gate, site.fragment),
    subjectVariable: 'IPCSkeleton::GetCallingTokenID()/GetCallingFullTokenID()',
    blocksOperation: blocks }));
  if (gateLines.some((row) => !row.line)) return unknown('rust-gate-shape-unknown', { ...operation, saRegistration });

  const subject = { kind: 'hap-process', tokenType: 'TOKEN_HAP', systemApp: false,
    description: 'local IPC caller with a HAP access token that is not a system application' };
  const proposition = 'This caller can query the asset records of the user specified by request Tag::UserId';
  return {
    ...operation,
    status: blocks ? 'excluded' : 'candidate',
    verificationStatus: 'static-only',
    assurance: 'bounded-analysis',
    contract,
    saRegistration,
    security: {
      status: blocks ? 'excluded' : 'candidate',
      family: blocks ? 'scoped-gate-rejection' : 'gate-non-blocking',
      ...(blocks ? {} : { reason: 'policy-anchor-doc-only' }),
      subject,
      proposition,
      rejectingGates: blocks ? ['cross-user-system-hap-permission'] : []
    },
    gates: gateLines,
    unanalyzable: [],
    limitation: 'Only the declared standard Asset SA 8100 shared-library build, local IPC with a valid interface token, request maps carrying Tag::UserId and this Query code are proven. C++ IPC caller identity has known fallbacks (token 0 falls back to UID; no active invoker returns self token); plugin on_app_request/redirect_request effects and Rust macro numeric expansion are not proven; no other code, impl_enum_trait user, build variant, or remote/distributed path is covered.'
  };
}

function analyze(facts, entry, binding, cfg) {
  const unknown = (reason, extra = {}) => ({ status: 'insufficient', reason, contract,
    security: { status: 'insufficient', reason }, ...extra });
  if (entry?.kind !== 'ipc-code' || entry.ipcCode !== cfg.code || entry.method !== cfg.handler ||
      binding?.binding !== 'resolved' || binding.bound?.factId !== entry.factRef) {
    return unknown('rust-code-binding-unresolved');
  }
  const rels = { enum: cfg.enumFile, stub: cfg.stubFile, service: cfg.serviceFile,
    operation: cfg.operationFile, gate: cfg.gateFile, calling: cfg.callingFile,
    process: cfg.processFile, ffi: cfg.ffiFile, ffiHeader: cfg.ffiHeaderFile };
  const texts = {};
  for (const [key, rel] of Object.entries(rels)) {
    if (!facts.verifyFile(rel).ok) return unknown('stale-input', { file: rel });
    texts[key] = fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
  }
  const profiles = facts.index().metadata.sa.filter((row) => row.payload?.saId === 8100 &&
    row.sourceFile === cfg.profileFile);
  const profilePath = path.join(facts.sourceRoot, ...cfg.profileFile.split('/'));
  if (profiles.length !== 1 || !fs.existsSync(profilePath) ||
      sha256File(profilePath) !== profiles[0].sha256) return unknown('rust-sa-profile-stale');
  texts.profile = fs.readFileSync(profilePath, 'utf8');
  for (const [key, pinned] of Object.entries(cfg.pinned || {})) {
    const abs = path.join(facts.sourceRoot, ...pinned.file.split('/'));
    if (!fs.existsSync(abs) || sha256File(abs) !== pinned.sha256) {
      return unknown('rust-dependency-stale', { file: pinned.file });
    }
    texts[key] = fs.readFileSync(abs, 'utf8');
  }
  const binary = require('../facts/rust').probeBinary();
  if (!binary || !fs.existsSync(binary) || (cfg.probeSha256 && sha256File(binary) !== cfg.probeSha256)) {
    return unknown('rust-probe-stale');
  }
  const probe = {};
  for (const key of ['enum', 'stub', 'service', 'operation', 'gate']) {
    probe[key] = probeRows(binary, path.join(facts.sourceRoot, ...rels[key].split('/')));
    if (!probe[key]) return unknown('rust-probe-failed', { file: rels[key] });
  }
  return sourceProof(entry, binding, cfg, facts.index(), texts, probe);
}

module.exports = { analyze, sourceProof };
