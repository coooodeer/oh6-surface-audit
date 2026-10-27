use std::{env, fs, process};
use syn::{parse::Parser, punctuated::Punctuated, visit::{self, Visit}, BinOp, Expr, ExprIf,
    ExprMacro, ExprMatch, ExprMethodCall, ExprTry, ImplItemFn, ItemEnum, ItemFn, ItemMacro,
    Lit, Pat, Stmt, Token, UnOp};

fn path_is(expr: &Expr, parts: &[&str]) -> bool {
    matches!(expr, Expr::Path(value) if value.path.segments.iter().map(|p| p.ident.to_string())
        .collect::<Vec<_>>() == parts)
}

fn local_value<'a>(statement: &'a Stmt, name: &str) -> Option<&'a Expr> {
    let Stmt::Local(local) = statement else { return None; };
    let Pat::Ident(ident) = &local.pat else { return None; };
    if ident.ident != name { return None; }
    local.init.as_ref().filter(|init| init.diverge.is_none()).map(|init| init.expr.as_ref())
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum GatePart { Blocking, NonBlocking }

fn gate_macro(stmts: &[Stmt]) -> Option<(GatePart, &syn::Macro)> {
    match stmts {
        [Stmt::Expr(Expr::Return(ret), Some(_))] => {
            let Some(value) = &ret.expr else { return None; };
            let Expr::Macro(mac) = value.as_ref() else { return None; };
            Some((GatePart::Blocking, &mac.mac))
        }
        [Stmt::Expr(Expr::Macro(mac), _)] => Some((GatePart::NonBlocking, &mac.mac)),
        [Stmt::Macro(stmt_mac)] => Some((GatePart::NonBlocking, &stmt_mac.mac)),
        _ => None,
    }
}

fn error_macro_is(mac: &syn::Macro, error: &str) -> bool {
    if !mac.path.is_ident("log_throw_error") { return false; }
    let Ok(args) = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone()) else {
        return false;
    };
    matches!(args.first(), Some(first) if path_is(first, &["ErrCode", error]))
}

fn reject_shape(if_expr: &ExprIf, callee: &str, error: &str) -> Option<GatePart> {
    if if_expr.else_branch.is_some() || if_expr.then_branch.stmts.len() != 1 { return None; }
    let Expr::Unsafe(unsafe_expr) = if_expr.cond.as_ref() else { return None; };
    let [Stmt::Expr(Expr::Unary(unary), None)] = unsafe_expr.block.stmts.as_slice() else { return None; };
    let (UnOp::Not(_), Expr::Call(call)) = (&unary.op, unary.expr.as_ref()) else { return None; };
    if !path_is(&call.func, &[callee]) { return None; }
    if callee == "CheckSystemHapPermission" && !call.args.is_empty() { return None; }
    if callee == "CheckPermission" {
        let [Expr::MethodCall(arg)] = call.args.iter().collect::<Vec<_>>().as_slice() else { return None; };
        if arg.method != "as_ptr" || !arg.args.is_empty() ||
            !path_is(&arg.receiver, &["permission"]) { return None; }
    }
    let (part, mac) = gate_macro(if_expr.then_branch.stmts.as_slice())?;
    if error_macro_is(mac, error) { Some(part) } else { None }
}

fn uid_gate_shape(uid: &ExprIf) -> Option<GatePart> {
    if uid.else_branch.is_some() || uid.then_branch.stmts.len() != 1 { return None; }
    let Expr::Binary(compare) = uid.cond.as_ref() else { return None; };
    if !matches!(compare.op, BinOp::Gt(_)) || !path_is(&compare.left, &["user_id"]) ||
        !path_is(&compare.right, &["ROOT_USER_UPPERBOUND"]) { return None; }
    let (part, mac) = gate_macro(uid.then_branch.stmts.as_slice())?;
    if error_macro_is(mac, "AccessDenied") { Some(part) } else { None }
}

fn cstring_init(expr: &Expr) -> Option<&syn::ExprCall> {
    match expr {
        Expr::Call(call) => Some(call),
        Expr::MethodCall(method) if method.method == "unwrap" && method.args.is_empty() => {
            match method.receiver.as_ref() { Expr::Call(call) => Some(call), _ => None }
        }
        _ => None,
    }
}

fn asset_gate_state(node: &ItemFn) -> Option<GatePart> {
    let [Stmt::Expr(Expr::If(outer), None), Stmt::Expr(tail, None)] = node.block.stmts.as_slice()
        else { return None; };
    if outer.else_branch.is_some() || !matches!(tail, Expr::Call(call)
        if path_is(&call.func, &["Ok"]) && matches!(call.args.first(), Some(Expr::Tuple(tuple))
            if call.args.len() == 1 && tuple.elems.is_empty())) {
        return None;
    }
    let Expr::MethodCall(is_some) = outer.cond.as_ref() else { return None; };
    let Expr::MethodCall(get) = is_some.receiver.as_ref() else { return None; };
    let Some(Expr::Reference(tag)) = get.args.first() else { return None; };
    if is_some.method != "is_some" || !is_some.args.is_empty() || get.method != "get" ||
        get.args.len() != 1 || !path_is(&get.receiver, &["attrs"]) ||
        !path_is(&tag.expr, &["Tag", "UserId"]) { return None; }
    let body = &outer.then_branch.stmts;
    if body.len() != 6 { return None; }
    let (Stmt::Expr(Expr::If(system), None), permission_local @ Stmt::Local(_),
        Stmt::Expr(Expr::If(permission), None), uid_local @ Stmt::Local(_),
        user_local @ Stmt::Local(_),
        Stmt::Expr(Expr::If(uid), None)) = (&body[0], &body[1], &body[2], &body[3], &body[4], &body[5])
        else { return None; };
    let Some(permission_init) = local_value(permission_local, "permission").and_then(cstring_init)
        else { return None; };
    if !path_is(&permission_init.func, &["CString", "new"]) ||
        !matches!(permission_init.args.first(), Some(Expr::Lit(lit))
            if permission_init.args.len() == 1 && matches!(&lit.lit, Lit::Str(value)
                if value.value() == "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS")) { return None; }
    let Some(Expr::Call(uid_init)) = local_value(uid_local, "uid") else { return None; };
    if !path_is(&uid_init.func, &["Skeleton", "calling_uid"]) || !uid_init.args.is_empty() {
        return None;
    }
    let Some(Expr::Try(user_init)) = local_value(user_local, "user_id") else { return None; };
    let Expr::Call(user_call) = user_init.expr.as_ref() else { return None; };
    if !path_is(&user_call.func, &["get_user_id"]) ||
        !matches!(user_call.args.first(), Some(arg) if user_call.args.len() == 1 && path_is(arg, &["uid"])) {
        return None;
    }
    let system_part = reject_shape(system, "CheckSystemHapPermission", "NotSystemApplication")?;
    let permission_part = reject_shape(permission, "CheckPermission", "PermissionDenied")?;
    let uid_part = uid_gate_shape(uid)?;
    Some(if system_part == GatePart::Blocking && permission_part == GatePart::Blocking
        && uid_part == GatePart::Blocking { GatePart::Blocking } else { GatePart::NonBlocking })
}

#[derive(Default)]
struct StubCalls(Vec<(String, usize, usize)>);

impl<'ast> Visit<'ast> for StubCalls {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if let Expr::Path(receiver) = node.receiver.as_ref() {
            if receiver.path.is_ident("stub") {
                self.0.push((node.method.to_string(), node.method.span().start().line, node.args.len()));
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

#[derive(Default)]
struct FunctionEdges {
    execute: Vec<(String, usize, usize)>,
    try_calls: Vec<(String, usize, usize)>,
    tail_call: Option<(String, usize, usize)>,
    unsupported: Vec<usize>,
}

impl<'ast> Visit<'ast> for FunctionEdges {
    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        if node.mac.path.is_ident("execute") {
            let args = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(node.mac.tokens.clone());
            match args.as_ref().ok().and_then(|args| args.first()) {
                Some(Expr::Path(target)) if target.path.segments.len() == 2 => {
                    self.execute.push((format!("{}::{}", target.path.segments[0].ident,
                        target.path.segments[1].ident), node.mac.path.segments[0].ident.span().start().line,
                        args.as_ref().map(|a| a.len().saturating_sub(1)).unwrap_or(0)));
                }
                _ => self.unsupported.push(node.mac.path.segments[0].ident.span().start().line),
            }
        }
        visit::visit_expr_macro(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast ExprTry) {
        if let Expr::Call(call) = node.expr.as_ref() {
            if let Expr::Path(target) = call.func.as_ref() {
                if let Some(name) = target.path.segments.last() {
                    self.try_calls.push((name.ident.to_string(), name.ident.span().start().line, call.args.len()));
                }
            }
        }
        visit::visit_expr_try(self, node);
    }
}

fn qualified(owner: &str, name: &str) -> String {
    if owner.is_empty() { name.to_string() } else { format!("{owner}::{name}") }
}

struct Inventory<'a> {
    file: &'a str,
    rows: Vec<String>,
    ctx: Vec<String>,
}

impl Inventory<'_> {
    fn row(&mut self, kind: &str, name: &str, line: usize, end_line: usize, ctx: &str, argc: usize) {
        self.rows.push(format!("{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.file, kind, name, line, end_line, ctx, argc));
    }

    fn emit_function(&mut self, node: &ItemFn, owner: &str) {
        let name = node.sig.ident.to_string();
        let line = node.sig.ident.span().start().line;
        let end = node.block.brace_token.span.close().end().line;
        let q = qualified(owner, &name);
        self.row("function", &name, line, end, owner, node.sig.inputs.len());
        if name == "check_system_permission" {
            let kind = match asset_gate_state(node) {
                Some(GatePart::Blocking) => "asset-gate",
                Some(GatePart::NonBlocking) => "asset-gate-noblock",
                None => "asset-gate-unresolved",
            };
            self.row(kind, "UserId->system-app,permission,uid", line, 0, &q, 0);
        }
        let mut edges = FunctionEdges::default();
        edges.visit_block(&node.block);
        for (target, call_line, argc) in edges.try_calls {
            self.row("try-call", &format!("{q}->{target}"), call_line, 0, &q, argc);
        }
        for (target, call_line, argc) in edges.execute {
            self.row("execute-call", &format!("{q}->{target}"), call_line, 0, &q, argc);
        }
        for call_line in edges.unsupported { self.row("execute-unresolved", &q, call_line, 0, &q, 0); }
        if let Some(Stmt::Expr(Expr::Call(call), None)) = node.block.stmts.last() {
            if let Expr::Path(target) = call.func.as_ref() {
                let callee = target.path.segments.iter().map(|part| part.ident.to_string())
                    .collect::<Vec<_>>().join("::");
                self.row("tail-call", &format!("{q}->{callee}"),
                    target.path.segments[0].ident.span().start().line, 0, &q, call.args.len());
            }
        }
    }
}

impl<'ast> Visit<'ast> for Inventory<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let owner = self.ctx.last().cloned().unwrap_or_default();
        self.emit_function(node, &owner);
        self.ctx.push(qualified(&owner, &node.sig.ident.to_string()));
        visit::visit_item_fn(self, node);
        self.ctx.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let owner = self.ctx.last().map(|s| s.as_str()).unwrap_or("").to_string();
        let name = node.sig.ident.to_string();
        let q = qualified(&owner, &name);
        self.row("method", &name, node.sig.ident.span().start().line,
            node.block.brace_token.span.close().end().line, &owner, node.sig.inputs.len());
        let mut edges = FunctionEdges::default();
        edges.visit_block(&node.block);
        for (target, line, argc) in edges.try_calls {
            self.row("try-call", &format!("{q}->{target}"), line, 0, &q, argc);
        }
        for (target, line, argc) in edges.execute {
            self.row("execute-call", &format!("{q}->{target}"), line, 0, &q, argc);
        }
        for line in edges.unsupported { self.row("execute-unresolved", &q, line, 0, &q, 0); }
        if let Some(Stmt::Expr(Expr::Call(call), None)) = node.block.stmts.last() {
            if let Expr::Path(target) = call.func.as_ref() {
                let callee = target.path.segments.iter().map(|part| part.ident.to_string())
                    .collect::<Vec<_>>().join("::");
                self.row("tail-call", &format!("{q}->{callee}"),
                    target.path.segments[0].ident.span().start().line, 0, &q, call.args.len());
            }
        }
        self.ctx.push(q);
        visit::visit_impl_item_fn(self, node);
        self.ctx.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let owner = match node.self_ty.as_ref() {
            syn::Type::Path(ty) => ty.path.segments.iter()
                .map(|segment| segment.ident.to_string()).collect::<Vec<_>>().join("::"),
            _ => String::new(),
        };
        self.ctx.push(owner);
        visit::visit_item_impl(self, node);
        self.ctx.pop();
    }

    fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
        if node.mac.path.is_ident("impl_enum_trait") {
            if let Ok(item) = syn::parse2::<ItemEnum>(node.mac.tokens.clone()) {
                for variant in item.variants {
                    self.row("ipc-enum", &variant.ident.to_string(), variant.ident.span().start().line, 0, "", 0);
                }
            } else {
                self.row("unsupported-macro", "impl_enum_trait", node.mac.path.segments[0].ident.span().start().line, 0, "", 0);
            }
        }
        visit::visit_item_macro(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        let ctx = self.ctx.last().map(|s| s.as_str()).unwrap_or("").to_string();
        for arm in &node.arms {
            if let Pat::Path(path) = &arm.pat {
                if path.path.segments.len() == 2 && path.path.segments[0].ident == "IpcCode" {
                    let code = path.path.segments[1].ident.to_string();
                    let line = path.path.segments[1].ident.span().start().line;
                    self.row("ipc-arm", &code, line, 0, &ctx, 0);
                    let mut calls = StubCalls::default();
                    calls.visit_expr(&arm.body);
                    if calls.0.len() == 1 {
                        self.row("ipc-call", &format!("{}->{}", code, calls.0[0].0), calls.0[0].1, 0, &ctx, calls.0[0].2);
                    } else {
                        self.row("ipc-unresolved", &code, line, 0, &ctx, 0);
                    }
                }
            }
        }
        visit::visit_expr_match(self, node);
    }
}

fn inspect(file: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    let parsed = syn::parse_file(source)?;
    let mut inventory = Inventory { file, rows: Vec::new(), ctx: Vec::new() };
    inventory.visit_file(&parsed);
    Ok(inventory.rows)
}

fn main() {
    let files: Vec<_> = env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("usage: oh6-rust-ast-probe <rust-source>...");
        process::exit(2);
    }
    for file in &files {
        let source = fs::read_to_string(file).unwrap_or_else(|err| {
            eprintln!("{file}: {err}");
            process::exit(1);
        });
        let rows = inspect(file, &source).unwrap_or_else(|err| {
            eprintln!("{file}: {err}");
            process::exit(1);
        });
        for row in rows { println!("{row}"); }
    }
}

#[cfg(test)]
mod tests {
    use super::inspect;
    use std::{fs, path::Path};

    const GATE_FIXTURE: &str = "fn check_system_permission(attrs: &AssetMap) -> Result<()> {\n\
        if attrs.get(&Tag::UserId).is_some() {\n\
            if unsafe { !CheckSystemHapPermission() } {\n\
                return log_throw_error!(ErrCode::NotSystemApplication, \"not system\");\n\
            }\n\
            let permission = CString::new(\"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS\").unwrap();\n\
            if unsafe { !CheckPermission(permission.as_ptr()) } {\n\
                return log_throw_error!(ErrCode::PermissionDenied, \"denied\");\n\
            }\n\
            let uid = Skeleton::calling_uid();\n\
            let user_id = get_user_id(uid)?;\n\
            if user_id > ROOT_USER_UPPERBOUND {\n\
                return log_throw_error!(ErrCode::AccessDenied, \"uid {}\", user_id);\n\
            }\n\
        }\n\
        Ok(())\n\
    }";

    fn gate_row(source: &str) -> Option<String> {
        let rows = inspect("sample.rs", source).unwrap();
        rows.iter().filter_map(|r| {
            let kind = r.split('\t').nth(1)?;
            kind.starts_with("asset-gate").then(|| kind.to_string())
        }).next()
    }

    #[test]
    fn extracts_structured_enum_and_dispatch_without_inventing_other_arms() {
        let source = "impl_enum_trait! { pub enum IpcCode { Get, Query } }\n\
            fn dispatch(code: IpcCode) { match code { IpcCode::Query => stub.query(),\n\
            IpcCode::Get => stub.get(), _ => fallback() } }";
        let rows = inspect("sample.rs", source).unwrap();
        assert_eq!(rows.iter().filter(|r| r.contains("\tipc-enum\t")).count(), 2);
        assert_eq!(rows.iter().filter(|r| r.contains("\tipc-arm\t")).count(), 2);
        assert!(rows.iter().any(|r| r.contains("\tipc-call\tQuery->query\t")));
        assert!(rows.iter().any(|r| r.contains("\tfunction\tdispatch\t")));
        assert!(!rows.iter().any(|r| r.contains("\tipc-arm\tfallback\t")));
    }

    #[test]
    fn ambiguous_or_absent_stub_call_is_unresolved() {
        let source = "fn dispatch(code: IpcCode) { match code {\n\
            IpcCode::Query => { stub.query(); stub.remove(); },\n\
            IpcCode::Add => fallback(), _ => () } }";
        let rows = inspect("sample.rs", source).unwrap();
        assert_eq!(rows.iter().filter(|r| r.contains("\tipc-unresolved\t")).count(), 2);
        assert!(!rows.iter().any(|r| r.contains("\tipc-call\t")));
    }

    #[test]
    fn execute_and_try_edges_require_supported_ast_shapes() {
        let source = "impl AssetService { fn query(&self) { execute!(operations::query, caller, map) }\n\
            fn unknown(&self) { execute!(other + target, caller, map) } }\n\
            fn query() { check_arguments()?; db_query() }\n\
            fn check_arguments() { common::check_system_permission(attrs) }\n\
            fn no_gate() { check_arguments(); db_query() }";
        let rows = inspect("sample.rs", source).unwrap();
        assert!(rows.iter().any(|r| r.contains("\texecute-call\tAssetService::query->operations::query\t")));
        assert!(rows.iter().any(|r| r.contains("\texecute-unresolved\tAssetService::unknown\t")));
        assert!(rows.iter().any(|r| r.contains("\ttry-call\tquery->check_arguments\t")));
        assert!(rows.iter().any(|r| r.contains("\ttail-call\tcheck_arguments->common::check_system_permission\t")));
        assert!(!rows.iter().any(|r| r.contains("\ttry-call\tno_gate->")));
    }

    #[test]
    fn malformed_source_is_not_a_partial_inventory() {
        assert!(inspect("bad.rs", "fn broken( {").is_err());
    }

    #[test]
    fn rows_carry_context_and_arity_columns() {
        let source = "impl AssetService { fn query(&self, calling_info: &CallingInfo, map: &AssetMap) {\n\
            execute!(operations::query, calling_info, map) } }\n\
            fn dispatch(stub: &AssetService, code: IpcCode) { match code {\n\
            IpcCode::Query => stub.query(a, b), _ => () } }";
        let rows = inspect("sample.rs", source).unwrap();
        let method = rows.iter().find(|r| r.contains("\tmethod\tquery\t")).unwrap();
        let parts: Vec<&str> = method.split('\t').collect();
        assert_eq!(parts[5], "AssetService");
        assert_eq!(parts[6], "3");
        let call = rows.iter().find(|r| r.contains("\tipc-call\tQuery->query\t")).unwrap();
        assert_eq!(call.split('\t').nth(5), Some("dispatch"));
        assert_eq!(call.split('\t').nth(6), Some("2"));
        let exec = rows.iter().find(|r| r.contains("\texecute-call\t")).unwrap();
        assert_eq!(exec.split('\t').nth(5), Some("AssetService::query"));
        assert_eq!(exec.split('\t').nth(6), Some("2"));
    }

    #[test]
    fn real_asset_ipc_has_seven_unique_dispatch_edges() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../OpenHarmony/base/security/asset");
        let ipc = fs::read_to_string(root.join("frameworks/ipc/src/lib.rs")).unwrap();
        let stub = fs::read_to_string(root.join("services/core_service/src/stub.rs")).unwrap();
        let enums = inspect("ipc.rs", &ipc).unwrap();
        let arms = inspect("stub.rs", &stub).unwrap();
        let codes: Vec<_> = enums.iter().filter(|r| r.contains("\tipc-enum\t")).collect();
        let calls: Vec<_> = arms.iter().filter(|r| r.contains("\tipc-call\t")).collect();
        assert_eq!(codes.len(), 7);
        assert_eq!(calls.len(), 7);
        assert!(!arms.iter().any(|r| r.contains("\tipc-unresolved\t")));
        assert_eq!(calls.iter().filter(|r| r.contains("\tipc-call\tQuery->query\t")).count(), 1);
        let service = fs::read_to_string(root.join("services/core_service/src/lib.rs")).unwrap();
        let operation = fs::read_to_string(root.join("services/core_service/src/operations/operation_query.rs")).unwrap();
        let service_rows = inspect("service.rs", &service).unwrap();
        let operation_rows = inspect("operation.rs", &operation).unwrap();
        assert_eq!(service_rows.iter().filter(|r| r.contains("\texecute-call\tAssetService::query->operations::query\t")).count(), 1);
        assert_eq!(operation_rows.iter().filter(|r| r.contains("\ttry-call\tquery->check_arguments\t")).count(), 1);
        assert_eq!(operation_rows.iter().filter(|r| r.contains("\ttail-call\tcheck_arguments->common::check_system_permission\t")).count(), 1);
    }

    #[test]
    fn asset_gate_accepts_cstring_new_unwrap_and_direct_call_shapes() {
        assert_eq!(gate_row(GATE_FIXTURE).as_deref(), Some("asset-gate"));
        let direct = GATE_FIXTURE.replace(".unwrap()", "");
        assert_eq!(gate_row(&direct).as_deref(), Some("asset-gate"));
        let wrapped = GATE_FIXTURE.replace(".unwrap()", ".expect(\"cstring\")");
        assert_eq!(gate_row(&wrapped).as_deref(), Some("asset-gate-unresolved"));
    }

    #[test]
    fn asset_gate_counterexamples_cover_rejection_caller_and_object() {
        assert_eq!(gate_row(GATE_FIXTURE).as_deref(), Some("asset-gate"));
        // 拒绝早退消失：门禁仍可识别但不再阻断 → asset-gate-noblock（对应 candidate 上限）
        let nonblocking = [
            ("return log_throw_error!(ErrCode::NotSystemApplication, \"not system\");",
                "log_throw_error!(ErrCode::NotSystemApplication, \"not system\");"),
            ("return log_throw_error!(ErrCode::PermissionDenied, \"denied\");",
                "log_throw_error!(ErrCode::PermissionDenied, \"denied\");"),
            ("return log_throw_error!(ErrCode::AccessDenied, \"uid {}\", user_id);",
                "log_throw_error!(ErrCode::AccessDenied, \"uid {}\", user_id);"),
        ];
        for (from, to) in nonblocking {
            assert_eq!(gate_row(&GATE_FIXTURE.replace(from, to)).as_deref(),
                Some("asset-gate-noblock"), "dropped early exit must stay identifiable: {from}");
        }
        let mutations = [
            // 门禁极性反转/条件漂移
            ("!CheckSystemHapPermission()", "CheckSystemHapPermission()"),
            ("user_id > ROOT_USER_UPPERBOUND", "user_id >= ROOT_USER_UPPERBOUND"),
            // 调用方身份不来自 IPC 调用方
            ("let uid = Skeleton::calling_uid();", "let uid = Skeleton::self_uid();"),
            ("CheckPermission(permission.as_ptr())", "CheckPermission(other.as_ptr())"),
            ("CheckSystemHapPermission()", "CheckSystemHapPermission(caller)"),
            // 对象/触发面错位
            ("ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS", "ohos.permission.OTHER"),
            ("attrs.get(&Tag::UserId)", "attrs.get(&Tag::Secret)"),
            // 用户范围校验缺失（? 早退语义丢失）
            ("let user_id = get_user_id(uid)?;", "let user_id = get_user_id(uid);"),
        ];
        for (from, to) in mutations {
            assert_eq!(gate_row(&GATE_FIXTURE.replace(from, to)).as_deref(),
                Some("asset-gate-unresolved"), "mutation must stay unresolved: {from} -> {to}");
        }
        // 混合变异：一处早退丢失 + 一处极性反转 → 整形不成立，unresolved
        let mixed = GATE_FIXTURE
            .replace("return log_throw_error!(ErrCode::PermissionDenied, \"denied\");",
                "log_throw_error!(ErrCode::PermissionDenied, \"denied\");")
            .replace("!CheckSystemHapPermission()", "CheckSystemHapPermission()");
        assert_eq!(gate_row(&mixed).as_deref(), Some("asset-gate-unresolved"));
    }

    #[test]
    fn real_asset_permission_check_gate_is_resolved() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../OpenHarmony/base/security/asset");
        let source = fs::read_to_string(
            root.join("services/core_service/src/operations/common/permission_check.rs")).unwrap();
        let rows = inspect("permission_check.rs", &source).unwrap();
        assert_eq!(rows.iter().filter(|r| r.contains("\tasset-gate\t")).count(), 1);
        assert!(!rows.iter().any(|r| r.contains("\tasset-gate-unresolved\t")));
        assert!(!rows.iter().any(|r| r.contains("\tasset-gate-noblock\t")));
    }
}
