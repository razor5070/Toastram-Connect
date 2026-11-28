//! Account ABI v2. All handles are checked integer IDs, including result handles.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Instant,
};
use toastlink_core::account::{AccountClient, Actor, ConversationOp, DeviceGrant, Error, Session, VisualKind};
use uuid::Uuid;

struct State {
    client: AccountClient,
    pending: Option<DeviceGrant>,
    session: Option<Session>,
}
enum Object {
    Client(Arc<Mutex<State>>),
    Bytes(Vec<u8>),
}
static OBJECTS: LazyLock<Mutex<HashMap<u64, Object>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT: AtomicU64 = AtomicU64::new(1);
fn insert(obj: Object) -> Result<u64, Error> {
    let id = NEXT
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| Error::Storage)?;
    OBJECTS.lock().map_err(|_| Error::Storage)?.insert(id, obj);
    Ok(id)
}
fn error(e: Error) -> i32 {
    match e {
        Error::Origin => 2,
        Error::Protocol => 3,
        Error::Transport => 4,
        Error::Pending => 5,
        Error::SlowDown => 6,
        Error::Denied => 7,
        Error::Expired => 8,
        Error::LoginRequired => 9,
        Error::Conflict => 10,
        Error::NoActivePersona => 11,
        Error::NotFound => 12,
        Error::Storage => 13,
        Error::Quota => 15,
        Error::Rejected(n) => 1000 + i32::from(n),
    }
}
fn boundary(f: impl FnOnce() -> Result<(), Error>) -> i32 {
    catch_unwind(AssertUnwindSafe(f))
        .map(|r| r.err().map_or(0, error))
        .unwrap_or(14)
}
unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8], Error> {
    if data.is_null() || len == 0 || len > 1_048_576 {
        return Err(Error::Protocol);
    }
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    origin: String,
    ca_pem: Option<String>,
}
#[no_mangle]
pub unsafe extern "C" fn toast_account_v2_open(data: *const u8, len: usize, out: *mut u64) -> i32 {
    if out.is_null() {
        return 3;
    }
    unsafe {
        *out = 0;
    }
    boundary(|| {
        let arg: Open =
            serde_json::from_slice(unsafe { input(data, len)? }).map_err(|_| Error::Protocol)?;
        let client =
            AccountClient::discover(&arg.origin, arg.ca_pem.as_deref().map(str::as_bytes))?;
        unsafe {
            *out = insert(Object::Client(Arc::new(Mutex::new(State {
                client,
                pending: None,
                session: None,
            }))))?;
        }
        Ok(())
    })
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Op {
    Authorize {
        device_name: String,
    },
    AuthorizeScoped { device_name: String, scopes: Vec<String> },
    Conversation { action: ConversationOp, args: serde_json::Map<String,Value> },
    Poll,
    AnnouncementPoll {},
    AnnouncementClaim { id: Uuid },
    AnnouncementAck { id: Uuid },
    Restore,
    Identity,
    Disconnect,
    ForgetLocal,
    ListPersonas,
    ActivePersona,
    Persona {
        persona_id: Uuid,
    },
    Visuals {
        persona_id: Uuid,
    },
    VisualAsset {
        persona_id: Uuid,
        kind: VisualKind,
        sha256: String,
        mime: String,
    },
    Blank {
        activate: bool,
    },
    Generate {
        model: String,
        activate: bool,
    },
    Activate {
        persona_id: Uuid,
    },
    Update {
        persona_id: Uuid,
        name: String,
        profile: String,
        expected_revision: u64,
        actor: Actor,
    },
    DeletePersona {
        persona_id: Uuid,
        expected_revision: u64,
        confirm: String,
    },
    SaveMemory {
        persona_id: Uuid,
        content: String,
        weight: f64,
        origin_kind: Option<String>,
        origin_ref: Option<String>,
    },
    Search {
        persona_id: Uuid,
        query: String,
        limit: u8,
    },
    DeleteMemory {
        persona_id: Uuid,
        memory_id: Uuid,
    },
    RestoreLastMemory {
        persona_id: Uuid,
    },
    StoreEvidence {
        persona_id: Uuid,
        answer_id: Uuid,
        revision: u32,
        evidence: Value,
    },
    LoadEvidence {
        persona_id: Uuid,
        answer_id: Uuid,
        revision: u32,
    },
    Prepare {
        persona_id: Option<Uuid>,
        messages: Vec<Value>,
        memory_query: String,
        memory_limit: u8,
        retrieval_mode: Option<String>,
    },
}
impl State {
    fn execute(&mut self, op: Op) -> Result<Value, Error> {
        match op {
            Op::Authorize { device_name } => {
                let grant = self.client.authorize(&device_name)?;
                let meta = json!({"user_code":grant.user_code,"verification_url":grant.verification_url,"expires_in":grant.deadline.saturating_duration_since(Instant::now()).as_secs(),"interval":grant.interval.as_secs()});
                self.pending = Some(grant);
                return Ok(meta);
            }
            Op::AuthorizeScoped { device_name, scopes } => {
                let grant = self.client.authorize_scoped(&device_name, &scopes)?;
                let meta = json!({"user_code":grant.user_code,"verification_url":grant.verification_url,"expires_in":grant.deadline.saturating_duration_since(Instant::now()).as_secs(),"interval":grant.interval.as_secs()});
                self.pending = Some(grant);
                return Ok(meta);
            }
            Op::Poll => {
                let grant = self.pending.as_mut().ok_or(Error::Expired)?;
                let tokens = grant.poll()?;
                self.pending = None;
                let session = self.client.accept(tokens)?;
                let identity = json!(session.identity());
                self.session = Some(session);
                return Ok(identity);
            }
            Op::Restore => {
                self.session = None;
                let session = self.client.restore()?;
                let identity = json!(session.identity());
                self.session = Some(session);
                return Ok(identity);
            }
            Op::ForgetLocal => {
                self.client.forget_local()?;
                self.pending = None;
                self.session = None;
                return Ok(Value::Null);
            }
            _ => (),
        }
        let s = self.session.as_mut().ok_or(Error::LoginRequired)?;
        Ok(match op {
            Op::Identity => json!(s.me()?),
            Op::AnnouncementClaim { id } => s.claim_announcement(id)?,
            Op::Conversation { action,args } => s.conversation(action,args)?,
            Op::Disconnect => {
                s.revoke()?;
                self.client.forget_device(s.identity())?;
                self.session = None;
                self.pending = None;
                Value::Null
            }
            Op::ListPersonas => json!(s.personas()?),
            Op::ActivePersona => json!(s.active_persona()?),
            Op::Persona { persona_id } => json!(s.persona(persona_id)?),
            Op::Visuals { persona_id } => json!(s.visuals(persona_id)?),
            Op::VisualAsset {
                persona_id,
                kind,
                sha256,
                mime,
            } => {
                let bytes = s.visual_asset(persona_id, kind, &sha256, &mime)?;
                json!({"sha256":sha256,"mime":mime,"data_base64":STANDARD.encode(bytes)})
            }
            Op::Blank { activate } => json!(s.blank(activate)?),
            Op::Generate { model, activate } => json!(s.generate(&model, activate)?),
            Op::Activate { persona_id } => json!(s.activate(persona_id)?),
            Op::Update {
                persona_id,
                name,
                profile,
                expected_revision,
                actor,
            } => json!(s.update(persona_id, &name, &profile, expected_revision, actor)?),
            Op::DeletePersona {
                persona_id,
                expected_revision,
                confirm,
            } => json!(s.delete_persona(persona_id, expected_revision, &confirm)?),
            Op::SaveMemory {
                persona_id,
                content,
                weight,
                origin_kind,
                origin_ref,
            } => json!(s.save_memory_with_origin(
                persona_id,
                &content,
                weight,
                origin_kind.as_deref(),
                origin_ref.as_deref()
            )?),
            Op::Search {
                persona_id,
                query,
                limit,
            } => json!(s.search(persona_id, &query, limit)?),
            Op::DeleteMemory {
                persona_id,
                memory_id,
            } => json!(s.delete_memory(persona_id, memory_id)?),
            Op::RestoreLastMemory { persona_id } => {
                json!({"memory_id":s.restore_last_memory(persona_id)?})
            }
            Op::StoreEvidence {
                persona_id,
                answer_id,
                revision,
                evidence,
            } => s.store_evidence(persona_id, answer_id, revision, &evidence)?,
            Op::LoadEvidence {
                persona_id,
                answer_id,
                revision,
            } => s.load_evidence(persona_id, answer_id, revision)?,
            Op::Prepare {
                persona_id,
                messages,
                memory_query,
                memory_limit,
                retrieval_mode,
            } => json!(s.prepare_with_retrieval_mode(
                persona_id,
                &messages,
                &memory_query,
                memory_limit,
                retrieval_mode.as_deref()
            )?),
            _ => return Err(Error::Protocol),
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn toast_account_v2_call(
    handle: u64,
    data: *const u8,
    len: usize,
    out: *mut u64,
) -> i32 {
    if out.is_null() {
        return 3;
    }
    unsafe {
        *out = 0;
    }
    boundary(|| {
        // Only conversation requests may use the expanded history payload limit.
        if data.is_null() || len==0 || len>9*1024*1024+4096 {return Err(Error::Protocol);}
        let raw=unsafe { std::slice::from_raw_parts(data,len) };
        let op:Op=serde_json::from_slice(raw).map_err(|_|Error::Protocol)?;
        if len>1_048_576 && !matches!(&op,Op::Conversation{..}) {return Err(Error::Protocol);}
        let client = match OBJECTS.lock().map_err(|_| Error::Storage)?.get(&handle) {
            Some(Object::Client(c)) => c.clone(),
            _ => return Err(Error::Protocol),
        };
        let result = match op {
            Op::Conversation { action,args } => {
                let request={
                    let mut state=client.lock().map_err(|_|Error::Storage)?;
                    state.session.as_mut().ok_or(Error::LoginRequired)?.conversation_request(action,args)?
                };
                let (binding,result)=request.wait();
                let mut state=client.lock().map_err(|_|Error::Storage)?;
                state.session.as_mut().ok_or(Error::LoginRequired)?.finish_conversation(binding,result)?
            }
            Op::AnnouncementPoll {} | Op::AnnouncementAck { .. } => {
                let request = {
                    let mut state = client.lock().map_err(|_| Error::Storage)?;
                    let session = state.session.as_mut().ok_or(Error::LoginRequired)?;
                    match op {
                        Op::AnnouncementPoll {} => session.announcement_poll_request()?,
                        Op::AnnouncementAck { id } => session.announcement_ack_request(id)?,
                        _ => return Err(Error::Protocol),
                    }
                };
                let response = request.wait();
                let mut state = client.lock().map_err(|_| Error::Storage)?;
                state.session.as_mut().ok_or(Error::LoginRequired)?.finish_announcement(response)?
            }
            other=>client.lock().map_err(|_| Error::Storage)?.execute(other)?,
        };
        unsafe {
            *out = insert(Object::Bytes(
                serde_json::to_vec(&result).map_err(|_| Error::Protocol)?,
            ))?;
        }
        Ok(())
    })
}
/// Long-poll one finite SSE notification without holding the account session lock.
#[no_mangle]
pub unsafe extern "C" fn toast_account_v2_conversation_events(handle:u64,after:u64,out:*mut u64)->i32 {
    if out.is_null(){return 3;}
    unsafe{*out=0;}
    boundary(|| {
        let client=match OBJECTS.lock().map_err(|_|Error::Storage)?.get(&handle) {
            Some(Object::Client(c))=>c.clone(),_=>return Err(Error::Protocol),
        };
        let request={
            let mut state=client.lock().map_err(|_|Error::Storage)?;
            state.session.as_mut().ok_or(Error::LoginRequired)?.conversation_event_request(after)?
        };
        let result=request.wait()?;
        unsafe{*out=insert(Object::Bytes(serde_json::to_vec(&result).map_err(|_|Error::Protocol)?))?;}
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn toast_account_v2_copy(
    handle: u64,
    dst: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    if len.is_null() {
        return 3;
    }
    unsafe {
        *len = 0;
    }
    boundary(|| {
        let map = OBJECTS.lock().map_err(|_| Error::Storage)?;
        let Some(Object::Bytes(data)) = map.get(&handle) else {
            return Err(Error::Protocol);
        };
        unsafe {
            *len = data.len();
        }
        if dst.is_null() && cap == 0 {
            return Ok(());
        }
        if dst.is_null() || cap < data.len() {
            return Err(Error::Protocol);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    })
}
#[no_mangle]
pub extern "C" fn toast_account_v2_release(handle: u64) -> i32 {
    boundary(|| {
        OBJECTS
            .lock()
            .map_err(|_| Error::Storage)?
            .remove(&handle)
            .map(|_| ())
            .ok_or(Error::Protocol)
    })
}

#[no_mangle]
pub unsafe extern "C" fn toast_account_v2_forget_local(data: *const u8, len: usize) -> i32 {
    boundary(|| {
        let arg: Open =
            serde_json::from_slice(unsafe { input(data, len)? }).map_err(|_| Error::Protocol)?;
        AccountClient::forget_offline(&arg.origin, arg.ca_pem.as_deref().map(str::as_bytes))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn announcement_operations_are_strict() {
        assert!(matches!(serde_json::from_str::<super::Op>(r#"{"op":"announcement_poll"}"#).unwrap(), super::Op::AnnouncementPoll {}));
        assert!(serde_json::from_str::<super::Op>(r#"{"op":"announcement_poll","account_id":"forged"}"#).is_err());
        assert!(serde_json::from_str::<super::Op>(r#"{"op":"announcement_ack"}"#).is_err());
    }
    #[test]
    fn conversation_abi_parses_explicit_scopes_and_allowlisted_operations() {
        assert!(serde_json::from_str::<Op>(r#"{"op":"authorize_scoped","device_name":"desktop","scopes":["profile","conversation.read"]}"#).is_ok());
        assert!(serde_json::from_str::<Op>(r#"{"op":"conversation","action":"changes","args":{"after":0}}"#).is_ok());
        assert!(serde_json::from_str::<Op>(r#"{"op":"conversation","action":"arbitrary_url","args":{}}"#).is_err());
    }

    use super::*;
    #[test]
    fn prepare_preserves_legacy_requests_and_accepts_hybrid_mode() {
        let mut request = json!({
            "op": "prepare", "persona_id": null,
            "messages": [], "memory_query": "topic", "memory_limit": 20
        });
        assert!(matches!(
            serde_json::from_value::<Op>(request.clone()),
            Ok(Op::Prepare {
                memory_limit: 20,
                retrieval_mode: None,
                ..
            })
        ));
        request["retrieval_mode"] = json!("semantic_hybrid");
        assert!(matches!(
            serde_json::from_value::<Op>(request),
            Ok(Op::Prepare { memory_limit: 20, retrieval_mode: Some(mode), .. })
                if mode == "semantic_hybrid"
        ));
    }

    #[test]
    fn save_memory_accepts_supplied_and_omitted_origin_fields() {
        let persona = Uuid::new_v4();
        let legacy = json!({
            "op":"save_memory", "persona_id":persona,
            "content":"hello", "weight":0.5
        });
        assert!(matches!(
            serde_json::from_value::<Op>(legacy),
            Ok(Op::SaveMemory { persona_id, origin_kind: None, origin_ref: None, .. })
                if persona_id == persona
        ));
        let annotated = json!({
            "op":"save_memory", "persona_id":persona,
            "content":"hello", "weight":0.5,
            "origin_kind":"user_saved", "origin_ref":"turn:123"
        });
        assert!(matches!(
            serde_json::from_value::<Op>(annotated),
            Ok(Op::SaveMemory { origin_kind: Some(kind), origin_ref: Some(reference), .. })
                if kind == "user_saved" && reference == "turn:123"
        ));
        let with_extra = json!({
            "op":"save_memory", "persona_id":persona,
            "content":"hello", "weight":0.5,
            "origin_kind":"assistant_saved", "unexpected":"value"
        });
        assert!(serde_json::from_value::<Op>(with_extra).is_err());
    }

    #[test]
    fn unified_visual_operations_are_strictly_scoped() {
        let persona = Uuid::new_v4();
        let manifest = json!({"op":"visuals","persona_id":persona});
        assert!(matches!(serde_json::from_value::<Op>(manifest.clone()),
            Ok(Op::Visuals { persona_id }) if persona_id == persona));
        let mut extra = manifest;
        extra["account_id"] = json!("untrusted");
        assert!(serde_json::from_value::<Op>(extra).is_err());
        let request = json!({"op":"visual_asset","persona_id":persona,
            "kind":"sprites","sha256":"a".repeat(64),"mime":"image/png"});
        assert!(matches!(serde_json::from_value::<Op>(request.clone()),
            Ok(Op::VisualAsset { persona_id, kind: VisualKind::Sprites, .. }) if persona_id == persona));
        for kind in ["../other", "expansion"] {
            let mut invalid = request.clone();
            invalid["kind"] = json!(kind);
            assert!(serde_json::from_value::<Op>(invalid).is_err());
        }
        assert!(serde_json::from_value::<Op>(json!({
            "op":"expansion_manifest","persona_id":persona
        }))
        .is_err());
    }

    #[test]
    fn restore_last_memory_operation_parses_and_rejects_extra_fields() {
        let persona = Uuid::new_v4();
        let operation = serde_json::json!({
            "op":"restore_last_memory", "persona_id":persona
        });
        assert!(matches!(
            serde_json::from_value::<Op>(operation),
            Ok(Op::RestoreLastMemory { persona_id }) if persona_id == persona
        ));
        let extra = serde_json::json!({
            "op":"restore_last_memory", "persona_id":persona, "account_id":"untrusted"
        });
        assert!(serde_json::from_value::<Op>(extra).is_err());
    }

    #[test]
    fn bounded_inputs_and_owned_result_lifetime() {
        let mut out = 17;
        assert_eq!(
            unsafe { toast_account_v2_open(std::ptr::null(), 0, &mut out) },
            3
        );
        assert_eq!(out, 0);
        let invalid = [0xff];
        assert_eq!(
            unsafe { toast_account_v2_open(invalid.as_ptr(), invalid.len(), &mut out) },
            3
        );
        let handle = insert(Object::Bytes(b"ok".to_vec())).unwrap();
        let mut len = 0;
        let mut buf = [0; 2];
        assert_eq!(
            unsafe { toast_account_v2_copy(handle, buf.as_mut_ptr(), 1, &mut len) },
            3
        );
        assert_eq!(len, 2);
        assert_eq!(
            unsafe { toast_account_v2_copy(handle, buf.as_mut_ptr(), 2, &mut len) },
            0
        );
        assert_eq!(&buf, b"ok");
        assert_eq!(toast_account_v2_release(handle), 0);
        assert_eq!(
            unsafe { toast_account_v2_copy(handle, buf.as_mut_ptr(), 2, &mut len) },
            3
        );
        assert_eq!(len, 0);
    }
}
