//! Account ABI v2. All handles are checked integer IDs, including result handles.
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
use toastlink_core::account::{AccountClient, Actor, DeviceGrant, Error, Session};
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
    Poll,
    Restore,
    Identity,
    Disconnect,
    ForgetLocal,
    ListPersonas,
    ActivePersona,
    Persona {
        persona_id: Uuid,
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
    Prepare {
        persona_id: Option<Uuid>,
        messages: Vec<Value>,
        memory_query: String,
        memory_limit: u8,
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
            Op::Poll => {
                let grant = self.pending.as_mut().ok_or(Error::Expired)?;
                let tokens = grant.poll()?;
                self.pending = None;
                let session = self.client.accept(tokens)?;
                let identity = json!(session.identity);
                self.session = Some(session);
                return Ok(identity);
            }
            Op::Restore => {
                self.session = None;
                let session = self.client.restore()?;
                let identity = json!(session.identity);
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
            Op::Disconnect => {
                s.revoke()?;
                self.session = None;
                self.pending = None;
                self.client.forget_local()?;
                Value::Null
            }
            Op::ListPersonas => json!(s.personas()?),
            Op::ActivePersona => json!(s.active_persona()?),
            Op::Persona { persona_id } => json!(s.persona(persona_id)?),
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
            } => json!(s.save_memory(persona_id, &content, weight)?),
            Op::Search {
                persona_id,
                query,
                limit,
            } => json!(s.search(persona_id, &query, limit)?),
            Op::DeleteMemory {
                persona_id,
                memory_id,
            } => json!(s.delete_memory(persona_id, memory_id)?),
            Op::Prepare {
                persona_id,
                messages,
                memory_query,
                memory_limit,
            } => json!(s.prepare(persona_id, &messages, &memory_query, memory_limit)?),
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
        let op: Op =
            serde_json::from_slice(unsafe { input(data, len)? }).map_err(|_| Error::Protocol)?;
        let client = match OBJECTS.lock().map_err(|_| Error::Storage)?.get(&handle) {
            Some(Object::Client(c)) => c.clone(),
            _ => return Err(Error::Protocol),
        };
        let result = client.lock().map_err(|_| Error::Storage)?.execute(op)?;
        unsafe {
            *out = insert(Object::Bytes(
                serde_json::to_vec(&result).map_err(|_| Error::Protocol)?,
            ))?;
        }
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
