#![allow(private_bounds)]
use std::{
    cmp::Ordering,
    collections::HashMap,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    vec::Drain,
};

use argon2;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};

use keyring::Entry as KeyringEntry;
use postcard::{from_bytes, to_stdvec};
use rand::{RngExt, TryRng, rngs::SysRng};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use time::{Date, Duration, UtcDateTime};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod error;
pub use error::{Error, Result};

static SECURE_PARAMS: argon2::Result<argon2::Params> = argon2::Params::new(262_144, 4, 4, None); // 256 MB main encryption

static FAST_PARAMS: argon2::Result<argon2::Params> = argon2::Params::new(32_768, 3, 4, None); // stores the encrypted key in os storage

static LOG_MAX_LEN: usize = 1024;
static PRE_ALLOC_SECURE_BUF: bool = true;

fn set_union<T, F>(mut a: &mut Drain<'_, T>, mut b: &mut Drain<'_, T>, cmp: F) -> Vec<T>
where
    F: Fn(&T, &T) -> Ordering,
{
    let mut merged = Vec::with_capacity(a.len() + b.len());
    let mut curr_a = a.next();
    let mut curr_b = b.next();
    loop {
        match (curr_a, curr_b) {
            (Some(value_a), Some(value_b)) => match cmp(&value_a, &value_b) {
                Ordering::Less => {
                    merged.push(value_a);
                    curr_a = a.next();
                    curr_b = Some(value_b);
                }
                Ordering::Equal => {
                    merged.push(value_a);
                    curr_a = a.next();
                    curr_b = b.next();
                }
                Ordering::Greater => {
                    merged.push(value_b);
                    curr_b = b.next();
                    curr_a = Some(value_a);
                }
            },
            (Some(value), None) => {
                merged.push(value);
                merged.extend(&mut a);
                break;
            }
            (None, Some(value)) => {
                merged.push(value);
                merged.extend(&mut b);
                break;
            }
            _ => break,
        }
    }
    merged
}

#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
struct KeyStore {
    cipher_text: Vec<u8>,
    salt: [u8; 16],
    nonce: [u8; 24],
}

fn derive_key(password: &[u8], salt: [u8; 16]) -> Result<[u8; 32]> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        SECURE_PARAMS.clone().unwrap(),
    );
    let mut key = [0; 32];
    argon2
        .hash_password_into(password, &salt, key.as_mut_slice())
        .map_err(|_| "Couldn't generate hashing parameters")?;
    Ok(key)
}

fn cache_key(key: [u8; 32], password: &[u8], repo_name: &str) -> Result<()> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    let mut rng = SysRng;
    rng.try_fill_bytes(&mut salt)?;
    rng.try_fill_bytes(&mut nonce)?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        FAST_PARAMS.clone().unwrap(),
    );
    let mut output = [0; 32];
    argon2
        .hash_password_into(password, &salt, &mut output)
        .map_err(|_| "Couldn't generate hashing parameters")?;

    let cipher = XChaCha20Poly1305::new(&output.into());

    let hashed_key = cipher.encrypt(&nonce.into(), key.as_slice())?;

    let store = KeyStore {
        cipher_text: hashed_key,
        salt,
        nonce,
    };

    let entry = KeyringEntry::new("SecretInnKeep", repo_name)?;
    entry.set_password(&STANDARD.encode(to_stdvec(&store)?.as_slice()))?;
    Ok(())
}

fn retrieve_key(password: &[u8], repo_name: &str) -> Result<[u8; 32]> {
    let entry = KeyringEntry::new("SecretInnKeep", repo_name)?;
    let secret = entry.get_password()?;

    let store = from_bytes::<KeyStore>(STANDARD.decode(&secret)?.as_slice())?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        FAST_PARAMS.clone().unwrap(),
    );

    let mut output = [0; 32];
    argon2
        .hash_password_into(password, &store.salt, &mut output)
        .map_err(|_| "Couldn't generate hashing parameters")?;

    let cipher = XChaCha20Poly1305::new(&output.into());

    let key: [u8; 32] = cipher
        .decrypt(&store.nonce.into(), store.cipher_text.as_slice())?
        .as_slice()
        .try_into()?;

    Ok(key)
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
struct Token {
    token: String,
    #[zeroize(skip)]
    expiry_date: Date,
}

#[derive(Serialize, Deserialize)]
struct PullBody {
    #[serde(rename = "_links")]
    links: PullBodyLinks,
    content: Option<String>,
    download_url: Option<String>,
    encoding: Option<String>,
    entries: Option<Vec<Entry>>,
    git_url: Option<String>,
    html_url: Option<String>,
    name: String,
    path: String,
    sha: String,
    size: i64,
    #[serde(rename = "type")]
    pull_body_type: String,
    url: String,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    #[serde(rename = "_links")]
    links: EntryLinks,
    download_url: Option<String>,
    git_url: Option<String>,
    html_url: Option<String>,
    name: String,
    path: String,
    sha: String,
    size: i64,
    #[serde(rename = "type")]
    entry_type: String,
    url: String,
}

#[derive(Serialize, Deserialize)]
struct EntryLinks {
    git: Option<String>,
    html: Option<String>,
    #[serde(rename = "self")]
    links_self: String,
}

#[derive(Serialize, Deserialize)]
struct PullBodyLinks {
    git: Option<String>,
    html: Option<String>,
    #[serde(rename = "self")]
    links_self: String,
}

#[derive(Serialize, Deserialize)]
struct PushBody {
    message: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<String>,
    committer: Committer,
    branch: String,
}

#[derive(Serialize, Deserialize)]
struct Committer {
    name: String,
    email: String,
}

impl Committer {
    fn new(name: &str, email: &str) -> Self {
        Self {
            name: name.to_string(),
            email: email.to_string(),
        }
    }
}

#[derive(ZeroizeOnDrop)]
struct HashParam {
    key: [u8; 32],
    nonce: [u8; 24],
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop, Zeroize)]
pub struct MetaData {
    pub repo_name: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    #[zeroize(skip)]
    pub time_stamp: UtcDateTime,
}

impl MetaData {
    pub fn new(
        repo_name: String,
        device_name: Option<String>,
        device_type: Option<String>,
    ) -> Self {
        Self {
            repo_name,
            device_name,
            device_type,
            time_stamp: UtcDateTime::now(),
        }
    }

    pub fn empty(repo_name: String) -> Self {
        return Self {
            repo_name,
            device_name: None,
            device_type: None,
            time_stamp: UtcDateTime::now(),
        };
    }
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
struct SecureRingBuf<T: Zeroize> {
    max_cap: usize,
    write_index: usize,
    buf: Vec<T>,
}

impl<T: Zeroize> SecureRingBuf<T> {
    pub fn new(mut max_cap: usize) -> Self {
        max_cap = std::cmp::max(max_cap, 15);
        let buf = if PRE_ALLOC_SECURE_BUF {
            Vec::<T>::with_capacity(max_cap) // aditional element to handle extra push
        } else {
            vec![] // for maximum secuiry the vector should reserve memory
        };

        Self {
            max_cap,
            write_index: 0,
            buf,
        }
    }

    pub fn push(&mut self, value: T) {
        if self.buf.len() >= self.max_cap {
            self.buf[self.write_index] = value;
        } else {
            self.buf.push(value);
        }
        self.write_index = (self.write_index + 1) % self.max_cap;
    }

    pub fn iter(&'_ self) -> SecureRingBufIterator<'_, T> {
        let index = if self.buf.len() >= self.max_cap {
            self.write_index
        } else {
            0
        };
        SecureRingBufIterator {
            ref_buf: &self,
            index,
            count: 0,
        }
    }

    pub fn merge<F>(&mut self, other: &mut SecureRingBuf<T>, cmp: F)
    // fills the buf whith the largest max_cap items w.r.t cmp O(N) merging is not worth it????
    where
        F: Fn(&T, &T) -> Ordering,
    {
        let mut a: Vec<T> = self.buf.drain(..).collect();
        a.sort_by(&cmp);

        let mut b: Vec<T> = other.buf.drain(..).collect();
        b.sort_by(&cmp);

        let mut merged = set_union(&mut a.drain(..), &mut b.drain(..), &cmp);

        let start = std::cmp::max(0, merged.len() as isize - self.max_cap as isize) as usize;
        self.buf.extend(merged.drain(start..));
    }
}

struct SecureRingBufIterator<'a, T: Zeroize> {
    ref_buf: &'a SecureRingBuf<T>,
    index: usize,
    count: usize,
}

impl<'a, T: Zeroize> Iterator for SecureRingBufIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < self.ref_buf.buf.len() {
            let result = &self.ref_buf.buf[self.index];
            self.index = (self.index + 1) % self.ref_buf.buf.len();
            self.count += 1;
            Some(result)
        } else {
            None
        }
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct PasswordEntry {
    #[zeroize(skip)]
    uuid: Uuid,
    #[zeroize(skip)]
    last_edit: UtcDateTime,
    name: String,
    url: Option<String>,
    username: Option<String>,
    password: String,
    note: Option<String>,
}

impl PasswordEntry {
    pub fn new(
        name: String,
        url: Option<String>,
        username: Option<String>,
        password: String,
        note: Option<String>,
    ) -> Self {
        let uuid = Uuid::now_v7();
        let last_edit = UtcDateTime::now();
        Self {
            uuid,
            last_edit,
            name,
            url,
            username,
            password,
            note,
        }
    }

    fn edit(
        &mut self,
        name: Option<String>,
        url: Option<String>,
        username: Option<String>,
        password: Option<String>,
        note: Option<String>,
    ) {
        if let Some(s) = name {
            self.name = s;
        };
        if let Some(s) = url {
            self.url = Some(s);
        };
        if let Some(s) = username {
            self.username = Some(s);
        };
        if let Some(s) = password {
            self.password = s;
        };
        if let Some(s) = note {
            self.note = Some(s);
        };
        self.last_edit = UtcDateTime::now();
    }

    fn view<'a>(&'a self) -> PasswordView<'a> {
        PasswordView::new(
            &self.uuid,
            &self.name,
            (&self.url).as_deref(),
            (&self.note).as_deref(),
        )
    }
}

#[derive(Debug)]
pub struct PasswordView<'a> {
    pub uuid: &'a Uuid,
    pub name: &'a str,
    pub url: Option<&'a str>,
    pub note: Option<&'a str>,
}

impl<'a> PasswordView<'a> {
    pub fn new(uuid: &'a Uuid, name: &'a str, url: Option<&'a str>, note: Option<&'a str>) -> Self {
        Self {
            uuid,
            name,
            url,
            note,
        }
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
struct Payload {
    token: Token,
    log_history: SecureRingBuf<MetaData>,
    passwords: Vec<PasswordEntry>,
}

impl Payload {
    pub fn encrypt(&self, params: &HashParam) -> Result<Vec<u8>> {
        let mut payload_bytes = Zeroizing::new(to_stdvec(&self)?); // TODO change this as it might leak data
        let padded_size = payload_bytes.len() + (1 << 18) - payload_bytes.len() % (1 << 8);
        let mut rng = rand::rng();
        payload_bytes.resize_with(padded_size, || rng.random());

        let cipher = XChaCha20Poly1305::new(&params.key.into());
        Ok(cipher.encrypt(&params.nonce.into(), payload_bytes.as_slice())?)
    }

    pub fn new(pat: &str, exp_date: i32) -> Result<Self> {
        let token = Token {
            token: pat.to_string(),
            expiry_date: if exp_date == 0 {
                Date::MAX
            } else {
                UtcDateTime::now()
                    .date()
                    .checked_add(Duration::days(exp_date as i64))
                    .unwrap()
            },
        };

        Ok(Self {
            token,
            log_history: SecureRingBuf::new(LOG_MAX_LEN),
            passwords: vec![],
        })
    }

    pub fn log(&mut self, repo_name: &str, device_name: Option<&str>, device_type: Option<&str>) {
        self.log_history.push(MetaData {
            repo_name: repo_name.to_string(),
            device_name: device_name.map(|s| s.to_string()),
            device_type: device_type.map(|s| s.to_string()),
            time_stamp: UtcDateTime::now(),
        });
    }

    pub fn merge(&mut self, mut other: Payload) {
        self.log_history.merge(&mut other.log_history, |a, b| {
            a.time_stamp.cmp(&b.time_stamp)
        });

        let mut merged: HashMap<Uuid, PasswordEntry> =
            self.passwords.drain(..).map(|p| (p.uuid, p)).collect();

        for pwd in other.passwords.drain(..) {
            let edit_time = pwd.last_edit;
            match merged.insert(pwd.uuid, pwd) {
                Some(cur) => {
                    if edit_time < cur.last_edit {
                        merged.insert(cur.uuid, cur);
                    }
                }
                None => {}
            }
        }

        self.passwords = merged.into_values().collect();
    }
}

#[derive(Serialize, Deserialize)]
struct Blob {
    salt: [u8; 16],
    nonce: [u8; 24],
    payload_store: Vec<u8>,
}

impl Blob {
    pub fn from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut bytes = Vec::<u8>::new();
        reader.read_to_end(&mut bytes)?;
        Ok(from_bytes::<Blob>(&bytes)?)
    }

    pub fn decrypt(&self, params: &HashParam) -> Result<Payload> {
        let cipher = XChaCha20Poly1305::new(&params.key.into());
        let payload_bytes =
            Zeroizing::new(cipher.decrypt(&params.nonce.into(), self.payload_store.as_slice())?);
        Ok(from_bytes::<Payload>(payload_bytes.as_slice())?)
    }
}

pub trait VaultMarker {}

#[derive(ZeroizeOnDrop)]
pub struct LockedVault;

impl VaultMarker for LockedVault {}

#[derive(ZeroizeOnDrop)]
pub struct UnlockedVault {
    session_key: [u8; 32],
    payload: Payload,
}

impl VaultMarker for UnlockedVault {}

impl UnlockedVault {
    fn get_payload_mut(&mut self) -> &mut Payload {
        &mut self.payload
    }

    fn get_payload(&self) -> &Payload {
        &self.payload
    }
}

pub struct Vault<V>
where
    V: ZeroizeOnDrop + VaultMarker,
{
    repo_name: String,
    device_name: Option<String>,
    device_type: Option<String>,
    cache_path: PathBuf,
    state: V,
}

impl Vault<UnlockedVault> {
    pub fn add_entry(
        &mut self,
        name: &str,
        url: Option<&str>,
        username: Option<&str>,
        password: &str,
        note: Option<&str>,
    ) {
        self.state
            .get_payload_mut()
            .passwords
            .push(PasswordEntry::new(
                name.to_string(),
                url.as_deref().map(|s| s.to_string()),
                username.as_deref().map(|s| s.to_string()),
                password.to_string(),
                note.as_deref().map(|s| s.to_string()),
            ));

        self.state.get_payload_mut().log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );
    }

    pub fn edit_entry(
        &mut self,
        uuid: Uuid,
        name: Option<&str>,
        url: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        note: Option<&str>,
    ) -> Result<()> {
        let res = self
            .state
            .get_payload()
            .passwords
            .binary_search_by_key(&uuid, |p| p.uuid)
            .map_err(|_| "No Password Found")?;

        self.state.get_payload_mut().passwords[res].edit(
            name.as_deref().map(|s| s.to_string()),
            url.as_deref().map(|s| s.to_string()),
            username.as_deref().map(|s| s.to_string()),
            password.as_deref().map(|s| s.to_string()),
            note.as_deref().map(|s| s.to_string()),
        );
        Ok(())
    }

    pub fn get_entry(&self, uuid: Uuid) -> Result<&PasswordEntry> {
        let res = self
            .state
            .get_payload()
            .passwords
            .binary_search_by_key(&uuid, |p| p.uuid)
            .map_err(|_| "No Password Found")?;
        Ok(&self.state.get_payload().passwords[res])
    }

    pub fn get_logs(&self) -> impl Iterator<Item = &MetaData> {
        self.state.get_payload().log_history.iter()
    }

    pub fn get_view<'a>(&'a self) -> impl Iterator<Item = PasswordView<'a>> {
        self.state.get_payload().passwords.iter().map(|p| p.view())
    }

    pub fn export_csv() {
        todo!()
    }

    pub fn import_csv(&mut self) -> Result<()> {
        todo!()
    }

    pub fn lock(self) -> Vault<LockedVault> {
        Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: LockedVault,
        }
    }

    async fn pull(&self) -> Result<PullBody> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_str("application/vnd.github+json")?,
        );
        let mut token_header =
            HeaderValue::from_str(&(format!("Bearer {}", &self.state.payload.token.token)))?;
        token_header.set_sensitive(true);
        headers.insert(AUTHORIZATION, token_header);
        headers.insert("X-GitHub-Api-Version", HeaderValue::from_str("2026-03-10")?);
        headers.insert("User-Agent", HeaderValue::from_str("Password Manager App")?);

        let client = reqwest::Client::builder().build()?;
        let body_str = client
            .get(
                &(format!(
                    "https://api.github.com/repos/{}/contents/vault.dat",
                    &self.repo_name
                )),
            )
            .headers(headers)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str::<PullBody>(&body_str)?)
    }

    fn sync(&mut self, blob: Blob) -> Result<Vec<u8>> {
        let file_params = HashParam {
            key: self.state.session_key,
            nonce: blob.nonce,
        };

        let payload = blob.decrypt(&file_params)?;

        self.state.get_payload_mut().merge(payload);
        self.state.get_payload_mut().log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );

        let mut nonce = [0u8; 24];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut nonce)?;

        let updated_params = HashParam {
            key: self.state.session_key,
            nonce: nonce,
        };
        let encrypted_payload = self.state.get_payload().encrypt(&updated_params)?;

        let updated_blob = Blob {
            salt: blob.salt,
            nonce: updated_params.nonce,
            payload_store: encrypted_payload,
        };

        Ok(to_stdvec(&updated_blob)?)
    }

    pub async fn remote_sync(&mut self) -> Result<()> {
        let pull_body = self.pull().await?;
        let blob;
        if let Some(c) = pull_body.content {
            let c = c.replace('\n', "").replace('\r', "");
            blob = from_bytes::<Blob>(&STANDARD.decode(&c)?)?
        } else {
            return Err("Empty response".into());
        }
        let sha = pull_body.sha;
        let serialized_blob = self.sync(blob)?;

        self.push(
            serialized_blob.as_slice(),
            Some(&sha),
            &self.state.payload.token.token,
        )
        .await?;
        Ok(())
    }

    pub fn local_sync(&mut self) -> Result<()> {
        let file_path = &(self.cache_path.join("cache.dat"));
        if !file_path.is_file() {
            return Err(format!("Vault file doesn't exist {:?}", file_path).into());
        }
        let blob = Blob::from_file(file_path)?;

        let serialized_blob = self.sync(blob)?;
        fs::write(file_path, serialized_blob.as_slice())?;
        Ok(())
    }

    pub async fn global_sync(&mut self) -> Result<()> {
        self.remote_sync().await?;
        self.local_sync()?;
        Ok(())
    }

    // TODO add write to disk ????
}

impl Vault<LockedVault> {
    pub fn empty(
        repo_name: &str,
        device_name: Option<&str>,
        device_type: Option<&str>,
        path: &Path,
    ) -> Vault<LockedVault> {
        Vault {
            repo_name: repo_name.to_string(),
            device_name: device_name.as_deref().map(|s| s.to_string()),
            device_type: device_type.as_deref().map(|s| s.to_string()),
            cache_path: path.to_path_buf(),
            state: LockedVault,
        }
    }

    pub async fn remote_unlock(self, password: &str) -> Result<Vault<UnlockedVault>> {
        let blob = self.fetch().await?;
        let master_key = derive_key(password.as_bytes(), blob.salt)?;

        let file_params = HashParam {
            key: master_key,
            nonce: blob.nonce,
        };

        let payload = blob.decrypt(&file_params)?;

        cache_key(master_key, password.as_bytes(), &self.repo_name)?;

        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key: master_key,
                payload,
            },
        })
    }

    pub fn local_unlock(self, password: &str) -> Result<Vault<UnlockedVault>> {
        let mut buf = Vec::new();
        let mut cache_file = File::open(self.cache_path.join("cache.dat"))?;
        cache_file.read_to_end(&mut buf)?;

        let blob = from_bytes::<Blob>(&buf)?;
        let master_key = derive_key(password.as_bytes(), blob.salt)?;

        let file_params = HashParam {
            key: master_key,
            nonce: blob.nonce,
        };

        let payload = blob.decrypt(&file_params)?;
        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key: master_key,
                payload,
            },
        })
    }

    pub async fn remote_unlock_cached(self, password: &str) -> Result<Vault<UnlockedVault>> {
        let client = reqwest::Client::builder().build()?;
        let blob_bytes = client
            .get(
                &("https://github.com/".to_string()
                    + &self.repo_name
                    + "/raw/refs/heads/main/vault.dat"),
            )
            .header("Cache-Control", "no-cache, no-store, must-revalidate")
            .send()
            .await?
            .bytes()
            .await?;
        let blob = from_bytes::<Blob>(&blob_bytes.slice(..))?;
        let master_key = retrieve_key(password.as_bytes(), &self.repo_name)?;

        let file_params = HashParam {
            key: master_key,
            nonce: blob.nonce,
        };

        let payload = blob.decrypt(&file_params)?;

        cache_key(master_key, password.as_bytes(), &self.repo_name)?;

        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key: master_key,
                payload,
            },
        })
    }

    pub fn local_unlock_cached(self, password: &str) -> Result<Vault<UnlockedVault>> {
        let mut buf = Vec::new();
        let mut cache_file = File::open(self.cache_path.join("cache.dat"))?;
        cache_file.read_to_end(&mut buf)?;

        let blob = from_bytes::<Blob>(&buf)?;
        let master_key = retrieve_key(password.as_bytes(), &self.repo_name)?;

        let file_params = HashParam {
            key: master_key,
            nonce: blob.nonce,
        };

        let payload = blob.decrypt(&file_params)?;

        cache_key(master_key, password.as_bytes(), &self.repo_name)?;

        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key: master_key,
                payload,
            },
        })
    }

    pub async fn init_repo(
        self,
        pat: &str,
        exp_date: i32,
        password: &str,
    ) -> Result<Vault<UnlockedVault>> {
        let mut payload = Payload::new(pat, exp_date)?;

        payload.log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut salt)?;
        rng.try_fill_bytes(&mut nonce)?;

        let master_key = derive_key(password.as_bytes(), salt)?;

        let params = HashParam {
            key: master_key,
            nonce,
        };

        let encrypted_payload = payload.encrypt(&params)?;

        let blob = Blob {
            salt: salt,
            nonce: params.nonce,
            payload_store: encrypted_payload,
        };

        let serialized_blob = to_stdvec(&blob)?;

        fs::write(
            &(self.cache_path.join("cache.dat")),
            serialized_blob.as_slice(),
        )?;

        self.push(serialized_blob.as_slice(), None, pat).await?;

        cache_key(master_key, password.as_bytes(), &self.repo_name)?;

        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key: master_key,
                payload,
            },
        })
    }
}

impl<V> Vault<V>
where
    V: ZeroizeOnDrop + VaultMarker,
{
    async fn fetch(&self) -> Result<Blob> {
        let client = reqwest::Client::builder().build()?;
        let blob_bytes = client
            .get(
                &("https://github.com/".to_string()
                    + &self.repo_name
                    + "/raw/refs/heads/main/vault.dat"),
            )
            .header("Cache-Control", "no-cache, no-store, must-revalidate")
            .send()
            .await?
            .bytes()
            .await?;
        let blob = from_bytes::<Blob>(&blob_bytes.slice(..))?;
        Ok(blob)
    }

    async fn push(&self, data: &[u8], sha: Option<&str>, token: &str) -> Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_str("application/vnd.github+json")?,
        );
        let mut token_header = HeaderValue::from_str(&(format!("Bearer {}", token)))?;
        token_header.set_sensitive(true);
        headers.insert(AUTHORIZATION, token_header);
        headers.insert("X-GitHub-Api-Version", HeaderValue::from_str("2026-03-10")?);
        headers.insert("User-Agent", HeaderValue::from_str("Password Manager App")?);

        let client = reqwest::Client::builder().build()?;

        let body = PushBody {
            message: "Commit Message".to_string(),
            content: STANDARD.encode(data),
            sha: sha.map(|s| s.to_string()),
            committer: Committer::new("Password Manager App", "pmapp@gmail.com"),
            branch: "main".to_string(),
        };

        let res = client
            .put(
                &(format!(
                    "https://api.github.com/repos/{}/contents/vault.dat",
                    &self.repo_name
                )),
            )
            .headers(headers)
            .body(serde_json::to_string(&body)?)
            .send()
            .await?;
        println!("{:?}", res.status());
        Ok(())
    }
}
