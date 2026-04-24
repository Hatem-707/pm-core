#![allow(private_bounds)]
use std::{
    cmp::Ordering,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    str::from_utf8,
    vec::Drain,
};

use anyhow::{Error, Result};
use argon2;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use educe::Educe;
use git2::{
    Commit, Cred, FetchOptions, ObjectType, Oid, PushOptions, RemoteCallbacks, Repository,
    Signature,
};
use postcard::{from_bytes, to_stdvec};
use rand::{TryRng, prelude::*, rngs::SysRng};
use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

static SECURE_PARAMS: Result<argon2::Params, argon2::Error> =
    argon2::Params::new(262_144, 4, 4, None); // 256 MB main encryption

static FAST_PARAMS: Result<argon2::Params, argon2::Error> = argon2::Params::new(65536, 3, 4, None); // 64 MB local encryption 5 times faster

static LOG_MAX_LEN: usize = 1024;
static PRE_ALLOC_SECURE_BUF: bool = true;

fn clone_snapshot(path: &Path, repo_name: &str, priv_key: &str) -> Result<Repository> {
    clone_archive(path, repo_name, 1, priv_key)
}

fn clone_archive(path: &Path, repo_name: &str, depth: i32, priv_key: &str) -> Result<Repository> {
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, _allowed_types| {
        Cred::ssh_key_from_memory(username_from_url.unwrap_or("git"), None, priv_key, None)
    });

    let mut fo = FetchOptions::new();
    fo.remote_callbacks(callbacks);
    fo.depth(depth);

    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fo);

    let repo = builder.clone(&("git@github.com:".to_string() + repo_name + ".git"), path)?;
    Ok(repo)
}

fn find_last_commit(repo: &'_ Repository) -> Result<Commit<'_>, git2::Error> {
    let obj = repo.head()?.resolve()?.peel(ObjectType::Commit)?;
    obj.into_commit()
        .map_err(|_| git2::Error::from_str("Couldn't find commit"))
}

fn add_and_commit(repo: &Repository, path: &Path, message: &str) -> Result<Oid, git2::Error> {
    let mut index = repo.index()?;
    index.add_path(path)?;
    let oid = index.write_tree()?;
    let signature = Signature::now("Password Manager", "pmapp@gmail.com")?;
    let parent_commit = find_last_commit(&repo);
    let tree = repo.find_tree(oid)?;

    match parent_commit {
        Ok(c) => {
            repo.commit(
                Some("HEAD"), //  point HEAD to our new commit
                &signature,   // author
                &signature,   // committer
                message,      // commit message
                &tree,        // tree
                &[&c],        // parents
            )
        }
        Err(_) => {
            repo.commit(
                Some("HEAD"), //  point HEAD to our new commit
                &signature,   // author
                &signature,   // committer
                message,      // commit message
                &tree,        // tree
                &[],          // parents
            )
        }
    }
}

fn ssh_push(repo: &Repository, priv_key: &str) -> Result<()> {
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, _allowed_types| {
        Cred::ssh_key_from_memory(username_from_url.unwrap_or("git"), None, priv_key, None)
    });

    let mut po = PushOptions::new();
    po.remote_callbacks(callbacks);

    repo.find_branch("main", git2::BranchType::Local)
        .inspect_err(|_| {
            let commit = find_last_commit(&repo).unwrap();
            repo.branch("main", &commit, false).unwrap();
        })?;

    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, _allowed_types| {
        Cred::ssh_key_from_memory(username_from_url.unwrap_or("git"), None, priv_key, None)
    });

    let mut remote = repo.find_remote("origin")?;
    remote.connect_auth(git2::Direction::Push, Some(callbacks), None)?;
    remote.push(&["refs/heads/main:refs/heads/main"], Some(&mut po))?;
    Ok(())
}

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

#[derive(ZeroizeOnDrop)]
struct HashParam {
    key: [u8; 32],
    nonce: [u8; 24],
}

impl HashParam {
    pub fn new(password: &[u8], salt: [u8; 16], argon_params: argon2::Params) -> Result<Self> {
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );

        let mut nonce = [0u8; 24];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut nonce)?;

        let mut key = [0; 32];
        argon2
            .hash_password_into(password, &salt, key.as_mut_slice())
            .map_err(|_| Error::msg("Couldn't generate hashing parameters"))?;

        Ok(Self { key, nonce })
    }

    pub fn with_nonce(
        password: &[u8],
        salt: [u8; 16],
        nonce: [u8; 24],
        argon_params: argon2::Params,
    ) -> Result<Self> {
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );

        let mut key = [0; 32];
        argon2
            .hash_password_into(password, &salt, key.as_mut_slice())
            .map_err(|_| Error::msg("Couldn't generate hashing parameters"))?;

        Ok(Self { key, nonce })
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize)]
struct SessionKey {
    hashed_key: Vec<u8>,
    kek: [u8; 32], // key encryption key
    ken: [u8; 24], // key encryption nonce
}

impl SessionKey {
    pub fn new(key: &str) -> Result<Self> {
        let mut rng = SysRng;
        let mut kek = [0u8; 32];
        let mut ken = [0u8; 24];
        rng.try_fill_bytes(&mut kek)?;
        rng.try_fill_bytes(&mut ken)?;

        let cipher = XChaCha20Poly1305::new(&kek.into());
        let hashed_key = cipher.encrypt(&ken.into(), key.as_bytes())?;

        Ok(Self {
            hashed_key,
            kek,
            ken,
        })
    }

    pub fn get_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut plain_key = Zeroizing::new(Vec::<u8>::with_capacity(self.hashed_key.len()));
        let cipher = XChaCha20Poly1305::new(&self.kek.into());
        plain_key.extend(cipher.decrypt(&self.ken.into(), self.hashed_key.as_slice())?);
        Ok(plain_key)
    }
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
        let mut merged;
        match (
            self.buf.len() < self.max_cap,
            other.buf.len() < other.max_cap,
        ) {
            (true, true) => {
                let mut a = self.buf.drain(..);
                let mut b = other.buf.drain(..);
                merged = set_union(&mut a, &mut b, cmp);
            }
            (true, false) => {
                let mut a = self.buf.drain(..);
                let mut b = other.buf.drain(other.write_index..);
                merged = set_union(&mut a, &mut b, &cmp);
                drop(b);
                let mut b = other.buf.drain(..other.write_index);
                merged.extend(set_union(&mut a, &mut b, &cmp));
            }
            (false, true) => {
                let mut a = self.buf.drain(self.write_index..);
                let mut b = other.buf.drain(..);
                merged = set_union(&mut a, &mut b, &cmp);
                drop(a);
                let mut a = self.buf.drain(..self.write_index);
                merged.extend(set_union(&mut a, &mut b, &cmp));
            }
            (false, false) => {
                let mut a = self.buf.drain(self.write_index..);
                let mut b = other.buf.drain(other.write_index..);
                merged = set_union(&mut a, &mut b, &cmp);
                drop(a);
                drop(b);
                let mut a = self.buf.drain(..self.write_index);
                let mut b = other.buf.drain(..other.write_index);
                merged.extend(set_union(&mut a, &mut b, &cmp));
            }
        };

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

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Educe)]
#[educe(Debug)]
struct Payload {
    #[educe(Debug(ignore))]
    priv_key: SessionKey,
    log_history: SecureRingBuf<MetaData>,
    passwords: Vec<PasswordEntry>,
    #[serde(skip_deserializing)]
    #[educe(Debug(ignore))]
    padding: Vec<u8>,
}

impl Payload {
    fn size(&self) -> usize {
        // not counting the padding
        self.priv_key.hashed_key.len()
            + 56
            + self.passwords.len() * size_of::<PasswordEntry>()
            + self
                .passwords
                .iter()
                .map(|a| {
                    a.name.len()
                        + a.url.as_ref().map_or(0, |s| s.len())
                        + a.username.as_ref().map_or(0, |s| s.len())
                        + a.note.as_ref().map_or(0, |s| s.len())
                        + a.password.len()
                })
                .sum::<usize>()
            + size_of::<SecureRingBuf<MetaData>>()
            + self.log_history.buf.len() * size_of::<MetaData>()
    }

    pub fn pad(&mut self) {
        let curr_size = self.size();
        let pad_size = (1 << 20) - curr_size % (1 << 20); // not serilized size but close enough 
        let mut rng = rand::rng();
        self.padding.resize(pad_size, 0);
        rng.fill(self.padding.as_mut_slice());
    }

    pub fn encrypt(&self, params: &HashParam) -> Result<Vec<u8>> {
        let payload_bytes = Zeroizing::new(to_stdvec(&self)?); // TODO change this as it might leak data

        let cipher = XChaCha20Poly1305::new(&params.key.into());
        Ok(cipher.encrypt(&params.nonce.into(), payload_bytes.as_slice())?)
    }

    pub fn new(priv_key: &str) -> Result<Self> {
        Ok(Self {
            priv_key: SessionKey::new(priv_key)?,
            log_history: SecureRingBuf::new(LOG_MAX_LEN),
            passwords: vec![],
            padding: vec![],
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

        // since we are using v7 uuids we can use sorted vector set union algorithm

        let mut a = self.passwords.drain(..);
        let mut b = other.passwords.drain(..);

        let merged_passwords = set_union(&mut a, &mut b, |a, b| {
            match (a.uuid.cmp(&b.uuid), a.last_edit.cmp(&b.last_edit)) {
                (Ordering::Less, _) => Ordering::Less,
                (Ordering::Greater, _) => Ordering::Greater,
                (Ordering::Equal, Ordering::Less) => Ordering::Greater,
                (Ordering::Equal, Ordering::Equal) => Ordering::Equal,
                (Ordering::Equal, Ordering::Greater) => Ordering::Less,
            }
        });

        drop(a);
        drop(b);

        self.passwords.extend(merged_passwords);
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
        from_bytes::<Blob>(&bytes).map_err(|_| Error::msg("Error reading Blob from file"))
    }

    pub fn decrypt(self, params: &HashParam) -> Result<Payload> {
        let cipher = XChaCha20Poly1305::new(&params.key.into());
        let payload_bytes =
            Zeroizing::new(cipher.decrypt(&params.nonce.into(), self.payload_store.as_slice())?);
        let payload = from_bytes::<Payload>(payload_bytes.as_slice())
            .map_err(|_| Error::msg("Couldn't Desrialize decrypted Metadata"))?;
        Ok(payload)
    }
}

pub trait VaultMarker {}

#[derive(ZeroizeOnDrop)]
pub struct LockedVault;

impl VaultMarker for LockedVault {}

#[derive(ZeroizeOnDrop)]
pub struct UnlockedVault {
    session_key: SessionKey,
    payload: Payload,
}

impl VaultMarker for UnlockedVault {}

impl UnlockedVault {
    fn get_session_key(&self) -> &SessionKey {
        &self.session_key
    }

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
            .binary_search_by_key(&uuid, |p| p.uuid);
        match res {
            Ok(i) => {
                self.state.get_payload_mut().passwords[i].edit(
                    name.as_deref().map(|s| s.to_string()),
                    url.as_deref().map(|s| s.to_string()),
                    username.as_deref().map(|s| s.to_string()),
                    password.as_deref().map(|s| s.to_string()),
                    note.as_deref().map(|s| s.to_string()),
                );
                Ok(())
            }
            Err(_) => Err(Error::msg("No matching password")),
        }
    }

    pub fn get_entry(&self, uuid: Uuid) -> Result<&PasswordEntry> {
        let res = self
            .state
            .get_payload()
            .passwords
            .binary_search_by_key(&uuid, |p| p.uuid);
        match res {
            Ok(i) => Ok(&self.state.get_payload().passwords[i]),
            Err(_) => Err(Error::msg("No matching password")),
        }
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

    fn sync(&mut self, file_path: &Path, params: argon2::Params) -> Result<()> {
        if !file_path.is_file() {
            return Err(Error::msg(format!(
                "Vault file doesn't exist {:?}",
                file_path
            )));
        }

        let blob = Blob::from_file(file_path)?;

        let file_params = HashParam::with_nonce(
            &self.state.get_session_key().get_key()?,
            blob.salt,
            blob.nonce,
            params.clone(),
        )?;
        let payload = blob.decrypt(&file_params)?;

        self.state.get_payload_mut().merge(payload);
        self.state.get_payload_mut().log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );

        let mut salt = [0u8; 16];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut salt)?;

        let updated_params =
            HashParam::new(&self.state.get_session_key().get_key()?, salt, params)?;

        self.state.get_payload_mut().pad();
        let encrypted_payload = self.state.get_payload().encrypt(&updated_params)?;

        let blob = Blob {
            salt: salt,
            nonce: updated_params.nonce,
            payload_store: encrypted_payload,
        };

        let serialized_blob = to_stdvec(&blob)?;

        fs::write(file_path, serialized_blob.as_slice())?;
        Ok(())
    }

    pub fn remote_sync(&mut self) -> Result<()> {
        let repo_offset = "repo";

        let repo = clone_snapshot(
            &(self.cache_path.join(repo_offset)),
            &self.repo_name,
            from_utf8(&self.state.get_payload().priv_key.get_key()?)?,
        )?;

        self.sync(
            &(self.cache_path.join(repo_offset).join("vault.dat")),
            SECURE_PARAMS.clone().unwrap(),
        )?;

        add_and_commit(&repo, Path::new("vault.dat"), "Commit Message")?;
        ssh_push(
            &repo,
            from_utf8(&self.state.get_payload().priv_key.get_key()?)?,
        )?;
        Ok(())
    }

    pub fn local_sync(&mut self) -> Result<()> {
        self.sync(
            &(self.cache_path.join("cache.dat")),
            FAST_PARAMS.clone().unwrap(),
        )?;
        Ok(())
    }
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

    pub async fn remote_unlock(self, master_key: &str) -> Result<Vault<UnlockedVault>> {
        let session_key = SessionKey::new(master_key)?;
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

        let file_params = HashParam::with_nonce(
            &session_key.get_key()?,
            blob.salt,
            blob.nonce,
            SECURE_PARAMS.clone().unwrap(),
        )?;

        let payload = blob.decrypt(&file_params)?;

        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key,
                payload,
            },
        })
    }

    pub fn local_unlock(self, master_key: &str) -> Result<Vault<UnlockedVault>> {
        let session_key = SessionKey::new(master_key)?;
        let mut buf = Vec::new();
        let mut cache_file = File::open(self.cache_path.join("cache.dat"))?;
        cache_file.read_to_end(&mut buf)?;

        let blob = from_bytes::<Blob>(&buf)?;
        let file_params = HashParam::with_nonce(
            &session_key.get_key()?,
            blob.salt,
            blob.nonce,
            FAST_PARAMS.clone().unwrap(),
        )?;

        let payload = blob.decrypt(&file_params)?;
        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key,
                payload,
            },
        })
    }

    pub fn init_repo(self, priv_key: &str, master_key: &str) -> Result<Vault<UnlockedVault>> {
        let repo_offset = "repo";

        let repo = clone_snapshot(
            &(self.cache_path.join(repo_offset)),
            &self.repo_name,
            priv_key,
        )?;

        let mut payload = Payload::new(priv_key)?;

        payload.log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );

        let mut salt = [0u8; 16];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut salt)?;

        let remote_params =
            HashParam::new(master_key.as_bytes(), salt, SECURE_PARAMS.clone().unwrap())?;

        let local_params =
            HashParam::new(master_key.as_bytes(), salt, FAST_PARAMS.clone().unwrap())?;

        let encrypted_payload = payload.encrypt(&remote_params)?;

        let remote_blob = Blob {
            salt: salt,
            nonce: remote_params.nonce,
            payload_store: encrypted_payload,
        };

        let encrypted_payload = payload.encrypt(&local_params)?;

        let local_blob = Blob {
            salt: salt,
            nonce: local_params.nonce,
            payload_store: encrypted_payload,
        };

        fs::write(
            &(self.cache_path.join("cache.dat")),
            to_stdvec(&local_blob)?.as_slice(),
        )?;

        fs::write(
            &(self.cache_path.join(&repo_offset).join("vault.dat")),
            to_stdvec(&remote_blob)?.as_slice(),
        )?;

        add_and_commit(&repo, Path::new("vault.dat"), "Commit Message")?;
        ssh_push(&repo, priv_key)?;

        let session_key = SessionKey::new(master_key)?;
        Ok(Vault {
            repo_name: self.repo_name,
            device_name: self.device_name,
            device_type: self.device_type,
            cache_path: self.cache_path,
            state: UnlockedVault {
                session_key,
                payload,
            },
        })
    }
}
