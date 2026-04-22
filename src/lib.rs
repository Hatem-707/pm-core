use std::{
    backtrace,
    cmp::Ordering,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
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
    argon2::Params::new(262_144, 4, 1, None); // 256 MB main encryption

static LOG_MAX_LEN: usize = 1024;
static PRE_ALLOC_SECURE_BUF: bool = true;

fn clear_dir(dir_path: &Path) -> Result<()> {
    if !dir_path.exists() {
        return Ok(());
    }
    if !dir_path.is_dir() {
        return Err(Error::msg("Path isn't a vaild directory"));
    }
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn clone_snapshot(path: &Path, repo_name: &str, priv_key: &str) -> Result<Repository> {
    clone_archive(path, repo_name, 1, priv_key)
}

fn clone_archive(path: &Path, repo_name: &str, depth: i32, priv_key: &str) -> Result<Repository> {
    clear_dir(path)?;
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

#[derive(ZeroizeOnDrop)]
struct HashParam {
    key: [u8; 32],
    nonce: [u8; 24],
}

impl HashParam {
    pub fn from_password(
        password: &str,
        salt: &[u8],
        argon_params: argon2::Params,
    ) -> Result<Self> {
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );
        let mut output_key_material: Zeroizing<[u8; 56]> = Zeroizing::new([0; 56]);
        argon2
            .hash_password_into(
                password.as_bytes(),
                salt,
                output_key_material.as_mut_slice(),
            )
            .map_err(|_| Error::msg("Couldn't generate hashing parameters"))?;
        let (key, nonce): ([u8; 32], [u8; 24]) = {
            let (l, r) = output_key_material.split_at(32);
            (l.try_into().unwrap(), r.try_into().unwrap())
        };
        Ok(Self { key, nonce })
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
            (self.write_index + 1) % self.max_cap
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
    // fills the buf whith the largest max_cap items w.r.t cmp
    where
        F: Fn(&T, &T) -> Ordering,
    {
        let mut merged = Vec::<T>::with_capacity(self.buf.len() + other.buf.len());
        let mut a = self.buf.drain(..);
        let mut b = other.buf.drain(..);
        merged.extend(&mut a);
        merged.extend(&mut b);
        merged.sort_by(cmp);
        drop(a);
        drop(b);
        let start = std::cmp::max(0, merged.len() - self.max_cap);
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
        if self.count < self.ref_buf.max_cap {
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
        PasswordView::new(&self.uuid, &self.name, (&self.url).as_deref())
    }
}

pub struct PasswordView<'a> {
    pub uuid: &'a Uuid,
    pub name: &'a str,
    pub url: Option<&'a str>,
}

impl<'a> PasswordView<'a> {
    pub fn new(uuid: &'a Uuid, name: &'a str, url: Option<&'a str>) -> Self {
        Self { uuid, name, url }
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Educe)]
#[educe(Debug)]
struct Payload {
    priv_key: String,
    log_history: SecureRingBuf<MetaData>,
    passwords: Vec<PasswordEntry>,
    #[serde(skip_deserializing)]
    #[educe(Debug(ignore))]
    padding: Vec<u8>,
}

impl Payload {
    fn size(&self) -> usize {
        // not counting the padding
        self.priv_key.len()
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

    fn pad(&mut self) {
        let curr_size = self.size();
        let pad_size = curr_size - curr_size % (1 << 20); // not serilized size but close enough 
        let mut rng = rand::rng();
        self.padding.resize(pad_size, 0);
        rng.fill(self.padding.as_mut_slice());
    }

    pub fn encrypt(&mut self, password: &str, salt: &[u8]) -> Result<Vec<u8>> {
        self.pad();
        let payload_bytes = Zeroizing::new(to_stdvec(&self)?); // TODO change this as it might leak data

        let hash_param = HashParam::from_password(password, salt, SECURE_PARAMS.clone().unwrap())?;

        let cipher = XChaCha20Poly1305::new(&hash_param.key.into());
        Ok(cipher.encrypt(&hash_param.nonce.into(), payload_bytes.as_slice())?)
    }

    pub fn new(key: String) -> Self {
        Self {
            priv_key: key,
            log_history: SecureRingBuf::new(LOG_MAX_LEN),
            passwords: vec![],
            padding: vec![],
        }
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

        let mut merged_passwords =
            Vec::<PasswordEntry>::with_capacity(self.passwords.len() + other.passwords.len());

        let mut a = self.passwords.drain(..);
        let mut b = other.passwords.drain(..);

        let mut curr_a = a.next();
        let mut curr_b = b.next();

        loop {
            match (curr_a, curr_b) {
                (Some(ele_a), Some(ele_b)) => {
                    if ele_a.uuid < ele_b.uuid {
                        merged_passwords.push(ele_a);
                        curr_a = a.next();
                        curr_b = Some(ele_b);
                    } else if ele_a.uuid == ele_b.uuid {
                        if ele_a.last_edit >= ele_b.last_edit {
                            merged_passwords.push(ele_a);
                        } else {
                            merged_passwords.push(ele_b);
                        }
                        curr_a = a.next();
                        curr_b = b.next();
                    } else {
                        merged_passwords.push(ele_b);
                        curr_a = Some(ele_a);
                        curr_b = b.next();
                    }
                }
                (Some(ele), None) => {
                    merged_passwords.push(ele);
                    merged_passwords.extend(&mut a);
                    break;
                }
                (None, Some(ele)) => {
                    merged_passwords.push(ele);
                    merged_passwords.extend(&mut b);
                    break;
                }
                _ => break,
            }
        }

        drop(a);
        drop(b);
        self.passwords.append(&mut merged_passwords);
    }
}

#[derive(Serialize, Deserialize)]
struct Blob {
    salt: [u8; 16],
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

    pub fn decrypt(self, password: &str) -> Result<Payload> {
        let payload_params =
            HashParam::from_password(password, &self.salt, SECURE_PARAMS.clone().unwrap())?;
        let cipher = XChaCha20Poly1305::new(&payload_params.key.into());
        let payload_bytes = Zeroizing::new(
            cipher.decrypt(&payload_params.nonce.into(), self.payload_store.as_slice())?,
        );
        let payload = from_bytes::<Payload>(payload_bytes.as_slice())
            .map_err(|_| Error::msg("Couldn't Desrialize decrypted Metadata"))?;
        Ok(payload)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Vault {
    repo_name: String,
    device_name: Option<String>,
    device_type: Option<String>,
    #[zeroize(skip)]
    cache_path: PathBuf,
    master_key: String,
    payload: Payload,
}

impl Vault {
    pub fn from_local(
        device_name: Option<&str>,
        device_type: Option<&str>,
        path: &Path,
        master_key: String,
    ) -> Result<Self> {
        let blob = Blob::from_file(&path.join("cache.dat"))?;
        let payload = blob.decrypt(&master_key)?;
        let Some(last_meta) = payload.log_history.iter().last() else {
            return Err(Error::msg("No Metadate to retrive repo name."));
        };
        Ok(Self {
            device_name: device_name.map(|s| s.to_string()),
            device_type: device_type.map(|s| s.to_string()),
            cache_path: path.to_path_buf(),
            repo_name: last_meta.repo_name.to_string(),
            master_key,
            payload,
        })
    }

    pub fn from_local_with_repo_name(
        repo_name: &str,
        device_name: Option<&str>,
        device_type: Option<&str>,
        path: &Path,
        master_key: String,
    ) -> Result<Self> {
        let blob = Blob::from_file(&path.join("cache.dat"))?;
        let payload = blob.decrypt(&master_key)?;

        Ok(Self {
            device_name: device_name.map(|s| s.to_string()),
            device_type: device_type.map(|s| s.to_string()),
            cache_path: path.to_path_buf(),
            repo_name: repo_name.to_string(),
            master_key,
            payload,
        })
    }

    pub async fn from_remote(
        repo_name: &str,
        device_name: Option<&str>,
        device_type: Option<&str>,
        path: &Path,
        master_key: String,
    ) -> Result<Self> {
        let blob_bytes = reqwest::get(
            &("https://github.com/".to_string() + repo_name + "/raw/refs/heads/main/vault.dat"),
        )
        .await?
        .bytes()
        .await?;
        let blob = from_bytes::<Blob>(&blob_bytes.slice(..))?;
        let payload = blob.decrypt(&master_key)?;

        Ok(Self {
            device_name: device_name.map(|s| s.to_string()),
            device_type: device_type.map(|s| s.to_string()),
            cache_path: path.to_path_buf(),
            repo_name: repo_name.to_string(),
            master_key,
            payload,
        })
    }

    pub fn empty(
        repo_name: &str,
        device_name: Option<&str>,
        device_type: Option<&str>,
        path: &Path,
        master_key: String,
        priv_key: &str,
    ) -> Result<Self> {
        Ok(Self {
            device_name: device_name.map(|s| s.to_string()),
            device_type: device_type.map(|s| s.to_string()),
            cache_path: path.to_path_buf(),
            repo_name: repo_name.to_string(),
            master_key,
            payload: Payload::new(priv_key.to_string()),
        })
    }

    pub fn add_entry(
        &mut self,
        name: &str,
        url: Option<&str>,
        username: Option<&str>,
        password: &str,
        note: Option<&str>,
    ) {
        self.payload.passwords.push(PasswordEntry::new(
            name.to_string(),
            url.as_deref().map(|s| s.to_string()),
            username.as_deref().map(|s| s.to_string()),
            password.to_string(),
            note.as_deref().map(|s| s.to_string()),
        ));

        self.payload.log(
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
            .payload
            .passwords
            .binary_search_by_key(&uuid, |p| p.uuid);
        match res {
            Ok(i) => {
                self.payload.passwords[i].edit(
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

    pub fn retrive_entry(&self, uuid: Uuid) -> Result<&PasswordEntry> {
        let res = self
            .payload
            .passwords
            .binary_search_by_key(&uuid, |p| p.uuid);
        match res {
            Ok(i) => Ok(&self.payload.passwords[i]),
            Err(_) => Err(Error::msg("No matching password")),
        }
    }

    pub fn get_logs(&self) -> impl Iterator<Item = &MetaData> {
        self.payload.log_history.iter()
    }

    pub fn get_view_iterator<'a>(&'a self) -> impl Iterator<Item = PasswordView<'a>> {
        self.payload.passwords.iter().map(|p| p.view())
    }

    pub fn import_csv() {
        todo!()
    }

    pub fn export_csv() {
        todo!()
    }

    pub fn remote_sync(&mut self) -> Result<()> {
        let repo_offset = "repo";

        let repo = clone_snapshot(
            &(self.cache_path.join(repo_offset)),
            &self.repo_name,
            &self.payload.priv_key,
        )?;

        let remote_blob = Blob::from_file(&(self.cache_path.join(repo_offset).join("vault.dat")))?;

        let remote_payload = remote_blob.decrypt(&self.master_key)?;

        self.payload.merge(remote_payload);
        self.payload.log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );

        let mut salt = [0u8; 16];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut salt)?;

        let encrypted_payload = self.payload.encrypt(&self.master_key, &salt)?;

        let blob = Blob {
            salt: salt,
            payload_store: encrypted_payload,
        };

        let serialized_blob = to_stdvec(&blob)?;

        fs::write(
            &(self.cache_path.join("cache.dat")),
            serialized_blob.as_slice(),
        )?;

        fs::write(
            &(self.cache_path.join(&repo_offset).join("vault.dat")),
            serialized_blob.as_slice(),
        )?;

        add_and_commit(&repo, Path::new("vault.dat"), "Commit Message")?;
        ssh_push(&repo, &self.payload.priv_key)?;
        Ok(())
    }

    pub fn local_sync(&mut self) -> Result<()> {
        let blob = Blob::from_file(&(self.cache_path.join("cache.dat")))?;
        let local_payload = blob.decrypt(&self.master_key)?;
        self.payload.merge(local_payload);
        Ok(())
    }

    pub fn update_local_cache(&mut self) -> Result<()> {
        self.payload.log(
            &self.repo_name,
            self.device_name.as_deref(),
            self.device_type.as_deref(),
        );

        let mut salt = [0u8; 16];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut salt)?;

        let encrypted_payload = self.payload.encrypt(&self.master_key, &salt)?;

        let blob = Blob {
            salt: salt,
            payload_store: encrypted_payload,
        };

        let serialized_blob = to_stdvec(&blob)?;
        fs::write(
            &(self.cache_path.join("cache.dat")),
            serialized_blob.as_slice(),
        )?;
        Ok(())
    }
}
