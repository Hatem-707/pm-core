use std::{
    io::{Write, stderr, stdin, stdout},
    path::Path,
};

use anyhow::Result;
use pm_core::{UnlockedVault, Vault, LockedVault};
use ssh_key::{PrivateKey, rand_core::OsRng};
use uuid::Uuid;

fn action(vault: &mut Vault<UnlockedVault>) -> Result<()> {
    loop {
        println!("Choose an operation: (Add | Get | View | Logs | Quit)");
        let mut user_state = String::new();
        stdin().read_line(&mut user_state)?;
        if user_state.trim() == "Add" {
            println!("Adding a new password: ");
            print!("Name: ");
            stdout().flush()?;
            let mut name = String::new();
            stdin().read_line(&mut name)?;
            print!("Password: ");
            stdout().flush()?;
            let mut password = String::new();
            stdin().read_line(&mut password)?;
            vault.add_entry(name.trim(), None, None, password.trim(), None);
        } else if user_state.trim() == "Get" {
            println!("Getting password details: ");
            let mut uuid = String::new();
            stdin().read_line(&mut uuid)?;
            let p = vault.get_entry(Uuid::parse_str(uuid.trim())?)?;
            println!("Password is: \n {:#?}", p);
        } else if user_state.trim() == "View" {
            vault
                .get_view()
                .enumerate()
                .for_each(|p| println!("#{}: \n {:#?}", p.0, p.1));
        } else if user_state.trim() == "Logs" {
            vault
                .get_logs()
                .enumerate()
                .for_each(|m| println!("#{}: \n {:#?}", m.0, m.1));
        } else {
            println!("Exitting app");
            break;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cache_path = Path::new("test-dir");
    println!("Enter Repo name: (Formate Username/Repo_name)");
    let mut repo_name = String::new();
    stdin().read_line(&mut repo_name)?;
    println!("Choose an operation: (Init | Fetch | Read)");
    let mut user_state = String::new();
    stdin().read_line(&mut user_state)?;

    if user_state.trim() == "Init" {
        let mut master_key = String::new();
        let mut rng = OsRng;
        let priv_key = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)?;
        println!(
            "Add this public key to your deploy keys. \n {}",
            priv_key.public_key().to_openssh()?
        );
        println!("Enter a new master password: (should be very strong)");
        stdin().read_line(&mut master_key)?;
        let vault = Vault::empty(
            repo_name.trim(),
            Some("hatem laptop"),
            Some("Linux laptop"),
            &cache_path,
        );
        vault.init_repo(
            &priv_key.to_openssh(ssh_key::LineEnding::LF)?,
            &master_key
        )?;
    } else if user_state.trim() == "Fetch" {
        println!("Enter the master password: (must be the same one the repo uses)");
        let mut master_key = String::new();
        stdin().read_line(&mut master_key)?;
        let vault = Vault::empty(
            repo_name.trim(),
            Some("hatem laptop"),
            Some("Linux laptop"),
            &cache_path,
        );
        let mut vault = vault.remote_unlock(&master_key).await?;
        vault.local_sync()?;
        action(&mut vault)?;
        vault.remote_sync()?;
    } else if user_state.trim() == "Read" {
        println!("Enter the master password: (must be the same one the repo uses)");
        let mut master_key = String::new();
        stdin().read_line(&mut master_key)?;
        let vault = Vault::empty(
            repo_name.trim(),
            Some("hatem laptop"),
            Some("Linux laptop"),
            &cache_path,
        );
        let mut vault = vault.local_unlock(&master_key)?;
        action(&mut vault)?;
        vault.local_sync()?;
    } else {
        stderr().write(b"Invalid Option")?;
    }
    Ok(())
}
