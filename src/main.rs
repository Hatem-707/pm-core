use std::{io::stdin, path::Path};

use anyhow::Result;
use pm_core::Vault;
use ssh_key::{PrivateKey, rand_core::OsRng};

#[tokio::main]
async fn main() -> Result<()> {
    // let mut rng = OsRng;
    // let priv_key = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)?;
    // println!(
    //     "Add this public key to the depoly keys in the repo: \n{}",
    //     priv_key.public_key().to_openssh()?
    // );

    println!("Enter the repo name: ");
    let mut repo_name = String::new();
    stdin().read_line(&mut repo_name)?;
    println!("Enter the master key (Should be very strong): ");
    let mut master_key = String::new();
    stdin().read_line(&mut master_key)?;
    let meta_data = MetaData::new(
        repo_name.trim().to_string(),
        Some("My laptop".to_string()),
        Some("Linux desktop".to_string()),
    );

    // let mut vault = Vault::empty(
    //     meta_data,
    //     Path::new("test_dir"),
    //     master_key.trim().to_string(),
    //     &priv_key.to_openssh(ssh_key::LineEnding::LF)?,
    // )?;
    // println!("Enter new password name: ");
    // let mut pwd_name = String::new();
    // stdin().read_line(&mut pwd_name)?;
    // println!("Enter new password: ");
    // let mut pwd_password = String::new();
    // stdin().read_line(&mut pwd_password)?;

    // vault.add_entry(
    //     pwd_name.trim().to_string(),
    //     None,
    //     None,
    //     pwd_password.trim().to_string(),
    //     None,
    // );

    // vault.remote_sync()?;

    // println!("Repo Intialized !!!");

    let mut vault = Vault::from_remote(
        meta_data,
        Path::new("test_dir"),
        master_key.trim().to_string(),
    )
    .await?;

    println!("Enter new password name: ");
    let mut pwd_name = String::new();
    stdin().read_line(&mut pwd_name)?;
    println!("Enter new password: ");
    let mut pwd_password = String::new();
    stdin().read_line(&mut pwd_password)?;

    vault.add_entry(
        pwd_name.trim().to_string(),
        None,
        None,
        pwd_password.trim().to_string(),
        None,
    );

    vault.remote_sync()?;

    Ok(())
}
