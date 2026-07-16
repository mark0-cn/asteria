//! Offline localnet provisioning for Asteria's 3-of-4 private-order key set.
//!
//! Secret shares are written only to owner-restricted files. This binary never
//! prints them and deliberately has no option to return them on stdout.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use asteria::private_order::{
    PRIVATE_ORDER_VALIDATOR_COUNT, ThresholdPublicKeySet, ValidatorSecretShare,
};
use asteria::threshold_dkg::{
    DKG_PARTICIPANTS, DkgKind, DkgSession, FinalizedParticipant, Round1Message, Round2Message,
    derive_dkg_chain_domain, participant_finalize, participant_round1, participant_round2,
};
use clap::Parser;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

const PUBLIC_KEY_SET_FILE: &str = "public-key-set.json";
const DKG_SESSION_FILE: &str = "dkg-session.json";

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Provision a FROST DKG-backed Asteria private-order localnet key set"
)]
struct Args {
    /// A new output directory, or an existing complete directory to validate
    /// and reuse without changing any key material.
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value_t = 1)]
    epoch: u64,
    #[arg(long, default_value = "asteria-localnet-1")]
    chain_id: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    provision_directory(&args.output_dir, args.epoch, &args.chain_id)
}

fn provision_directory(output_dir: &Path, epoch: u64, chain_id: &str) -> Result<()> {
    let output_dir = absolute_path(output_dir)?;
    let chain_domain = derive_dkg_chain_domain(chain_id)?;
    if output_dir.exists() {
        validate_existing_directory(&output_dir, epoch, chain_domain)?;
        return Ok(());
    }

    let parent = output_dir
        .parent()
        .context("private-order output directory must have a parent")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create provisioning parent '{}'",
            parent.display()
        )
    })?;
    let file_name = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("private-order output directory must have a UTF-8 final component")?;
    let staging = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    create_private_directory(&staging)?;

    let result = (|| {
        let mut ceremony_id = [0_u8; 32];
        OsRng.fill_bytes(&mut ceremony_id);
        let session = DkgSession::initial(chain_domain, ceremony_id, epoch)?;
        let participants = generate_frost_material(&session)?;
        let public_keys = participants
            .first()
            .context("private-order DKG produced no participants")?
            .public_keys();
        write_dkg_session(&staging, &session)?;
        write_public_key_set(&staging, public_keys)?;
        for participant in &participants {
            write_secret_share(&staging, participant.secret_share())?;
        }
        validate_existing_directory(&staging, epoch, chain_domain)?;
        fs::rename(&staging, &output_dir).with_context(|| {
            format!(
                "failed to publish private-order provisioning directory '{}'",
                output_dir.display()
            )
        })?;
        Ok(())
    })();

    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn generate_frost_material(session: &DkgSession) -> Result<Vec<FinalizedParticipant>> {
    let mut round1_states = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
    let mut round1_messages: Vec<Round1Message> = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
    for validator_id in 1..=DKG_PARTICIPANTS {
        let (state, message) = participant_round1(session, validator_id, &mut OsRng)
            .map_err(|error| anyhow::anyhow!("private-order DKG round one failed: {error}"))?;
        round1_states.push(state);
        round1_messages.push(message);
    }

    let mut round2_states = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
    let mut round2_messages: Vec<Round2Message> =
        Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT * (PRIVATE_ORDER_VALIDATOR_COUNT - 1));
    for state in round1_states {
        let incoming = round1_messages
            .iter()
            .filter(|message| message.sender_id != state.validator_id())
            .cloned()
            .collect::<Vec<_>>();
        let (state, outgoing) = participant_round2(state, &incoming)
            .map_err(|error| anyhow::anyhow!("private-order DKG round two failed: {error}"))?;
        round2_states.push(state);
        round2_messages.extend(outgoing);
    }

    let mut participants = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
    for state in round2_states {
        let incoming = round2_messages
            .iter()
            .filter(|message| message.recipient_id == state.validator_id())
            .cloned()
            .collect::<Vec<_>>();
        participants.push(
            participant_finalize(state, &incoming).map_err(|error| {
                anyhow::anyhow!("private-order DKG finalization failed: {error}")
            })?,
        );
    }
    let expected_public_keys = participants
        .first()
        .context("private-order DKG produced no participants")?
        .public_keys();
    ensure!(
        participants
            .iter()
            .all(|participant| participant.public_keys() == expected_public_keys),
        "private-order DKG participants derived different epoch key sets"
    );
    Ok(participants)
}

fn validate_existing_directory(
    output_dir: &Path,
    epoch: u64,
    chain_domain: [u8; 32],
) -> Result<()> {
    let metadata = fs::symlink_metadata(output_dir).with_context(|| {
        format!(
            "failed to inspect provisioning directory '{}'",
            output_dir.display()
        )
    })?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "provisioning output must be a real directory"
    );
    let expected_names: BTreeSet<_> = [
        PUBLIC_KEY_SET_FILE.to_string(),
        DKG_SESSION_FILE.to_string(),
    ]
    .into_iter()
    .chain((1..=PRIVATE_ORDER_VALIDATOR_COUNT).map(secret_share_file_name))
    .collect();
    let actual_names: BTreeSet<_> = fs::read_dir(output_dir)?
        .map(|entry| {
            let entry = entry?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("provisioning directory contains a non-UTF-8 name"))
        })
        .collect::<Result<_>>()?;
    ensure!(
        actual_names == expected_names,
        "provisioning directory is incomplete or contains unexpected files"
    );

    let session_path = output_dir.join(DKG_SESSION_FILE);
    ensure_regular_file(&session_path, false)?;
    let session_bytes = fs::read(&session_path)?;
    let session: DkgSession = serde_json::from_slice(&session_bytes)
        .context("private-order DKG session is not valid JSON")?;
    ensure!(
        serde_jcs::to_vec(&session)? == session_bytes,
        "private-order DKG session is not canonical JSON"
    );
    ensure!(
        session.chain_domain == chain_domain,
        "existing private-order DKG session targets another chain"
    );
    ensure!(
        session.epoch == epoch && matches!(session.kind, DkgKind::Initial),
        "existing private-order DKG session does not match the requested initial epoch"
    );
    ensure!(
        DkgSession::initial(session.chain_domain, session.ceremony_id, session.epoch)? == session,
        "existing private-order DKG session is malformed"
    );

    let public_path = output_dir.join(PUBLIC_KEY_SET_FILE);
    ensure_regular_file(&public_path, false)?;
    let public_bytes = fs::read(&public_path)?;
    let public_keys: ThresholdPublicKeySet = serde_json::from_slice(&public_bytes)
        .context("public private-order key set is not valid JSON")?;
    ensure!(
        serde_jcs::to_vec(&public_keys)? == public_bytes,
        "public private-order key set is not canonical JSON"
    );
    public_keys.validate()?;
    ensure!(
        public_keys.epoch == epoch,
        "existing private-order key epoch does not match the requested epoch"
    );

    for validator_id in 1..=PRIVATE_ORDER_VALIDATOR_COUNT {
        let path = output_dir.join(secret_share_file_name(validator_id));
        ensure_regular_file(&path, true)?;
        let mut encoded = fs::read_to_string(&path)
            .with_context(|| format!("failed to read validator {validator_id} share"))?;
        ensure!(
            encoded.len() == 64
                && encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "validator {validator_id} share is not 32-byte lowercase hex"
        );
        let mut decoded = hex::decode(&encoded)
            .with_context(|| format!("validator {validator_id} share is malformed"))?;
        let scalar = secret_fixed_32(&mut decoded, "validator signing share")?;
        let imported = ValidatorSecretShare::from_provisioned_scalar(
            &public_keys,
            u16::try_from(validator_id)?,
            scalar,
        )?;
        drop(imported);
        encoded.zeroize();
    }
    Ok(())
}

fn write_dkg_session(output_dir: &Path, session: &DkgSession) -> Result<()> {
    let bytes = serde_jcs::to_vec(session)?;
    write_new_file(&output_dir.join(DKG_SESSION_FILE), &bytes, false)
}

fn write_public_key_set(output_dir: &Path, public_keys: &ThresholdPublicKeySet) -> Result<()> {
    let bytes = serde_jcs::to_vec(public_keys)?;
    write_new_file(&output_dir.join(PUBLIC_KEY_SET_FILE), &bytes, false)
}

fn write_secret_share(output_dir: &Path, secret_share: &ValidatorSecretShare) -> Result<()> {
    let validator_id = usize::from(secret_share.validator_id());
    let mut scalar = secret_share.export_scalar_for_provisioning();
    let mut encoded = hex::encode(scalar);
    scalar.zeroize();
    let result = write_new_file(
        &output_dir.join(secret_share_file_name(validator_id)),
        encoded.as_bytes(),
        true,
    );
    encoded.zeroize();
    result
}

fn write_new_file(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create provisioning file '{}'", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if secret {
        restrict_secret_permissions(path)?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

fn restrict_secret_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn ensure_regular_file(path: &Path, secret: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("missing provisioning file '{}'", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "provisioning path '{}' must be a regular file",
        path.display()
    );
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "secret share file '{}' is accessible to group or other users",
            path.display()
        );
    }
    #[cfg(not(unix))]
    let _ = secret;
    Ok(())
}

fn secret_share_file_name(validator_id: usize) -> String {
    format!("node{}.key-share", validator_id - 1)
}

fn secret_fixed_32(bytes: &mut Vec<u8>, label: &str) -> Result<[u8; 32]> {
    ensure!(
        bytes.len() == 32,
        "{label} is {} bytes, expected 32",
        bytes.len()
    );
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(bytes);
    bytes.zeroize();
    Ok(scalar)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_directory_is_complete_valid_and_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("private-order");
        provision_directory(&output, 7, "asteria-keygen-test").unwrap();
        let before = fs::read(output.join(PUBLIC_KEY_SET_FILE)).unwrap();
        let session: DkgSession =
            serde_json::from_slice(&fs::read(output.join(DKG_SESSION_FILE)).unwrap()).unwrap();
        assert_eq!(
            session.chain_domain,
            derive_dkg_chain_domain("asteria-keygen-test").unwrap()
        );
        assert_ne!(session.ceremony_id, [0; 32]);
        provision_directory(&output, 7, "asteria-keygen-test").unwrap();
        assert_eq!(fs::read(output.join(PUBLIC_KEY_SET_FILE)).unwrap(), before);
        let domain = derive_dkg_chain_domain("asteria-keygen-test").unwrap();
        validate_existing_directory(&output, 7, domain).unwrap();
        assert!(validate_existing_directory(&output, 8, domain).is_err());
        assert!(provision_directory(&output, 7, "another-chain").is_err());
    }

    #[test]
    fn partial_directory_is_refused_without_regeneration() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("private-order");
        fs::create_dir(&output).unwrap();
        fs::File::create(output.join(PUBLIC_KEY_SET_FILE)).unwrap();
        assert!(provision_directory(&output, 1, "asteria-keygen-test").is_err());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    }
}
