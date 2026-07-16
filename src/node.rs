use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _},
    net::SocketAddr,
    path::PathBuf,
};

use clap::Parser;
use tower_abci::BoxError;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use crate::{
    api::{AppState, router},
    consensus::{ChainApplication, PrivateValidatorConfig, serve_abci},
    store::StateStore,
};

#[derive(Parser)]
#[command(author, version, about = "Asteria ABCI blockchain application node")]
pub struct NodeArgs {
    #[arg(long, env = "ASTERIA_ABCI_BIND", default_value = "127.0.0.1:26658")]
    pub abci_bind: SocketAddr,
    #[arg(long, env = "ASTERIA_HTTP_BIND", default_value = "127.0.0.1:8080")]
    pub http_bind: SocketAddr,
    #[arg(long, env = "ASTERIA_DATA", default_value = "data/chain.redb")]
    pub data: PathBuf,
    #[arg(
        long,
        env = "ASTERIA_COMET_RPC",
        default_value = "http://127.0.0.1:26657"
    )]
    pub comet_rpc: String,
    #[arg(
        long,
        env = "ASTERIA_PRIVATE_VALIDATOR_ID",
        value_parser = clap::value_parser!(u16).range(1..=4)
    )]
    pub private_validator_id: Option<u16>,
    #[arg(long, env = "ASTERIA_PRIVATE_KEY_SHARE_FILE")]
    pub private_key_share_file: Option<PathBuf>,
}

pub async fn main_entry() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("asteria=info,tower_http=info")),
        )
        .try_init()
        .ok();
    if let Err(error) = run(NodeArgs::parse()).await {
        eprintln!("asteria-abci: {error}");
        std::process::exit(1);
    }
}

pub async fn run(args: NodeArgs) -> Result<(), BoxError> {
    let NodeArgs {
        abci_bind,
        http_bind,
        data,
        comet_rpc,
        private_validator_id,
        private_key_share_file,
    } = args;
    let store = StateStore::open(&data)?;
    let file_share = private_key_share_file
        .as_deref()
        .map(read_private_key_share)
        .transpose()?;
    let private_validator = match (private_validator_id, file_share.as_deref()) {
        (Some(validator_id), Some(key_share)) => {
            Some(PrivateValidatorConfig::from_hex(validator_id, key_share)?)
        }
        (None, None) => None,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private validator id and key-share file must be configured together",
            )
            .into());
        }
    };
    let (application, chain) =
        ChainApplication::open_with_private_validator(store, private_validator)?;
    let api = router(AppState::new(chain, &comet_rpc)?);
    let listener = tokio::net::TcpListener::bind(http_bind).await?;
    tracing::info!(
        abci_address = %abci_bind,
        http_address = %http_bind,
        comet_rpc = %comet_rpc,
        "Asteria blockchain application starting"
    );

    let http = async move {
        axum::serve(listener, api)
            .await
            .map_err(|error| Box::new(error) as BoxError)
    };
    tokio::try_join!(serve_abci(application, abci_bind), http)?;
    Ok(())
}

fn read_private_key_share(path: &std::path::Path) -> Result<Zeroizing<String>, BoxError> {
    let file = open_private_key_share(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private validator key-share must be a regular non-link file",
        )
        .into());
    }
    validate_private_key_share_permissions(&file, &metadata)?;
    if metadata.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private validator key-share file must contain exactly 64 bytes",
        )
        .into());
    }
    let mut encoded = Zeroizing::new(String::with_capacity(64));
    file.take(65).read_to_string(&mut encoded)?;
    if encoded.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private validator key-share file changed while it was being read",
        )
        .into());
    }
    Ok(encoded)
}

fn open_private_key_share(path: &std::path::Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn validate_private_key_share_permissions(
    file: &File,
    metadata: &std::fs::Metadata,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private validator key-share file is accessible to group or other users",
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_private_key_share(file, metadata)?;
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, metadata);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private validator key-share permissions are unsupported on this platform",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_private_key_share(file: &File, metadata: &std::fs::Metadata) -> io::Result<()> {
    use std::{ffi::c_void, mem::size_of, os::windows::fs::MetadataExt as _, ptr};

    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            SE_DACL_PROTECTED, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
        },
        Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT,
        System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
    };

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private validator key-share must not be a reparse point",
        ));
    }

    use std::os::windows::io::AsRawHandle as _;
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: all output pointers are valid for the call and the returned
    // descriptor is released with LocalFree before this function returns.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    struct LocalDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }
    let _descriptor = LocalDescriptor(descriptor);
    if descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private validator key-share must have an owner and a non-null DACL",
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor remains owned by _descriptor for the duration.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private validator key-share DACL must not inherit permissions",
        ));
    }

    let mut system_sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut system_sid_len = u32::try_from(system_sid.len()).expect("SID buffer length fits u32");
    // SAFETY: the fixed buffer is at least SECURITY_MAX_SID_SIZE bytes.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            ptr::null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut system_sid_len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut acl_info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: dacl and acl_info are valid and descriptor remains alive.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    for index in 0..acl_info.AceCount {
        let mut raw_ace: *mut c_void = ptr::null_mut();
        // SAFETY: index is bounded by the ACE count returned for this DACL.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Only ordinary allow ACEs for the owner or LocalSystem are accepted.
        // Object/callback/unknown ACE layouts are rejected instead of parsed
        // with the wrong SID offset.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private validator key-share DACL contains a non-allow ACE",
            ));
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = ptr::addr_of!(ace.SidStart).cast_mut().cast();
        // SAFETY: ACCESS_ALLOWED_ACE stores a valid SID at SidStart.
        let allowed = unsafe {
            EqualSid(sid, owner) != 0
                || EqualSid(sid, system_sid.as_mut_ptr().cast::<c_void>()) != 0
        };
        if !allowed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private validator key-share DACL grants access to an unexpected principal",
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
    };

    use super::*;

    #[test]
    fn share_reader_rejects_weak_permissions_and_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let share = temporary.path().join("validator.key-share");
        fs::write(&share, "a".repeat(64)).unwrap();
        fs::set_permissions(&share, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private_key_share(&share).unwrap().as_str(),
            "a".repeat(64)
        );

        fs::set_permissions(&share, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private_key_share(&share).is_err());

        fs::set_permissions(&share, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temporary.path().join("validator-link.key-share");
        symlink(&share, &link).unwrap();
        assert!(read_private_key_share(&link).is_err());
    }
}
