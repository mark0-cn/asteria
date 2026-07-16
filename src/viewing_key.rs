//! Root-backed viewing-key derivation and rotation boundary.
//!
//! This module deliberately does not persist or transport wallet secrets. A
//! caller supplies a root key from its own custody/recovery mechanism; the
//! resolver derives bounded epoch keys and returns them in `Zeroizing`
//! containers for the authenticated viewing cipher.

use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::shielded_margin::{
    EncryptedViewingPayload, Hash, NoteOpening, PublicNote, Result, ShieldedMarginError,
    ViewingKeyAad, ViewingKeyEpoch, ViewingKeyResolver, XChaChaViewingKeyCipher,
};

/// Maximum number of epoch keys retained by one resolver.
pub const MAX_VIEWING_KEY_RETENTION: usize = 1_024;

const ROOT_KDF_SALT: &[u8] = b"ASTERIA_VIEWING_KEY_ROOT_KDF_V1\0";
const ROOT_KDF_INFO: &[u8] = b"ASTERIA_VIEWING_KEY_EPOCH_V1\0";
const ROOT_FINGERPRINT_DOMAIN: &[u8] = b"ASTERIA_VIEWING_KEY_ROOT_FINGERPRINT_V1\0";
const ROOT_FINGERPRINT_VERSION: u16 = 1;

/// Resolver backed by one wallet root key.
///
/// The root is held in a `Zeroizing` allocation and is never serialized or
/// included in `Debug`. Epoch keys are derived on demand, so rotating the
/// current epoch does not duplicate long-lived secret material in the struct.
pub struct DerivedViewingKeyResolver {
    root: Zeroizing<Hash>,
    current_epoch: ViewingKeyEpoch,
    retention_epochs: usize,
    root_fingerprint: Hash,
}

impl fmt::Debug for DerivedViewingKeyResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedViewingKeyResolver")
            .field("root", &"<redacted>")
            .field("current_epoch", &self.current_epoch)
            .field("retention_epochs", &self.retention_epochs)
            .field("root_fingerprint", &hex::encode(self.root_fingerprint))
            .finish()
    }
}

impl DerivedViewingKeyResolver {
    /// Creates a resolver at `current_epoch` with the requested history window.
    pub fn new(
        root: Hash,
        current_epoch: ViewingKeyEpoch,
        retention_epochs: usize,
    ) -> Result<Self> {
        Self::from_zeroizing_root(Zeroizing::new(root), current_epoch, retention_epochs)
    }

    /// Creates a resolver without making an additional non-zeroizing root-key
    /// copy at this API boundary.
    pub fn from_zeroizing_root(
        root: Zeroizing<Hash>,
        current_epoch: ViewingKeyEpoch,
        retention_epochs: usize,
    ) -> Result<Self> {
        validate_root(&root)?;
        validate_retention(retention_epochs)?;
        let root_fingerprint = fingerprint_for_root(&root)?;
        let resolver = Self {
            root,
            current_epoch,
            retention_epochs,
            root_fingerprint,
        };
        // Exercise the exact derivation path at construction so malformed
        // parameters fail before the resolver is handed to a cipher.
        let _ = resolver.derive_epoch_key(current_epoch)?;
        Ok(resolver)
    }

    /// Creates a resolver at epoch zero.
    pub fn from_root(root: Hash, retention_epochs: usize) -> Result<Self> {
        Self::new(root, ViewingKeyEpoch::new(0), retention_epochs)
    }

    /// Reconstructs a resolver after root recovery, checking an out-of-band
    /// fingerprint before any derived key is made available.
    pub fn from_recovered_root(
        root: Hash,
        current_epoch: ViewingKeyEpoch,
        retention_epochs: usize,
        expected_fingerprint: Hash,
    ) -> Result<Self> {
        Self::from_recovered_zeroizing_root(
            Zeroizing::new(root),
            current_epoch,
            retention_epochs,
            expected_fingerprint,
        )
    }

    /// Recovery variant that keeps ownership of the supplied root inside a
    /// zeroizing container for both success and error paths.
    pub fn from_recovered_zeroizing_root(
        root: Zeroizing<Hash>,
        current_epoch: ViewingKeyEpoch,
        retention_epochs: usize,
        expected_fingerprint: Hash,
    ) -> Result<Self> {
        let actual = fingerprint_for_root(&root)?;
        if !bool::from(actual.ct_eq(&expected_fingerprint)) {
            return Err(ShieldedMarginError::ViewingCipherAuthentication);
        }
        Self::from_zeroizing_root(root, current_epoch, retention_epochs)
    }

    /// Computes the public fingerprint for this resolver's root.
    pub fn root_fingerprint(&self) -> Hash {
        self.root_fingerprint
    }

    /// Computes a public fingerprint for a candidate root without retaining it.
    pub fn fingerprint_for_root(root: &Hash) -> Result<Hash> {
        fingerprint_for_root(root)
    }

    pub const fn current_epoch(&self) -> ViewingKeyEpoch {
        self.current_epoch
    }

    pub const fn retention_epochs(&self) -> usize {
        self.retention_epochs
    }

    /// Returns the oldest epoch still available under the retention policy.
    pub fn oldest_retained_epoch(&self) -> ViewingKeyEpoch {
        let retained_before = u32::try_from(self.retention_epochs - 1)
            .expect("validated viewing-key retention fits u32");
        ViewingKeyEpoch::new(self.current_epoch.0.saturating_sub(retained_before))
    }

    pub fn is_epoch_retained(&self, epoch: ViewingKeyEpoch) -> bool {
        epoch >= self.oldest_retained_epoch() && epoch <= self.current_epoch
    }

    /// Encrypts one canonical note opening with chain, ledger, market, asset,
    /// commitment, and current key epoch bound into the AEAD context.
    pub fn seal_note_opening(
        &self,
        chain_domain: Hash,
        ledger_id: Hash,
        note: PublicNote,
        opening: &NoteOpening,
    ) -> Result<EncryptedViewingPayload> {
        if opening.commitment(note.market_id, note.collateral_asset) != note.commitment {
            return Err(ShieldedMarginError::CommitmentMismatch);
        }
        let aad =
            ViewingKeyAad::for_note_opening(chain_domain, ledger_id, self.current_epoch, note)?;
        let plaintext = Zeroizing::new(opening.to_canonical_bytes()?);
        XChaChaViewingKeyCipher.seal_with_resolver(self, &aad, &plaintext)
    }

    /// Decrypts and revalidates one note opening using the payload's retained
    /// historical epoch. A payload that authenticates but opens a different
    /// commitment is still rejected.
    pub fn open_note_opening(
        &self,
        chain_domain: Hash,
        ledger_id: Hash,
        note: PublicNote,
        payload: &EncryptedViewingPayload,
    ) -> Result<NoteOpening> {
        let aad =
            ViewingKeyAad::for_note_opening(chain_domain, ledger_id, payload.key_epoch, note)?;
        let plaintext = XChaChaViewingKeyCipher.open_with_resolver(self, &aad, payload)?;
        let opening = NoteOpening::from_canonical_bytes(&plaintext)?;
        if opening.commitment(note.market_id, note.collateral_asset) != note.commitment {
            return Err(ShieldedMarginError::CommitmentMismatch);
        }
        Ok(opening)
    }

    /// Advances by one epoch, returning the new current epoch.
    pub fn rotate(&mut self) -> Result<ViewingKeyEpoch> {
        let next = self.current_epoch.next()?;
        self.current_epoch = next;
        Ok(next)
    }

    /// Advances to a later epoch. Rollback is rejected so an operator cannot
    /// accidentally re-enable an expired key window.
    pub fn rotate_to(&mut self, epoch: ViewingKeyEpoch) -> Result<ViewingKeyEpoch> {
        if epoch <= self.current_epoch {
            return Err(ShieldedMarginError::ViewingKeyEpochMismatch);
        }
        self.current_epoch = epoch;
        Ok(epoch)
    }

    fn derive_epoch_key(&self, epoch: ViewingKeyEpoch) -> Result<Zeroizing<Hash>> {
        if !self.is_epoch_retained(epoch) {
            return Err(ShieldedMarginError::ViewingKeyEpochUnavailable(epoch.0));
        }
        derive_epoch_key(&self.root, epoch)
    }
}

impl ViewingKeyResolver for DerivedViewingKeyResolver {
    fn current_epoch(&self) -> Result<ViewingKeyEpoch> {
        Ok(self.current_epoch)
    }

    fn key_for_epoch(&self, epoch: ViewingKeyEpoch) -> Result<Zeroizing<Hash>> {
        self.derive_epoch_key(epoch)
    }
}

fn validate_root(root: &Hash) -> Result<()> {
    if bool::from(root.ct_eq(&[0; 32])) {
        return Err(ShieldedMarginError::InvalidViewingKey);
    }
    Ok(())
}

fn validate_retention(retention_epochs: usize) -> Result<()> {
    if retention_epochs == 0 || retention_epochs > MAX_VIEWING_KEY_RETENTION {
        return Err(ShieldedMarginError::InvalidViewingAssociatedData(
            "viewing-key retention is outside the supported bounds",
        ));
    }
    Ok(())
}

fn fingerprint_for_root(root: &Hash) -> Result<Hash> {
    validate_root(root)?;
    let mut hasher = Sha256::new();
    hasher.update(ROOT_FINGERPRINT_DOMAIN);
    hasher.update(ROOT_FINGERPRINT_VERSION.to_be_bytes());
    hasher.update(root);
    Ok(hasher.finalize().into())
}

fn derive_epoch_key(root: &Hash, epoch: ViewingKeyEpoch) -> Result<Zeroizing<Hash>> {
    validate_root(root)?;
    let mut info = Vec::with_capacity(ROOT_KDF_INFO.len() + 2 + 4);
    info.extend_from_slice(ROOT_KDF_INFO);
    info.extend_from_slice(&ROOT_FINGERPRINT_VERSION.to_be_bytes());
    info.extend_from_slice(&epoch.0.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(ROOT_KDF_SALT), root);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut key[..])
        .map_err(|_| ShieldedMarginError::ViewingCipherAuthentication)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shielded_margin::{
        CollateralAssetId, MarketId, NoteCommitment, NoteOpening, PublicNote, ViewingKeyAad,
        XChaChaViewingKeyCipher,
    };
    use zeroize::Zeroize;

    fn root(seed: u8) -> Hash {
        [seed; 32]
    }

    fn note() -> PublicNote {
        PublicNote {
            version: 3,
            market_id: MarketId::from_label(b"BTC-PERP"),
            collateral_asset: CollateralAssetId::from_label(b"USDC"),
            commitment: NoteCommitment([9; 32]),
        }
    }

    fn aad(epoch: ViewingKeyEpoch) -> ViewingKeyAad {
        ViewingKeyAad::for_note_opening([7; 32], [8; 32], epoch, note()).unwrap()
    }

    #[test]
    fn root_is_redacted_and_fingerprint_is_stable_without_exposing_secret() {
        let resolver = DerivedViewingKeyResolver::from_root(root(41), 3).unwrap();
        let debug = format!("{resolver:?}");
        assert!(!debug.contains(&hex::encode(root(41))));
        assert_eq!(
            resolver.root_fingerprint(),
            DerivedViewingKeyResolver::fingerprint_for_root(&root(41)).unwrap()
        );
        assert_ne!(resolver.root_fingerprint(), root(41));
        assert_ne!(resolver.root_fingerprint(), [0; 32]);
    }

    #[test]
    fn constructor_rejects_zero_root_and_invalid_retention() {
        assert_eq!(
            DerivedViewingKeyResolver::from_root([0; 32], 1).unwrap_err(),
            ShieldedMarginError::InvalidViewingKey
        );
        assert!(matches!(
            DerivedViewingKeyResolver::from_root(root(1), 0),
            Err(ShieldedMarginError::InvalidViewingAssociatedData(_))
        ));
        assert!(matches!(
            DerivedViewingKeyResolver::from_root(root(1), MAX_VIEWING_KEY_RETENTION + 1),
            Err(ShieldedMarginError::InvalidViewingAssociatedData(_))
        ));
    }

    #[test]
    fn epoch_keys_are_deterministic_separated_and_zeroizable() {
        let resolver = DerivedViewingKeyResolver::new(root(2), ViewingKeyEpoch::new(1), 4).unwrap();
        let first = resolver.key_for_epoch(ViewingKeyEpoch::new(0)).unwrap();
        let second = resolver.key_for_epoch(ViewingKeyEpoch::new(0)).unwrap();
        let next = resolver.key_for_epoch(ViewingKeyEpoch::new(1)).unwrap();
        assert_eq!(*first, *second);
        assert_ne!(*first, *next);
        let mut wiped = first;
        wiped.zeroize();
        assert_eq!(*wiped, [0; 32]);
    }

    #[test]
    fn rotation_enforces_monotonic_epochs_and_retention_window() {
        let mut resolver = DerivedViewingKeyResolver::from_root(root(3), 2).unwrap();
        assert_eq!(resolver.oldest_retained_epoch(), ViewingKeyEpoch::new(0));
        assert_eq!(resolver.rotate().unwrap(), ViewingKeyEpoch::new(1));
        assert!(resolver.is_epoch_retained(ViewingKeyEpoch::new(0)));
        assert_eq!(resolver.rotate().unwrap(), ViewingKeyEpoch::new(2));
        assert_eq!(resolver.oldest_retained_epoch(), ViewingKeyEpoch::new(1));
        assert!(!resolver.is_epoch_retained(ViewingKeyEpoch::new(0)));
        assert_eq!(
            resolver.key_for_epoch(ViewingKeyEpoch::new(0)),
            Err(ShieldedMarginError::ViewingKeyEpochUnavailable(0))
        );
        assert_eq!(
            resolver.rotate_to(ViewingKeyEpoch::new(2)),
            Err(ShieldedMarginError::ViewingKeyEpochMismatch)
        );
        assert_eq!(
            resolver.rotate_to(ViewingKeyEpoch::new(5)).unwrap(),
            ViewingKeyEpoch::new(5)
        );
        assert_eq!(resolver.oldest_retained_epoch(), ViewingKeyEpoch::new(4));
        assert_eq!(
            ViewingKeyEpoch::new(u32::MAX).next(),
            Err(ShieldedMarginError::ViewingKeyEpochOverflow)
        );
    }

    #[test]
    fn recovery_requires_matching_fingerprint_and_retains_old_keys_only_in_window() {
        let original = DerivedViewingKeyResolver::new(root(4), ViewingKeyEpoch::new(7), 3).unwrap();
        let fingerprint = original.root_fingerprint();
        let recovered = DerivedViewingKeyResolver::from_recovered_root(
            root(4),
            ViewingKeyEpoch::new(7),
            3,
            fingerprint,
        )
        .unwrap();
        assert_eq!(
            original.key_for_epoch(ViewingKeyEpoch::new(6)).unwrap(),
            recovered.key_for_epoch(ViewingKeyEpoch::new(6)).unwrap()
        );
        assert!(matches!(
            DerivedViewingKeyResolver::from_recovered_root(
                root(5),
                ViewingKeyEpoch::new(7),
                3,
                fingerprint
            ),
            Err(ShieldedMarginError::ViewingCipherAuthentication)
        ));
        assert_eq!(
            DerivedViewingKeyResolver::new(root(4), ViewingKeyEpoch::new(7), 3)
                .unwrap()
                .key_for_epoch(ViewingKeyEpoch::new(4)),
            Err(ShieldedMarginError::ViewingKeyEpochUnavailable(4))
        );
    }

    #[test]
    fn resolver_implements_cipher_rotation_and_historical_open() {
        let mut resolver = DerivedViewingKeyResolver::from_root(root(6), 2).unwrap();
        let cipher = XChaChaViewingKeyCipher;
        let old_aad = aad(resolver.current_epoch());
        let payload = cipher
            .seal_with_resolver(&resolver, &old_aad, b"recoverable")
            .unwrap();
        resolver.rotate().unwrap();
        assert_eq!(
            cipher
                .open_with_resolver(&resolver, &old_aad, &payload)
                .unwrap()
                .as_slice(),
            b"recoverable"
        );
        let new_aad = aad(resolver.current_epoch());
        assert!(
            cipher
                .seal_with_resolver(&resolver, &new_aad, b"current")
                .is_ok()
        );
    }

    #[test]
    fn note_opening_helpers_bind_commitment_and_recover_historical_epochs() {
        let chain_domain = [31; 32];
        let ledger_id = [32; 32];
        let market_id = MarketId::from_label(b"ETH-PERP");
        let collateral_asset = CollateralAssetId::from_label(b"USDC");
        let opening = NoteOpening {
            owner: [33; 32],
            nullifier_key: [34; 32],
            collateral: 50_000,
            position: -7,
            leverage: 4,
            blinding: [35; 32],
        };
        let note = PublicNote::new(market_id, collateral_asset, &opening);
        let mut resolver = DerivedViewingKeyResolver::from_root(root(7), 2).unwrap();
        let payload = resolver
            .seal_note_opening(chain_domain, ledger_id, note, &opening)
            .unwrap();
        resolver.rotate().unwrap();
        assert_eq!(
            resolver
                .open_note_opening(chain_domain, ledger_id, note, &payload)
                .unwrap(),
            opening
        );

        let mut wrong_opening = opening.clone();
        wrong_opening.collateral += 1;
        assert_eq!(
            resolver.seal_note_opening(chain_domain, ledger_id, note, &wrong_opening),
            Err(ShieldedMarginError::CommitmentMismatch)
        );
        let wrong_note = PublicNote {
            commitment: NoteCommitment([99; 32]),
            ..note
        };
        assert!(matches!(
            resolver.open_note_opening(chain_domain, ledger_id, wrong_note, &payload),
            Err(ShieldedMarginError::ViewingCipherAuthentication)
        ));
    }
}
