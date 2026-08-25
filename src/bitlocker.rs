//! BitLocker (FVE) volume unlock and transparent decryption.
//!
//! Given a credential -- recovery password, passphrase, startup .BEK key, raw
//! FVEK, or a suspended volume's clear key -- this parses the FVE metadata,
//! recovers the Volume Master Key and then the Full Volume Encryption Key, and
//! decrypts sectors on demand. Everything is read-only; no plaintext is ever
//! written back to the source.
//!
//! Data ciphers: AES-XTS-128/256 (the Windows 8+ default), AES-CBC-128/256,
//! and AES-CBC + Elephant diffuser (Vista/7).

use crate::crypto::{self, Aes};
use crate::reader::Source;
use sha2::{Digest, Sha256};

pub const FVE_SIGNATURE: &[u8] = b"-FVE-FS-";

// data encryption methods (FVE metadata header)
const M_AES_CBC_128_DIFFUSER: u32 = 0x8000;
const M_AES_CBC_256_DIFFUSER: u32 = 0x8001;
const M_AES_CBC_128: u32 = 0x8002;
const M_AES_CBC_256: u32 = 0x8003;
const M_AES_XTS_128: u32 = 0x8004;
const M_AES_XTS_256: u32 = 0x8005;

// metadata entry value types
const VT_KEY: u16 = 0x0001;
const VT_STRETCH_KEY: u16 = 0x0003;
const VT_AES_CCM_KEY: u16 = 0x0005;
const VT_VMK: u16 = 0x0008;
const VT_EXTERNAL_KEY: u16 = 0x0009;
// metadata entry types
const ET_FVEK: u16 = 0x0003;
// VMK protection types
const PROT_CLEAR: u16 = 0x0000;
const PROT_STARTUP_KEY: u16 = 0x0200;
const PROT_TPM_PIN: u16 = 0x0500;
const PROT_RECOVERY: u16 = 0x0800;
const PROT_PASSWORD: u16 = 0x2000;

const STRETCH_COUNT: u64 = 0x100000;

pub fn method_name(method: u32) -> &'static str {
    match method {
        M_AES_CBC_128_DIFFUSER => "AES-CBC-128 + diffuser",
        M_AES_CBC_256_DIFFUSER => "AES-CBC-256 + diffuser",
        M_AES_CBC_128 => "AES-CBC-128",
        M_AES_CBC_256 => "AES-CBC-256",
        M_AES_XTS_128 => "AES-XTS-128",
        M_AES_XTS_256 => "AES-XTS-256",
        _ => "?",
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    if o + 8 > b.len() {
        return 0;
    }
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

#[derive(Default, Clone)]
pub struct Credentials {
    pub recovery: Option<String>,
    pub password: Option<String>,
    pub bek: Option<Vec<u8>>,
    pub fvek: Option<Vec<u8>>,
}

impl Credentials {
    pub fn is_empty(&self) -> bool {
        self.recovery.is_none()
            && self.password.is_none()
            && self.bek.is_none()
            && self.fvek.is_none()
    }
}

/// 48 decimal digits (optionally dash-grouped 6x8) to the 16-byte intermediate.
pub fn parse_recovery_password(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut groups: Vec<String> = cleaned
        .split('-')
        .filter(|g| !g.is_empty())
        .map(|g| g.to_string())
        .collect();
    if groups.len() == 1 && groups[0].len() == 48 {
        let s = groups[0].clone();
        groups = (0..8).map(|i| s[i * 6..i * 6 + 6].to_string()).collect();
    }
    if groups.len() != 8
        || groups
            .iter()
            .any(|g| g.len() != 6 || !g.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("recovery password must be 8 groups of 6 digits".into());
    }
    let mut out = Vec::with_capacity(16);
    for g in &groups {
        let v: u64 = g.parse().map_err(|_| format!("bad recovery group {g}"))?;
        if v % 11 != 0 {
            return Err(format!("recovery group {g} not divisible by 11"));
        }
        let v = v / 11;
        if v > 0xFFFF {
            return Err(format!("recovery group {g} out of range"));
        }
        out.extend_from_slice(&(v as u16).to_le_bytes());
    }
    Ok(out)
}

/// The candidate initial hashes for a secret, in the order to try them.
///
/// A user passphrase is documented as SHA-256 applied twice over its UTF-16LE
/// form; a recovery password is documented as a single SHA-256 over the 16-byte
/// value the digit groups decode to. Sources disagree on which applies where,
/// and a wrong choice is indistinguishable from a wrong key -- so try both and
/// let the CCM MAC decide. The cost is one extra key stretch, only on the path
/// that would otherwise have failed outright.
fn password_hashes(data: &[u8]) -> [[u8; 32]; 2] {
    let single: [u8; 32] = Sha256::digest(data).into();
    let double: [u8; 32] = Sha256::digest(single).into();
    [double, single]
}

/// BitLocker key stretch: 2^20 SHA-256 rounds over an 88-byte struct of
/// (last_hash || initial_hash || salt || counter).
fn stretch_key(pw_hash: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut last = [0u8; 32];
    let mut buf = [0u8; 88];
    buf[32..64].copy_from_slice(pw_hash);
    let n = salt.len().min(16);
    buf[64..64 + n].copy_from_slice(&salt[..n]);
    for count in 0..STRETCH_COUNT {
        buf[..32].copy_from_slice(&last);
        buf[80..88].copy_from_slice(&count.to_le_bytes());
        last = Sha256::digest(buf).into();
    }
    last
}

struct Entry {
    etype: u16,
    vtype: u16,
    data: Vec<u8>,
}

/// Walk a metadata entry list: each entry is size(2) etype(2) vtype(2) ver(2)
/// then its payload.
fn walk_entries(body: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= body.len() {
        let size = u16le(body, pos) as usize;
        if size < 8 || pos + size > body.len() {
            break;
        }
        out.push(Entry {
            etype: u16le(body, pos + 2),
            vtype: u16le(body, pos + 4),
            data: body[pos + 8..pos + size].to_vec(),
        });
        pos += size;
    }
    out
}

pub struct FveMetadata {
    pub encryption_method: u32,
    pub header_sectors: u32,
    pub volume_header_offset: u64,
    pub encrypted_volume_size: u64,
    entries: Vec<Entry>,
}

pub fn parse_metadata(block: &[u8]) -> Result<FveMetadata, String> {
    if block.len() < 0x70 || &block[..8] != FVE_SIGNATURE {
        return Err("FVE metadata signature missing".into());
    }
    let encrypted_volume_size = u64le(block, 0x10);
    let header_sectors = u32le(block, 0x1C);
    let volume_header_offset = u64le(block, 0x20);
    let metadata_size = u32le(block, 0x40) as usize;
    let encryption_method = u32le(block, 0x40 + 0x24) & 0xFFFF;
    let end = (0x40 + metadata_size).min(block.len());
    if end <= 0x70 {
        return Err("FVE metadata body empty".into());
    }
    Ok(FveMetadata {
        encryption_method,
        header_sectors,
        volume_header_offset,
        encrypted_volume_size,
        entries: walk_entries(&block[0x70..end]),
    })
}

/// A decrypted CCM "key" payload is a 4-byte header then the raw key bytes.
fn key_from_payload(payload: &[u8]) -> Vec<u8> {
    if payload.len() > 4 {
        payload[4..].to_vec()
    } else {
        Vec::new()
    }
}

/// AES-CCM key entry data is nonce(12) || MAC(16) || ciphertext.
fn ccm_blob_decrypt(key: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 {
        return None;
    }
    crypto::ccm_decrypt(key, &blob[..12], &blob[12..], 16)
}

/// Protector name for a VMK protection type.
pub fn protector_name(protection: u16) -> &'static str {
    match protection {
        PROT_CLEAR => "clear key (suspended)",
        0x0100 => "TPM",
        PROT_STARTUP_KEY => "startup key (.BEK)",
        PROT_TPM_PIN => "TPM + PIN",
        PROT_RECOVERY => "recovery password",
        PROT_PASSWORD => "passphrase",
        _ => "unknown",
    }
}

/// A 16-byte mixed-endian GUID as its canonical string.
fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        b[3],
        b[2],
        b[1],
        b[0],
        b[5],
        b[4],
        b[7],
        b[6],
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

/// Every AES-CCM wrapped key inside a VMK entry, and the stretch salt if there
/// is one.
///
/// Windows nests the encrypted key *inside* the stretch-key entry, while some
/// tools write the two as siblings; accept both and let the CCM MAC decide
/// which blob (if any) the derived key opens.
fn vmk_key_material(nested: &[Entry]) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
    let mut salt = None;
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for e in nested {
        match e.vtype {
            VT_AES_CCM_KEY => blobs.push(e.data.clone()),
            VT_STRETCH_KEY if e.data.len() >= 20 => {
                // stretch key entry: method(4) salt(16) then nested entries
                salt = Some(e.data[4..20].to_vec());
                for inner in walk_entries(&e.data[20..]) {
                    if inner.vtype == VT_AES_CCM_KEY {
                        blobs.push(inner.data);
                    }
                }
            }
            _ => {}
        }
    }
    (salt, blobs)
}

/// Turn one VMK metadata entry into the plaintext VMK, if a credential fits.
fn unlock_vmk(entry: &Entry, creds: &Credentials) -> Option<Vec<u8>> {
    let data = &entry.data;
    if data.len() < 0x1C {
        return None;
    }
    let protection = u16le(data, 0x1A);
    let nested = walk_entries(&data[0x1C..]);

    // Clear key (suspended BitLocker): the VMK sits in the open.
    if protection == PROT_CLEAR {
        if let Some(k) = nested.iter().find(|e| e.vtype == VT_KEY) {
            return Some(key_from_payload(&k.data));
        }
    }

    let (salt, blobs) = vmk_key_material(&nested);

    // Recovery password or passphrase: stretch the salt, then CCM-unwrap.
    if let Some(salt) = &salt {
        let secret: Option<Vec<u8>> = match (&creds.recovery, &creds.password) {
            (Some(r), _) if protection == PROT_RECOVERY || protection == 0 => {
                parse_recovery_password(r).ok()
            }
            (_, Some(p)) if protection == PROT_PASSWORD || protection == PROT_TPM_PIN => {
                Some(p.encode_utf16().flat_map(|u| u.to_le_bytes()).collect())
            }
            _ => None,
        };
        if let Some(secret) = secret {
            for initial in password_hashes(&secret) {
                let dk = stretch_key(&initial, salt);
                for blob in &blobs {
                    if let Some(payload) = ccm_blob_decrypt(&dk, blob) {
                        return Some(key_from_payload(&payload));
                    }
                }
            }
            return None;
        }
    }

    // Startup key (.BEK): the external key CCM-unwraps the VMK directly.
    if let Some(bek) = &creds.bek {
        if protection == PROT_STARTUP_KEY {
            if let Some(ext) = external_key_from_bek(bek) {
                for blob in &blobs {
                    if let Some(payload) = ccm_blob_decrypt(&ext, blob) {
                        return Some(key_from_payload(&payload));
                    }
                }
            }
        }
    }
    None
}

/// A .BEK file is an FVE metadata block whose external-key entry holds a raw key.
fn external_key_from_bek(bek: &[u8]) -> Option<Vec<u8>> {
    let meta = parse_metadata(bek).ok()?;
    for e in &meta.entries {
        if e.vtype == VT_EXTERNAL_KEY && e.data.len() > 0x1C {
            for n in walk_entries(&e.data[0x1C..]) {
                if n.vtype == VT_KEY {
                    return Some(key_from_payload(&n.data));
                }
            }
        }
        if e.vtype == VT_KEY {
            return Some(key_from_payload(&e.data));
        }
    }
    None
}

impl FveMetadata {
    /// (identifier GUID, protection type) for every VMK protector on the
    /// volume. The identifier is what a recovery-key file calls
    /// "Identification", so it is how an analyst tells whether the key in hand
    /// belongs to this volume at all.
    pub fn protectors(&self) -> Vec<(String, u16)> {
        self.entries
            .iter()
            .filter(|e| e.vtype == VT_VMK && e.data.len() >= 0x1C)
            .map(|e| (guid(&e.data[..16]), u16le(&e.data, 0x1A)))
            .collect()
    }
}

pub fn recover_fvek(meta: &FveMetadata, creds: &Credentials) -> Result<Vec<u8>, String> {
    if let Some(fvek) = &creds.fvek {
        return Ok(fvek.clone());
    }
    let mut vmk = None;
    for e in &meta.entries {
        if e.vtype == VT_VMK {
            if let Some(k) = unlock_vmk(e, creds) {
                vmk = Some(k);
                break;
            }
        }
    }
    let vmk = vmk.ok_or_else(|| {
        "no VMK could be unlocked with the supplied credential (wrong recovery \
         key / password, or unsupported protector)"
            .to_string()
    })?;
    let fvek_entry = meta
        .entries
        .iter()
        .find(|e| e.etype == ET_FVEK && e.vtype == VT_AES_CCM_KEY)
        .or_else(|| meta.entries.iter().find(|e| e.vtype == VT_AES_CCM_KEY))
        .ok_or("no FVEK entry in metadata")?;
    let payload = ccm_blob_decrypt(&vmk, &fvek_entry.data)
        .ok_or("FVEK entry did not decrypt under the recovered VMK")?;
    Ok(key_from_payload(&payload))
}

// ------------------------------------------------------------ volume cipher

/// Sector-level decrypt for one FVE encryption method.
pub struct Cipher {
    xts: bool,
    diffuser: bool,
    aes1: Aes,
    aes2: Option<Aes>,
}

impl Cipher {
    pub fn new(method: u32, fvek: &[u8]) -> Result<Self, String> {
        let half = match method {
            M_AES_XTS_128 | M_AES_CBC_128_DIFFUSER => 16,
            M_AES_XTS_256 | M_AES_CBC_256_DIFFUSER => 32,
            M_AES_CBC_128 => 16,
            M_AES_CBC_256 => 32,
            _ => return Err(format!("unsupported encryption method {method:#06x}")),
        };
        let xts = matches!(method, M_AES_XTS_128 | M_AES_XTS_256);
        let diffuser = matches!(method, M_AES_CBC_128_DIFFUSER | M_AES_CBC_256_DIFFUSER);
        if fvek.len() < half {
            return Err("FVEK too short for the declared method".into());
        }
        let aes1 = Aes::new(&fvek[..half]).ok_or("bad FVEK length")?;
        let aes2 = if xts || diffuser {
            if fvek.len() < half * 2 {
                return Err("FVEK too short for a two-key method".into());
            }
            Some(Aes::new(&fvek[half..half * 2]).ok_or("bad FVEK length")?)
        } else {
            None
        };
        Ok(Cipher {
            xts,
            diffuser,
            aes1,
            aes2,
        })
    }

    fn sector_key(&self, sector_no: u64, size: usize) -> Vec<u8> {
        let aes2 = self.aes2.as_ref().expect("diffuser needs the second key");
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&sector_no.to_le_bytes());
        let mut k = aes2.encrypt(&b).to_vec();
        b[15] = 0x80;
        k.extend_from_slice(&aes2.encrypt(&b));
        k.iter().copied().cycle().take(size).collect()
    }

    pub fn decrypt_sector(&self, sector_no: u64, data: &[u8]) -> Vec<u8> {
        if self.xts {
            return crypto::xts_decrypt(
                &self.aes1,
                self.aes2.as_ref().expect("xts needs the tweak key"),
                sector_no,
                data,
            );
        }
        let mut ivb = [0u8; 16];
        ivb[..8].copy_from_slice(&sector_no.to_le_bytes());
        let iv = self.aes1.encrypt(&ivb);
        let plain = crypto::cbc_decrypt(&self.aes1, &iv, data);
        if !self.diffuser {
            return plain;
        }
        let sk = self.sector_key(sector_no, plain.len());
        crypto::diffuser_decrypt(&plain, &sk)
    }

    /// Inverse of decrypt_sector. Only used to build test volumes.
    pub fn encrypt_sector(&self, sector_no: u64, data: &[u8]) -> Vec<u8> {
        if self.xts {
            return crypto::xts_encrypt(
                &self.aes1,
                self.aes2.as_ref().expect("xts needs the tweak key"),
                sector_no,
                data,
            );
        }
        let mut ivb = [0u8; 16];
        ivb[..8].copy_from_slice(&sector_no.to_le_bytes());
        let iv = self.aes1.encrypt(&ivb);
        if !self.diffuser {
            return crypto::cbc_encrypt(&self.aes1, &iv, data);
        }
        let sk = self.sector_key(sector_no, data.len());
        let diffused = crypto::diffuser_encrypt(data, &sk);
        crypto::cbc_encrypt(&self.aes1, &iv, &diffused)
    }
}

// ----------------------------------------------------------- unlocked volume

/// An unlocked FVE volume: decrypts on demand and presents plaintext sectors.
pub struct Volume {
    pub base: u64,
    pub size: u64,
    pub sector_size: u64,
    pub method: u32,
    cipher: Cipher,
    header_bytes: u64,
    header_src: u64,
}

impl Volume {
    /// Plaintext bytes at a volume-relative offset.
    pub fn read(&self, src: &Source, offset: u64, length: usize) -> Vec<u8> {
        if offset >= self.size || length == 0 {
            return Vec::new();
        }
        let length = (length as u64).min(self.size - offset);
        let ss = self.sector_size;
        let start = offset - offset % ss;
        let mut end = offset + length;
        end += (ss - end % ss) % ss;
        let mut out = Vec::with_capacity((end - start) as usize);
        let mut pos = start;
        while pos < end {
            out.extend_from_slice(&self.decrypt_one(src, pos));
            pos += ss;
        }
        let lo = (offset - start) as usize;
        out[lo..lo + length as usize].to_vec()
    }

    fn decrypt_one(&self, src: &Source, vpos: u64) -> Vec<u8> {
        let ss = self.sector_size;
        // The first header_sectors hold BDE boot code; the real (encrypted)
        // originals live at volume_header_offset.
        if vpos < self.header_bytes && self.header_src != 0 {
            let at = self.header_src + vpos;
            let ct = src.pread(at, ss as usize);
            return self.cipher.decrypt_sector(at / ss, &ct);
        }
        let mut ct = src.pread(self.base + vpos, ss as usize);
        ct.resize(ss as usize, 0);
        self.cipher.decrypt_sector(vpos / ss, &ct)
    }
}

/// The FVE metadata block offsets in the volume header.
///
/// Windows 7 and later put three of them at 0xB0, right after the BitLocker
/// identifier GUID at 0xA0; Vista used 0x160. Both are returned -- a zero entry
/// is not a candidate, so whichever layout this volume uses, only its offsets
/// survive.
fn metadata_offsets(boot: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    for base in [0xB0usize, 0x160] {
        if boot.len() < base + 24 {
            continue;
        }
        for i in 0..3 {
            let off = u64le(boot, base + i * 8);
            if off != 0 && !out.contains(&off) {
                out.push(off);
            }
        }
    }
    out
}

/// The BitLocker identifier GUID at 0xA0, when the volume header carries one.
pub fn volume_identifier(boot: &[u8]) -> Option<String> {
    if boot.len() < 0xB0 {
        return None;
    }
    let id = guid(&boot[0xA0..0xB0]);
    if id.starts_with("00000000") {
        None
    } else {
        Some(id)
    }
}

pub fn is_bitlocker(src: &Source, base: u64) -> bool {
    let boot = src.pread(base, 512);
    boot.len() >= 11 && &boot[3..11] == FVE_SIGNATURE
}

/// Walk the volume for FVE metadata blocks, sector-aligned.
///
/// The header's three offsets are the normal route; this is for volumes where
/// they do not resolve -- a partly overwritten header, an unusual layout, or a
/// reader that hands back the wrong bytes. It reads the whole volume, so it is
/// opt-in rather than automatic.
pub fn scan_for_metadata(
    src: &Source,
    base: u64,
    limit: u64,
    mut log: impl FnMut(&str),
) -> Option<FveMetadata> {
    const STEP: usize = 8 << 20;
    let mut pos = base;
    let end = base.saturating_add(limit).min(src.size());
    while pos < end {
        let want = ((end - pos) as usize).min(STEP + 512);
        let buf = src.pread(pos, want);
        if buf.is_empty() {
            break;
        }
        let scan_to = buf.len().saturating_sub(8).min(STEP);
        let mut i = 0usize;
        while i <= scan_to {
            if buf[i..i + 8] == *FVE_SIGNATURE {
                let at = pos + i as u64;
                let block = src.pread(at, 0x10000);
                if let Ok(m) = parse_metadata(&block) {
                    log(&format!("bitlocker: metadata block found at {at:#x}"));
                    return Some(m);
                }
            }
            i += 512; // metadata blocks are sector aligned
        }
        pos += STEP as u64;
    }
    None
}

/// Detect and unlock a BitLocker volume at `base`; Ok(None) if it is not FVE.
pub fn unlock_volume(
    src: &Source,
    base: u64,
    creds: &Credentials,
    scan_metadata: bool,
    mut log: impl FnMut(&str),
) -> Result<Option<Volume>, String> {
    let boot = src.pread(base, 512);
    if boot.len() < 11 || &boot[3..11] != FVE_SIGNATURE {
        return Ok(None);
    }
    let sector_size = match u16le(&boot, 11) {
        0 => 512u64,
        n => n as u64,
    };
    if let Some(id) = volume_identifier(&boot) {
        log(&format!("bitlocker: volume identifier {id}"));
    }
    let mut meta = None;
    let mut tried: Vec<String> = Vec::new();
    for off in metadata_offsets(&boot) {
        if off == 0 {
            continue;
        }
        let block = src.pread(base + off, 0x10000);
        if block.len() >= 8 && &block[..8] == FVE_SIGNATURE {
            match parse_metadata(&block) {
                Ok(m) => {
                    log(&format!(
                        "bitlocker: metadata from the volume header at {off:#x}"
                    ));
                    meta = Some(m);
                    break;
                }
                Err(e) => tried.push(format!("{off:#x}: signature present but {e}")),
            }
        } else {
            // Report what is actually there: zeros usually mean the read did
            // not reach the data, other bytes mean the offset is wrong.
            let head: String = block.iter().take(8).map(|b| format!("{b:02x}")).collect();
            tried.push(format!(
                "{off:#x}: found {} ({} bytes read)",
                if head.is_empty() {
                    "nothing".into()
                } else {
                    head
                },
                block.len()
            ));
        }
    }
    if meta.is_none() && scan_metadata {
        log("bitlocker: header offsets did not resolve, scanning the volume...");
        meta = scan_for_metadata(src, base, src.size().saturating_sub(base), &mut log);
    }
    if let Some(m) = &meta {
        for (id, prot) in m.protectors() {
            log(&format!(
                "bitlocker: protector {id} is a {} ({prot:#06x})",
                protector_name(prot)
            ));
        }
    }
    let meta = meta.ok_or_else(|| {
        format!(
            "FVE boot sector at {base:#x} found but no valid metadata block. \
             Offsets from the boot sector: [{}]{}",
            tried.join("; "),
            if scan_metadata {
                " (volume scan also found none)"
            } else {
                ". Retry with --bitlocker-scan-metadata to search the volume."
            }
        )
    })?;
    let fvek = recover_fvek(&meta, creds)?;
    let cipher = Cipher::new(meta.encryption_method, &fvek)?;
    let size = if meta.encrypted_volume_size > 0 {
        meta.encrypted_volume_size
    } else {
        src.size() - base
    };
    Ok(Some(Volume {
        base,
        size,
        sector_size,
        method: meta.encryption_method,
        cipher,
        header_bytes: meta.header_sectors as u64 * sector_size,
        header_src: meta.volume_header_offset,
    }))
}
