//! BitLocker unlock, against volumes built by the reference implementation.
//!
//! `tests/fixtures/*.dd` were produced by BreadCrumb's own BitLocker test
//! builder (Python) and are committed as-is, so these tests check this port
//! against the other implementation's output rather than against itself.

use breadcrumb_rs::bitlocker::{self, Credentials};
use breadcrumb_rs::carver::{Carver, Options};
use breadcrumb_rs::crypto::{self, Aes};
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::SIGNATURES;
use std::path::{Path, PathBuf};

/// The recovery password the fixtures were built with.
const RECOVERY: &str = "011000-022000-033000-044000-055000-066000-077000-088000";
/// Same shape, wrong value: every group is still divisible by 11.
const WRONG: &str = "011011-022011-033011-044011-055011-066011-077011-088011";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn out_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("breadcrumb-rs-bl-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn carve_unlocked(image: &Path, creds: &Credentials, tag: &str) -> Vec<(u64, u64, String)> {
    let src = Source::open(image.to_str().unwrap()).unwrap();
    let src = src.unlock_bitlocker(creds, |_| {}).expect("unlock failed");
    assert!(
        matches!(src, Source::BitLocker(_)),
        "volume was not unlocked"
    );
    let out = out_dir(tag);
    let opts = Options {
        out_dir: out.to_string_lossy().into(),
        quiet: true,
        dry_run: true,
        ..Options::default()
    };
    let mut c = Carver::new(&src, SIGNATURES.iter().collect(), &opts);
    let mut recs: Vec<(u64, u64, String)> = c
        .run()
        .into_iter()
        .map(|r| (r.offset, r.size, r.sha256))
        .collect();
    recs.sort();
    let _ = std::fs::remove_dir_all(&out);
    recs
}

#[test]
fn recovery_password_unlocks_xts_and_diffuser_volumes() {
    for name in ["bitlocker_xts256.dd", "bitlocker_cbc128_diffuser.dd"] {
        let creds = Credentials {
            recovery: Some(RECOVERY.into()),
            ..Default::default()
        };
        let recs = carve_unlocked(&fixture(name), &creds, "rec");
        assert_eq!(recs.len(), 3, "{name}: expected the three planted files");
        // The plaintext volume holds a jpeg, a png and a pdf; all three must
        // come back with real content, not ciphertext noise.
        assert!(recs.iter().all(|(_, size, _)| *size > 0));
    }
}

#[test]
fn the_wrong_recovery_password_is_a_clean_failure() {
    let src = Source::open(fixture("bitlocker_xts256.dd").to_str().unwrap()).unwrap();
    let creds = Credentials {
        recovery: Some(WRONG.into()),
        ..Default::default()
    };
    let err = src
        .unlock_bitlocker(&creds, |_| {})
        .err()
        .expect("wrong key accepted");
    assert!(err.contains("no VMK could be unlocked"), "{err}");
}

#[test]
fn a_raw_fvek_skips_key_recovery_and_gives_the_same_bytes() {
    // Recover the FVEK with the password, then feed it back directly: the two
    // routes must produce the same carve.
    let image = fixture("bitlocker_xts256.dd");
    let with_password = carve_unlocked(
        &image,
        &Credentials {
            recovery: Some(RECOVERY.into()),
            ..Default::default()
        },
        "pw",
    );

    let src = Source::open(image.to_str().unwrap()).unwrap();
    let boot = src.pread(0, 512);
    let mut meta = None;
    for i in 0..3usize {
        let off = u64::from_le_bytes(boot[0x160 + i * 8..0x168 + i * 8].try_into().unwrap());
        if off == 0 {
            continue;
        }
        let block = src.pread(off, 0x10000);
        if block.len() >= 8 && &block[..8] == bitlocker::FVE_SIGNATURE {
            if let Ok(m) = bitlocker::parse_metadata(&block) {
                meta = Some(m);
                break;
            }
        }
    }
    let meta = meta.expect("no FVE metadata");
    let fvek = bitlocker::recover_fvek(
        &meta,
        &Credentials {
            recovery: Some(RECOVERY.into()),
            ..Default::default()
        },
    )
    .expect("fvek recovery failed");

    let with_fvek = carve_unlocked(
        &image,
        &Credentials {
            fvek: Some(fvek),
            ..Default::default()
        },
        "fvek",
    );
    assert_eq!(with_password, with_fvek);
}

#[test]
fn recovery_password_parsing_matches_the_documented_rules() {
    // 8 groups of 6 digits, each divisible by 11, /11 fitting in 16 bits.
    assert_eq!(
        bitlocker::parse_recovery_password(RECOVERY).unwrap().len(),
        16
    );
    let undashed: String = RECOVERY.chars().filter(|c| *c != '-').collect();
    assert_eq!(
        bitlocker::parse_recovery_password(&undashed).unwrap(),
        bitlocker::parse_recovery_password(RECOVERY).unwrap()
    );
    // 48 ones IS valid (111111 = 11 x 10101), so the bad cases are shape and
    // divisibility failures instead.
    for bad in [
        "",
        "nope",
        "123456-123456",
        "111112-111111-111111-111111-111111-111111-111111-111111",
    ] {
        assert!(
            bitlocker::parse_recovery_password(bad).is_err(),
            "{bad:?} accepted"
        );
    }
    // divisible by 11 but the quotient overflows 16 bits
    assert!(bitlocker::parse_recovery_password(
        "999999-999999-999999-999999-999999-999999-999999-999999"
    )
    .is_err());
}

#[test]
fn empty_credentials_leave_the_source_alone() {
    let src = Source::open(fixture("bitlocker_xts256.dd").to_str().unwrap()).unwrap();
    let src = src
        .unlock_bitlocker(&Credentials::default(), |_| {})
        .unwrap();
    assert!(
        !matches!(src, Source::BitLocker(_)),
        "unlocked without a credential"
    );
}

// ------------------------------------------------------------ cipher modes

#[test]
fn aes_matches_the_fips197_vector() {
    // FIPS-197 C.1: AES-128 of 00112233..ff under key 000102..0f.
    let key: Vec<u8> = (0u8..16).collect();
    let mut block = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let aes = Aes::new(&key).unwrap();
    aes.encrypt_block(&mut block);
    assert_eq!(
        block,
        [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a
        ]
    );
    aes.decrypt_block(&mut block);
    assert_eq!(block[0], 0x00);
    assert_eq!(block[15], 0xff);
}

#[test]
fn xts_cbc_and_diffuser_round_trip() {
    let data: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let k1 = Aes::new(&[0x11u8; 32]).unwrap();
    let k2 = Aes::new(&[0x22u8; 32]).unwrap();

    let ct = crypto::xts_encrypt(&k1, &k2, 7, &data);
    assert_ne!(ct, data, "xts produced plaintext");
    assert_eq!(crypto::xts_decrypt(&k1, &k2, 7, &ct), data);
    // the sector number is part of the tweak
    assert_ne!(crypto::xts_decrypt(&k1, &k2, 8, &ct), data);

    let iv = [0x33u8; 16];
    let ct = crypto::cbc_encrypt(&k1, &iv, &data);
    assert_eq!(crypto::cbc_decrypt(&k1, &iv, &ct), data);

    let sector_key: Vec<u8> = (0..512).map(|i| (i * 7 % 256) as u8).collect();
    let diffused = crypto::diffuser_encrypt(&data, &sector_key);
    assert_ne!(diffused, data);
    assert_eq!(crypto::diffuser_decrypt(&diffused, &sector_key), data);
}

#[test]
fn ccm_rejects_a_tampered_blob() {
    // The MAC is what makes a wrong key a clean failure rather than garbage.
    let key = [0x44u8; 32];
    let nonce = [0x55u8; 12];
    let aes = Aes::new(&key).unwrap();
    let _ = aes; // built above to prove the key length is accepted
                 // A blob that is not a valid CCM package must not decrypt.
    assert!(crypto::ccm_decrypt(&key, &nonce, &[0u8; 48], 16).is_none());
}
