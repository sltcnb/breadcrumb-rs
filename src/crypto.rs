//! The cipher modes BitLocker needs, over the `aes` crate's block cipher:
//! AES-XTS, AES-CBC, AES-CCM, and the Elephant diffuser.
//!
//! Keeping the modes here rather than pulling a crate per mode means the whole
//! decryption path is one readable file, which matters for a tool whose output
//! is evidence.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

/// AES-128 or AES-256, chosen by key length.
pub enum Aes {
    A128(Box<Aes128>),
    A256(Box<Aes256>),
}

impl Aes {
    pub fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Some(Aes::A128(Box::new(Aes128::new_from_slice(key).ok()?))),
            32 => Some(Aes::A256(Box::new(Aes256::new_from_slice(key).ok()?))),
            _ => None,
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        match self {
            Aes::A128(c) => c.encrypt_block(b),
            Aes::A256(c) => c.encrypt_block(b),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        match self {
            Aes::A128(c) => c.decrypt_block(b),
            Aes::A256(c) => c.decrypt_block(b),
        }
    }

    pub fn encrypt(&self, data: &[u8; 16]) -> [u8; 16] {
        let mut b = *data;
        self.encrypt_block(&mut b);
        b
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// -------------------------------------------------------------- AES-CBC

pub fn cbc_decrypt(aes: &Aes, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks(16) {
        if chunk.len() < 16 {
            out.extend_from_slice(chunk); // trailing partial block passes through
            break;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let ct = block;
        aes.decrypt_block(&mut block);
        out.extend_from_slice(&xor(&block, &prev));
        prev = ct;
    }
    out
}

pub fn cbc_encrypt(aes: &Aes, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks(16) {
        if chunk.len() < 16 {
            out.extend_from_slice(chunk);
            break;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(&xor(chunk, &prev));
        aes.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    out
}

// -------------------------------------------------------------- AES-XTS

/// Multiply the 128-bit tweak by the primitive element x in GF(2^128).
fn gf_mul_alpha(t: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in t.iter_mut() {
        let b = *byte;
        *byte = (b << 1) | carry;
        carry = b >> 7;
    }
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

fn xts_tweak(aes_tweak: &Aes, unit: u64) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(&unit.to_le_bytes());
    aes_tweak.encrypt(&t)
}

/// Decrypt one XTS data unit; `unit` is the sector number.
pub fn xts_decrypt(aes_data: &Aes, aes_tweak: &Aes, unit: u64, data: &[u8]) -> Vec<u8> {
    let mut tweak = xts_tweak(aes_tweak, unit);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() < 16 {
            out.extend_from_slice(chunk);
            break;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(&xor(chunk, &tweak));
        aes_data.decrypt_block(&mut block);
        out.extend_from_slice(&xor(&block, &tweak));
        gf_mul_alpha(&mut tweak);
    }
    out
}

pub fn xts_encrypt(aes_data: &Aes, aes_tweak: &Aes, unit: u64, data: &[u8]) -> Vec<u8> {
    let mut tweak = xts_tweak(aes_tweak, unit);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() < 16 {
            out.extend_from_slice(chunk);
            break;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(&xor(chunk, &tweak));
        aes_data.encrypt_block(&mut block);
        out.extend_from_slice(&xor(&block, &tweak));
        gf_mul_alpha(&mut tweak);
    }
    out
}

// -------------------------------------------------------------- AES-CCM
//
// BitLocker wraps keys in AES-CCM with a 12-byte nonce and a 16-byte MAC. The
// counter blocks and the CBC-MAC follow RFC 3610 with L = 3.

fn ccm_blocks(nonce: &[u8], counter: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = 2; // L - 1, with L = 3
    let n = nonce.len().min(12);
    b[1..1 + n].copy_from_slice(&nonce[..n]);
    b[13] = ((counter >> 16) & 0xFF) as u8;
    b[14] = ((counter >> 8) & 0xFF) as u8;
    b[15] = (counter & 0xFF) as u8;
    b
}

/// Decrypt a BitLocker CCM blob: MAC(16) || ciphertext. Returns the plaintext
/// only when the recomputed MAC matches, so a wrong key is a clean failure.
pub fn ccm_decrypt(key: &[u8], nonce: &[u8], data: &[u8], mac_len: usize) -> Option<Vec<u8>> {
    if data.len() < mac_len {
        return None;
    }
    let aes = Aes::new(key)?;
    let (mac_in, ct) = data.split_at(mac_len);

    // CTR: block 0 masks the MAC, blocks 1.. mask the payload.
    let mut plain = Vec::with_capacity(ct.len());
    for (i, chunk) in ct.chunks(16).enumerate() {
        let keystream = aes.encrypt(&ccm_blocks(nonce, i as u64 + 1));
        plain.extend_from_slice(&xor(chunk, &keystream[..chunk.len()]));
    }
    let s0 = aes.encrypt(&ccm_blocks(nonce, 0));
    let mac_expected = xor(mac_in, &s0[..mac_len]);

    // CBC-MAC over the flags/nonce/length block, then the plaintext.
    let mut b0 = [0u8; 16];
    b0[0] = 0x3A; // no AAD, M = 16 => ((16-2)/2)<<3 | (L-1)
    let n = nonce.len().min(12);
    b0[1..1 + n].copy_from_slice(&nonce[..n]);
    let len = plain.len() as u32;
    b0[13] = ((len >> 16) & 0xFF) as u8;
    b0[14] = ((len >> 8) & 0xFF) as u8;
    b0[15] = (len & 0xFF) as u8;
    let mut mac = b0;
    aes.encrypt_block(&mut mac);
    for chunk in plain.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for (m, b) in mac.iter_mut().zip(block.iter()) {
            *m ^= *b;
        }
        aes.encrypt_block(&mut mac);
    }
    if mac[..mac_len] != mac_expected[..] {
        return None; // wrong key, or a damaged entry
    }
    Some(plain)
}

// -------------------------------------------------- Elephant diffuser
//
// AES-CBC + Elephant diffuser is the Vista/7 default. It works on the sector
// as an array of 32-bit little-endian words.

const DIFFUSER_A_RC: [u32; 4] = [9, 0, 13, 0];
const DIFFUSER_B_RC: [u32; 4] = [0, 10, 0, 25];

fn words(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(b)
        })
        .collect()
}

fn unwords(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn diffuser_a_decrypt(w: &mut [u32]) {
    let n = w.len();
    for _ in 0..5 {
        for i in (0..n).rev() {
            let t = w[(i + 2) % n] ^ w[(i + 5) % n].rotate_left(DIFFUSER_A_RC[i % 4]);
            w[i] = w[i].wrapping_sub(t);
        }
    }
}

fn diffuser_a_encrypt(w: &mut [u32]) {
    let n = w.len();
    for _ in 0..5 {
        for i in 0..n {
            let t = w[(i + 2) % n] ^ w[(i + 5) % n].rotate_left(DIFFUSER_A_RC[i % 4]);
            w[i] = w[i].wrapping_add(t);
        }
    }
}

fn diffuser_b_decrypt(w: &mut [u32]) {
    let n = w.len();
    for _ in 0..3 {
        for i in (0..n).rev() {
            let t = w[(i + n - 2) % n] ^ w[(i + n - 5) % n].rotate_left(DIFFUSER_B_RC[i % 4]);
            w[i] = w[i].wrapping_sub(t);
        }
    }
}

fn diffuser_b_encrypt(w: &mut [u32]) {
    let n = w.len();
    for _ in 0..3 {
        for i in 0..n {
            let t = w[(i + n - 2) % n] ^ w[(i + n - 5) % n].rotate_left(DIFFUSER_B_RC[i % 4]);
            w[i] = w[i].wrapping_add(t);
        }
    }
}

/// Undo B, undo A, then XOR the sector key. Input is the CBC-decrypted sector.
pub fn diffuser_decrypt(data: &[u8], sector_key: &[u8]) -> Vec<u8> {
    let mut w = words(data);
    diffuser_b_decrypt(&mut w);
    diffuser_a_decrypt(&mut w);
    xor(&unwords(&w), sector_key)
}

/// XOR the sector key, apply A, then B. Output feeds AES-CBC-encrypt.
pub fn diffuser_encrypt(data: &[u8], sector_key: &[u8]) -> Vec<u8> {
    let mixed = xor(data, sector_key);
    let mut w = words(&mixed);
    diffuser_a_encrypt(&mut w);
    diffuser_b_encrypt(&mut w);
    unwords(&w)
}
