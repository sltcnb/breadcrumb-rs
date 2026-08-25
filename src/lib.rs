//! Signature-based file carver for disk images and block devices.
//!
//! A Rust port of the carving core of BreadCrumb (https://github.com/sltcnb/BreadCrumb):
//! scan raw bytes for file headers, parse each candidate's structure to find
//! its true end, and write the recovered bytes out with a SHA-256 manifest.
//! No filesystem metadata is needed or consulted.

pub mod bitlocker;
pub mod carver;
pub mod checkpoint;
pub mod crypto;
pub mod ewf;
pub mod grep;
pub mod handlers;
pub mod images;
pub mod json;
pub mod ntfs;
pub mod partition;
pub mod reader;
pub mod report;
pub mod signatures;
pub mod verify;
pub mod window;
