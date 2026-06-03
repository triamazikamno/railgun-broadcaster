use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Instant;

use bech32::{Bech32m, Hrp};
use eyre::{Result, WrapErr, bail, eyre};
use getrandom::fill;
use railgun_wallet::{ViewingKeyData, WalletKeys, bip39_mnemonic_from_entropy};
use structopt::StructOpt;

const DERIVATION_INDEX: u32 = 0;
const BIP39_ENTROPY_LEN: usize = 32;
const RAILGUN_ADDRESS_PAYLOAD_LEN: usize = 73;
const RAILGUN_ADDRESS_HRP: &str = "0zk";
const ALL_CHAINS_NETWORK_BYTES: [u8; 8] = [0x8d, 0x9e, 0x96, 0x93, 0x98, 0x8a, 0x91, 0xff];
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Debug, StructOpt)]
#[structopt(name = "vanity-address")]
struct Options {
    /// Suffix to match at the end of the all-chains 0zk address.
    #[structopt(long)]
    suffix: String,
    /// Number of worker threads. Defaults to available CPU parallelism.
    #[structopt(long)]
    threads: Option<usize>,
}

struct Candidate {
    address: String,
    entropy: [u8; BIP39_ENTROPY_LEN],
    attempts: u64,
}

struct SuffixMatcher {
    tail: Vec<u8>,
    written: usize,
}

enum SearchMessage {
    Found(Candidate),
    Error(String),
}

fn main() -> Result<()> {
    let options = Options::from_args();
    let suffix = normalize_suffix(&options.suffix)?;
    let thread_count = options.threads.unwrap_or_else(default_thread_count);
    if thread_count == 0 {
        bail!("--threads must be greater than zero");
    }

    eprintln!(
        "Searching for all-chains 0zk address suffix '{suffix}' with {thread_count} worker(s)"
    );
    let start = Instant::now();
    let found = search_suffix(&suffix, thread_count)?;
    let elapsed = start.elapsed();
    let mnemonic = bip39_mnemonic_from_entropy(&found.entropy).wrap_err("encode mnemonic")?;

    println!("address: {}", found.address);
    println!("mnemonic: {mnemonic}");
    println!("attempts: {}", found.attempts);
    println!("elapsed: {elapsed:.2?}");

    Ok(())
}

fn search_suffix(suffix: &str, thread_count: usize) -> Result<Candidate> {
    let done = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        let suffix = suffix.to_string();
        let done = Arc::clone(&done);
        let attempts = Arc::clone(&attempts);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            search_worker(&suffix, done.as_ref(), attempts.as_ref(), &tx);
        }));
    }
    drop(tx);

    let result = match rx
        .recv()
        .wrap_err("search workers exited without a match")?
    {
        SearchMessage::Found(candidate) => Ok(candidate),
        SearchMessage::Error(message) => Err(eyre!(message)),
    };
    done.store(true, Ordering::Relaxed);

    for handle in handles {
        handle.join().map_err(|_| eyre!("search worker panicked"))?;
    }

    result
}

fn search_worker(
    suffix: &str,
    done: &AtomicBool,
    attempts: &AtomicU64,
    tx: &Sender<SearchMessage>,
) {
    let suffix = suffix.as_bytes();
    let hrp = match railgun_address_hrp() {
        Ok(hrp) => hrp,
        Err(err) => {
            done.store(true, Ordering::Relaxed);
            let _ = tx.send(SearchMessage::Error(format!("{err:#}")));
            return;
        }
    };
    let mut matcher = SuffixMatcher::new(suffix.len());
    while !done.load(Ordering::Relaxed) {
        match generate_candidate(suffix, hrp, &mut matcher) {
            Ok(candidate) => {
                let current_attempts = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(mut candidate) = candidate {
                    candidate.attempts = current_attempts;
                    done.store(true, Ordering::Relaxed);
                    let _ = tx.send(SearchMessage::Found(candidate));
                    return;
                }
            }
            Err(err) => {
                done.store(true, Ordering::Relaxed);
                let _ = tx.send(SearchMessage::Error(format!("{err:#}")));
                return;
            }
        }
    }
}

fn generate_candidate(
    suffix: &[u8],
    hrp: Hrp,
    matcher: &mut SuffixMatcher,
) -> Result<Option<Candidate>> {
    let mut entropy = [0u8; BIP39_ENTROPY_LEN];
    fill(&mut entropy).map_err(|err| eyre!("generate entropy: {err:?}"))?;
    let wallet = WalletKeys::from_bip39_entropy(&entropy, DERIVATION_INDEX)
        .wrap_err("derive Railgun wallet")?;
    let payload = all_chains_address_payload(&wallet.viewing);
    matcher.reset();
    bech32::encode_to_writer::<Bech32m, _>(matcher, hrp, &payload)
        .map_err(|err| eyre!("encode all-chains address: {err}"))?;
    if !matcher.ends_with(suffix) {
        return Ok(None);
    }
    let address = bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|err| eyre!("encode matching all-chains address: {err}"))?;

    Ok(Some(Candidate {
        address,
        entropy,
        attempts: 0,
    }))
}

fn all_chains_address_payload(viewing: &ViewingKeyData) -> [u8; RAILGUN_ADDRESS_PAYLOAD_LEN] {
    let mut payload = [0u8; RAILGUN_ADDRESS_PAYLOAD_LEN];
    payload[0] = 0x01;
    payload[1..33].copy_from_slice(&viewing.master_public_key.to_be_bytes::<32>());
    payload[33..41].copy_from_slice(&ALL_CHAINS_NETWORK_BYTES);
    payload[41..73].copy_from_slice(&viewing.viewing_public_key);
    payload
}

fn railgun_address_hrp() -> Result<Hrp> {
    Hrp::parse(RAILGUN_ADDRESS_HRP).map_err(|_| eyre!("invalid Railgun address HRP"))
}

impl SuffixMatcher {
    fn new(suffix_len: usize) -> Self {
        Self {
            tail: vec![0u8; suffix_len],
            written: 0,
        }
    }

    const fn reset(&mut self) {
        self.written = 0;
    }

    fn record(&mut self, bytes: &[u8]) {
        if self.tail.is_empty() {
            return;
        }
        let tail_len = self.tail.len();
        for byte in bytes {
            self.tail[self.written % tail_len] = *byte;
            self.written += 1;
        }
    }

    fn ends_with(&self, suffix: &[u8]) -> bool {
        if suffix.is_empty() || self.written < suffix.len() || suffix.len() != self.tail.len() {
            return false;
        }

        let start = self.written % self.tail.len();
        suffix
            .iter()
            .enumerate()
            .all(|(index, byte)| self.tail[(start + index) % self.tail.len()] == *byte)
    }
}

impl io::Write for SuffixMatcher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.record(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn normalize_suffix(suffix: &str) -> Result<String> {
    let suffix = suffix.trim();
    if suffix.is_empty() {
        bail!("--suffix must not be empty");
    }
    if !suffix.is_ascii() {
        bail!("--suffix must contain only ASCII Bech32 characters");
    }

    let normalized = suffix.to_ascii_lowercase();
    if let Some(invalid) = normalized
        .chars()
        .find(|char| !BECH32_CHARSET.contains(*char))
    {
        bail!("suffix contains '{invalid}', which cannot appear at the end of a 0zk address");
    }

    Ok(normalized)
}

fn default_thread_count() -> usize {
    thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_suffix_accepts_bech32_suffix_chars() {
        assert_eq!(normalize_suffix("Xx90").expect("valid suffix"), "xx90");
    }

    #[test]
    fn normalize_suffix_rejects_empty_suffix() {
        assert!(normalize_suffix(" ").is_err());
    }

    #[test]
    fn normalize_suffix_rejects_impossible_bech32_suffix_chars() {
        assert!(normalize_suffix("b").is_err());
        assert!(normalize_suffix("1").is_err());
    }

    #[test]
    fn fixed_entropy_derives_all_chains_0zk_address() {
        let entropy = [0u8; BIP39_ENTROPY_LEN];
        let wallet =
            WalletKeys::from_bip39_entropy(&entropy, DERIVATION_INDEX).expect("derive wallet");
        let address = wallet
            .viewing
            .derive_address(None)
            .expect("derive all-chains address")
            .to_string();
        assert!(address.starts_with("0zk1"));
    }

    #[test]
    fn direct_payload_encoding_matches_core_address_encoding() {
        let entropy = [0u8; BIP39_ENTROPY_LEN];
        let wallet =
            WalletKeys::from_bip39_entropy(&entropy, DERIVATION_INDEX).expect("derive wallet");
        let payload = all_chains_address_payload(&wallet.viewing);
        let encoded =
            bech32::encode::<Bech32m>(railgun_address_hrp().expect("valid hrp"), &payload)
                .expect("encode address");
        let core_encoded = wallet
            .viewing
            .derive_address(None)
            .expect("derive all-chains address")
            .to_string();

        assert_eq!(encoded, core_encoded);
    }

    #[test]
    fn suffix_matcher_tracks_trailing_bytes() {
        let mut matcher = SuffixMatcher::new(4);

        io::Write::write_all(&mut matcher, b"0zk1abcdef").expect("write address");
        assert!(matcher.ends_with(b"cdef"));
        assert!(!matcher.ends_with(b"bcde"));

        matcher.reset();
        io::Write::write_all(&mut matcher, b"abcd").expect("write exact suffix length");
        assert!(matcher.ends_with(b"abcd"));

        io::Write::write_all(&mut matcher, b"e").expect("write one more byte");
        assert!(matcher.ends_with(b"bcde"));
    }
}
