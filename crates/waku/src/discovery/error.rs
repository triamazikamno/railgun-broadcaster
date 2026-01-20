/// Errors that can occur during DNS resolution (`DoH` or system resolver).
#[derive(Debug, thiserror::Error)]
pub enum DnsResolveError {
    #[error("HTTP client build failed: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("system resolver build failed: {0}")]
    SystemResolverBuild(#[from] hickory_resolver::ResolveError),
    #[error("system TXT lookup failed for {domain}: {source}")]
    SystemLookup {
        domain: String,
        #[source]
        source: hickory_resolver::ResolveError,
    },
    #[error("DoH request failed: {0}")]
    DohRequest(#[source] reqwest::Error),
    #[error("DoH JSON parse failed: {0}")]
    DohParse(#[source] reqwest::Error),
}

/// Errors that can occur when decoding an ENR record.
#[derive(Debug, thiserror::Error)]
pub enum EnrDecodeError {
    #[error("invalid ENR text: {0}")]
    InvalidEnrText(String),
    #[error("invalid ENR bytes: {0}")]
    InvalidEnrBytes(#[from] alloy_rlp::Error),
    #[error("ENR missing waku2 field")]
    MissingWaku2,
    #[error("ENR missing secp256k1 pubkey")]
    MissingSecp256k1,
    #[error("invalid secp256k1 pubkey: {0}")]
    InvalidSecp256k1(#[from] libp2p::identity::DecodingError),
    #[error("invalid multiaddr: {0}")]
    InvalidMultiaddr(#[from] libp2p::multiaddr::Error),
}

/// Errors that can occur during ENR tree traversal.
#[derive(Debug, thiserror::Error)]
pub enum EnrTreeError {
    #[error("invalid tree URL: must start with 'enrtree://'")]
    InvalidTreeUrlPrefix,
    #[error("invalid tree URL: missing '@' separator")]
    InvalidTreeUrlFormat,
    #[error("missing root TXT record at {0}")]
    MissingRoot(String),
    #[error("invalid root format: must start with 'enrtree-root:'")]
    InvalidRootPrefix,
    #[error("invalid root format: regex did not match")]
    InvalidRootFormat,
    #[error("invalid branch format: must start with 'enrtree-branch:'")]
    InvalidBranchPrefix,
    #[error("base32 decode failed: {0}")]
    Base32Decode(#[from] data_encoding::DecodeError),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[from] k256::ecdsa::Error),
    #[error("base64url decode failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("invalid signature length: expected at least 64 bytes")]
    InvalidSignatureLength,
    #[error("invalid signature: {0}")]
    InvalidSignature(#[source] k256::ecdsa::Error),
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("DNS resolution failed: {0}")]
    Dns(#[from] DnsResolveError),
}

/// Top-level discovery errors.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("DNS resolver initialization failed: {0}")]
    ResolverInit(#[from] DnsResolveError),
    #[error("ENR tree traversal failed: {0}")]
    EnrTree(#[from] EnrTreeError),
}
