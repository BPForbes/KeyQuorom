use std::fmt;

#[derive(Debug)]
pub enum Error {
    Db(rusqlite::Error),
    Io(std::io::Error),
    InvalidPath,
    KeyDerivationFailed,
    InvalidPassword,
    InvalidShareToken,
    ShareExpired,
    ShareRevoked,
    ShareExhausted,
    InvalidExpiresAt,
    ExpiresAtInPast,
    FileExpired,
    IntegrityCheckFailed,
    QuorumNotMet,
    InvalidQuorumThreshold,
    InvalidTreeSpec,
    KeyRevoked,
    WrongKeyType,
    InvalidPublicKey,
    SignatureVerificationFailed,
    PinMismatch,
    PinLocked,
    PinNotSet,
    InvalidPin,
    BundleFieldTooLarge,
    NodeNotFound,
    DuplicateNodeLabel,
    InvalidBridge,
    BridgeNotWhitelisted,
    BridgeNotFound,
    CannotEvict,
    CannotAddLeaf,
    ShareShapeMismatch,
    InvalidBridgePackage,
    NotBridgeMember,
    TooFewBridgeMembers,
    BridgeDestroyed,
    BridgeGenerationMismatch,
    SealedKeyNotHeld,
    /// Two parties whose node labels differ but reduce to the same delivery
    /// file name, which would leave one of them without an envelope.
    AmbiguousDeliveryName(String),
    InvalidApiKey,
    InvalidApiKeyRequest,
    ApiKeyExpired,
    ApiKeyRevoked,
    ApiKeyScopeDenied,
    ApiKeyNotFound,
    InvalidLicenseeKey,
    OrganizationDatabase,
    InvalidInboxPage,
    RelayRequest(String),
    TreeNotFound,
    StalePublicTree,
    InvalidProviderCertificate,
    ProviderCertificateRevoked,
    ProviderCertificateExpired,
    ProviderCapabilityDenied,
    RelayIdentityMismatch,
    InvalidProviderChallenge,
    UntrustedRelay,
    ProviderIdentityMissing,
    InvalidRootNetwork,
    RootNetworkRequired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "database error: {e}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::InvalidPath => write!(f, "path is not valid UTF-8"),
            Error::KeyDerivationFailed => write!(f, "key derivation failed"),
            Error::InvalidPassword => write!(f, "incorrect password"),
            Error::InvalidShareToken => write!(f, "invalid share token"),
            Error::ShareExpired => write!(f, "share link has expired"),
            Error::ShareRevoked => write!(f, "share link has been revoked"),
            Error::ShareExhausted => write!(f, "share link has reached its use limit"),
            Error::InvalidExpiresAt => {
                write!(f, "expiry must be yyyy-mm-dd hh:mm (UTC)")
            }
            Error::ExpiresAtInPast => write!(f, "expiry must be a future UTC time"),
            Error::FileExpired => {
                write!(f, "file has expired and has been removed from disk")
            }
            Error::IntegrityCheckFailed => write!(f, "decrypted content failed integrity check"),
            Error::QuorumNotMet => write!(f, "not enough valid shares to reconstruct this key"),
            Error::InvalidQuorumThreshold => {
                write!(f, "threshold must be between 1 and the number of children")
            }
            Error::InvalidTreeSpec => write!(f, "tree snapshot is malformed"),
            Error::KeyRevoked => write!(f, "hardware key has been revoked"),
            Error::WrongKeyType => write!(f, "hardware key is not the required type"),
            Error::InvalidPublicKey => write!(f, "public key is malformed"),
            Error::SignatureVerificationFailed => write!(f, "signature does not match"),
            Error::PinMismatch => write!(f, "incorrect PIN"),
            Error::PinLocked => write!(f, "PIN is locked after too many incorrect attempts"),
            Error::PinNotSet => write!(f, "no PIN is set for this resource"),
            Error::InvalidPin => write!(f, "PIN must be exactly 4 digits"),
            Error::BundleFieldTooLarge => {
                write!(f, "export bundle field exceeds its encodable length")
            }
            Error::NodeNotFound => write!(f, "no node with that label or id exists in this key"),
            Error::DuplicateNodeLabel => {
                write!(f, "each node label in a key tree must be unique")
            }
            Error::InvalidBridge => {
                write!(
                    f,
                    "bridge peer is missing, refers to this node, or is not in this key"
                )
            }
            Error::BridgeNotWhitelisted => {
                write!(f, "cross-branch link is not whitelisted by either node")
            }
            Error::BridgeNotFound => {
                write!(f, "no established cross-branch link between those nodes")
            }
            Error::CannotEvict => {
                write!(
                    f,
                    "this leaf cannot be evicted (not an active leaf, parent threshold is 1, remaining siblings cannot meet the threshold, or a sibling is not a leaf)"
                )
            }
            Error::CannotAddLeaf => {
                write!(
                    f,
                    "cannot add a leaf here (parent is not a split of active leaves, or adding would exceed 255 children)"
                )
            }
            Error::ShareShapeMismatch => {
                write!(f, "shares must share an x-coordinate and y-length")
            }
            Error::InvalidBridgePackage => {
                write!(f, "private-bridge package is malformed or not for this key")
            }
            Error::NotBridgeMember => {
                write!(f, "that node is not a member of this private bridge")
            }
            Error::TooFewBridgeMembers => {
                write!(
                    f,
                    "a private sign bridge needs at least two distinct members"
                )
            }
            Error::BridgeDestroyed => write!(f, "this private bridge has been destroyed"),
            Error::BridgeGenerationMismatch => {
                write!(
                    f,
                    "private-bridge package generation does not match local state"
                )
            }
            Error::SealedKeyNotHeld => {
                write!(
                    f,
                    "this store does not hold a sealed bridge secret for that member"
                )
            }
            Error::AmbiguousDeliveryName(file) => {
                write!(
                    f,
                    "two bridge parties both map to the delivery file {file}; rename one node label"
                )
            }
            Error::InvalidApiKey => write!(f, "invalid API key"),
            Error::InvalidApiKeyRequest => {
                write!(
                    f,
                    "API key request is malformed (scope, fingerprint, or expiry)"
                )
            }
            Error::ApiKeyExpired => write!(f, "API key has expired"),
            Error::ApiKeyRevoked => write!(f, "API key has been revoked"),
            Error::ApiKeyScopeDenied => write!(f, "API key is not permitted for this operation"),
            Error::ApiKeyNotFound => write!(f, "no API key with that id exists"),
            Error::InvalidLicenseeKey => {
                write!(
                    f,
                    "invalid licensee key; only the licensee can mint or rotate API keys"
                )
            }
            Error::OrganizationDatabase => write!(
                f,
                "this SQLite file is an organization database; the mailbox needs a separate database"
            ),
            Error::InvalidInboxPage => {
                write!(f, "inbox page size must be between 1 and 500")
            }
            Error::RelayRequest(msg) => write!(f, "relay request failed: {msg}"),
            Error::TreeNotFound => write!(f, "no published tree with that label exists"),
            Error::StalePublicTree => {
                write!(
                    f,
                    "public tree generation is older than the copy already stored"
                )
            }
            Error::InvalidProviderCertificate => {
                write!(f, "provider certificate is missing or invalid")
            }
            Error::ProviderCertificateRevoked => {
                write!(f, "provider certificate has been revoked")
            }
            Error::ProviderCertificateExpired => write!(f, "provider certificate has expired"),
            Error::ProviderCapabilityDenied => {
                write!(f, "provider certificate lacks required capabilities")
            }
            Error::RelayIdentityMismatch => {
                write!(
                    f,
                    "relay private key does not match the provider certificate"
                )
            }
            Error::InvalidProviderChallenge => write!(f, "provider identity challenge is invalid"),
            Error::UntrustedRelay => write!(
                f,
                "relay did not present a trusted KeyQuorum provider identity"
            ),
            Error::ProviderIdentityMissing => {
                write!(
                    f,
                    "mailbox host is not configured with a provider identity"
                )
            }
            Error::InvalidRootNetwork => write!(f, "root-network CIDR is malformed"),
            Error::RootNetworkRequired => write!(
                f,
                "provider root keys can only be generated on an authorized VPN tunnel"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
