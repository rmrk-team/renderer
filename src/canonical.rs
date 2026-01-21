use crate::config::Config;
use ethers::types::Address;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum CanonicalizeError {
    #[error("invalid chain")]
    InvalidChain,
    #[error("unknown chain")]
    UnknownChain,
    #[error("invalid collection address")]
    InvalidCollectionAddress,
}

pub fn canonicalize_chain(chain: &str, config: &Config) -> Result<String, CanonicalizeError> {
    let normalized = canonicalize_chain_unchecked(chain)?;
    if !config.render_utils_addresses.contains_key(&normalized) {
        return Err(CanonicalizeError::UnknownChain);
    }
    Ok(normalized)
}

pub fn canonicalize_chain_unchecked(chain: &str) -> Result<String, CanonicalizeError> {
    let normalized = chain.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 64
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.contains("..")
        || normalized.contains('\0')
    {
        return Err(CanonicalizeError::InvalidChain);
    }
    Ok(normalized)
}

pub fn canonicalize_collection_address(address: &str) -> Result<String, CanonicalizeError> {
    let addr =
        Address::from_str(address).map_err(|_| CanonicalizeError::InvalidCollectionAddress)?;
    Ok(format!("{:#x}", addr))
}

pub fn canonicalize_collection(
    chain: &str,
    collection_address: &str,
    config: &Config,
) -> Result<(String, String), CanonicalizeError> {
    Ok((
        canonicalize_chain(chain, config)?,
        canonicalize_collection_address(collection_address)?,
    ))
}
