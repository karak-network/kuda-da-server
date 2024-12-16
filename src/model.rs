use alloy::{
    primitives::{Address, U256},
    sol,
};
use borsh::{BorshDeserialize, BorshSerialize};
use celestia_types::nmt::NS_SIZE;
use serde::{Deserialize, Serialize};

pub const COMMITMENT_TYPE: u8 = 0x01;
pub const DA_LAYER_BYTE: u8 = 0x6B;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KudaSubmission {
    pub client_address: Address,
    pub data: String,
    pub reward_amount: U256,
    pub reward_token: Address,
    pub acceptable_da_layers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KudaResponse {
    pub response_object: String,
}

sol! {
    struct Receipt {
        bytes1 prefix;
        bytes context;
        string commitment;
        uint256 submissionTime;
    }

    struct CelestiaContext {
        bytes29 namespace;
        uint64 height;
    }

    struct Eip4844Context {
        uint64 slot;
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) enum DaLayer {
    Celestia = 0,
    #[serde(rename = "4844")]
    Eip4844 = 1,
}

impl std::fmt::Display for DaLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaLayer::Celestia => write!(f, "Celestia"),
            DaLayer::Eip4844 => write!(f, "4844"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct DaLayerError;

impl std::fmt::Display for DaLayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid DaLayer")
    }
}

impl TryFrom<u8> for DaLayer {
    type Error = DaLayerError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DaLayer::Celestia),
            1 => Ok(DaLayer::Eip4844),
            _ => Err(DaLayerError),
        }
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct Namespace(pub [u8; NS_SIZE]);

impl From<celestia_types::nmt::Namespace> for Namespace {
    fn from(value: celestia_types::nmt::Namespace) -> Self {
        Self(value.0)
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct BlobData {
    pub namespace: Option<Namespace>,
    pub data: Vec<u8>,
}
