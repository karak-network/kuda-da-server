use std::sync::Arc;

use alloy::primitives::{Address, U256};
use celestia_types::nmt::Namespace;
use url::Url;

use crate::model::DaLayer;

#[derive(Clone)]
pub(crate) struct Config {
    pub kuda_url: Url,
    pub namespace: Option<Namespace>,
    pub client_address: Address,
    pub reward_token: Address,
    pub reward_amount: U256,
    pub da_layers: Vec<DaLayer>,
    pub celestia_client: Arc<celestia_rpc::Client>,
    pub beacon_rpc_url: Url,
}
