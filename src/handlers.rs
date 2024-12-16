use std::{str::FromStr, sync::Arc, time::Duration};

use crate::{
    config::Config,
    contract::Kuda::{KudaInstance, ReceiptSubmitted},
    model::{
        BlobData, CelestiaContext, DaLayer, DaLayerError, Eip4844Context, KudaResponse,
        KudaSubmission, COMMITMENT_TYPE, DA_LAYER_BYTE,
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    hex,
    primitives::{Bytes, FixedBytes},
    providers::Provider,
    rpc::types::{beacon::sidecar::BeaconBlobBundle, Filter},
    sol_types::SolValue,
    transports::Transport,
};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use celestia_rpc::BlobClient;
use futures::StreamExt;
use http::StatusCode;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct ServerState<T: Transport + Clone, P: Provider<T> + Clone> {
    pub config: Config,
    pub client: reqwest::Client,
    pub kuda_instance: KudaInstance<T, P>,
    pub kuda_provider: P,
}

#[derive(Debug, Error)]
pub enum DaError {
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Kuda error: {0:?}")]
    Kuda(reqwest::Response),
    #[error("Alloy transport error: {0}")]
    AlloyTransport(#[from] alloy::transports::TransportError),
    #[error("Alloy sol types error: {0}")]
    AlloySolTypes(#[from] alloy::sol_types::Error),
    #[error("Alloy contract error: {0}")]
    AlloyContract(#[from] alloy::contract::Error),
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("Request timed out")]
    Timeout,
    #[error("Stream ended unexpectedly")]
    StreamEnded,
    #[error("Invalid DaLayer")]
    DaLayer(#[from] DaLayerError),
    #[error("Byte conversion error")]
    ByteConversion,
    #[error("Celestia json rpc error: {0}")]
    Celestia(#[from] jsonrpsee_core::ClientError),
    #[error("Url parsing error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Beacon rpc error")]
    BeaconRpc,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Celestia namespace not set")]
    CelestiaNamespaceNotSet,
    #[error("Celestia types error: {0}")]
    CelestiaTypes(#[from] celestia_types::Error),
    #[error("Uuid error: {0}")]
    Uuid(#[from] uuid::Error),
}

impl IntoResponse for DaError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{self}");
        let json = axum::response::Json(self.to_string());
        let response = (StatusCode::INTERNAL_SERVER_ERROR, json);
        axum::response::IntoResponse::into_response(response)
    }
}

pub type DaResult<T> = Result<T, DaError>;

pub async fn put_commitment<T: Transport + Clone, P: Provider<T> + Clone>(
    State(state): State<Arc<ServerState<T, P>>>,
    data: axum::body::Bytes,
) -> DaResult<String> {
    if state.config.da_layers.contains(&DaLayer::Celestia) && state.config.namespace.is_none() {
        return Err(DaError::CelestiaNamespaceNotSet);
    }

    let blob = BlobData {
        data: data.to_vec(),
        namespace: state.config.namespace.map(crate::model::Namespace::from),
    };
    let blob_bytes = borsh::to_vec(&blob)?;

    let submission = KudaSubmission {
        client_address: state.config.client_address,
        data: BASE64_STANDARD.encode(blob_bytes),
        reward_amount: state.config.reward_amount,
        reward_token: state.config.reward_token,
        acceptable_da_layers: state
            .config
            .da_layers
            .iter()
            .map(|l| l.to_string())
            .collect(),
    };

    tracing::info!("Submitting data to Kuda: {:?}", submission);

    let response = state
        .client
        .post(
            state
                .config
                .kuda_url
                .clone()
                .join("/aggregator/submitData")?,
        )
        .json(&submission)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DaError::Kuda(response));
    }

    let task_id = Uuid::from_str(&response.json::<KudaResponse>().await?.response_object)?;

    let receipt = tokio::time::timeout(
        Duration::from_secs(300),
        listen_for_receipt(
            task_id,
            state.kuda_instance.clone(),
            state.kuda_provider.clone(),
        ),
    )
    .await
    .map_err(|_| DaError::Timeout)??;

    let mut commitment_bytes = vec![];
    commitment_bytes.push(COMMITMENT_TYPE);
    commitment_bytes.push(DA_LAYER_BYTE);
    commitment_bytes.extend_from_slice(receipt.as_slice());

    let commitment = hex::encode(&commitment_bytes);

    Ok(commitment)
}

async fn listen_for_receipt<T: Transport + Clone, P: Provider<T> + Clone>(
    task_id: Uuid,
    kuda_instance: KudaInstance<T, P>,
    kuda_provider: P,
) -> DaResult<FixedBytes<16>> {
    tracing::info!("Listening for receipt: {task_id}");
    let filter = Filter::new()
        .address(*kuda_instance.address())
        .from_block(BlockNumberOrTag::Latest);
    tracing::info!("Filter: {:?}", filter);
    let mut stream = kuda_provider.subscribe_logs(&filter).await?.into_stream();

    while let Some(log) = stream.next().await {
        let log = log.log_decode::<ReceiptSubmitted>()?;
        let receipt = log.inner.data;
        tracing::info!("Received receipt: {}", receipt.taskId);
        if Uuid::from_slice(receipt.taskId.as_slice())? == task_id {
            let receipt = receipt.taskId;
            return Ok(receipt);
        }
    }

    Err(DaError::StreamEnded)
}

pub async fn get_commitment<T: Transport + Clone, P: Provider<T> + Clone>(
    State(state): State<Arc<ServerState<T, P>>>,
    Path(commitment): Path<String>,
) -> DaResult<Vec<u8>> {
    let bytes = hex::decode(&commitment)?;
    let receipt = state
        .kuda_instance
        .submittedReceipt(FixedBytes::<16>::from_slice(&bytes[2..]))
        .call()
        .await?;

    let da_layer = DaLayer::try_from(receipt.daLayer)?;
    let context = receipt.context;
    let commitment = receipt.commitment;

    match da_layer {
        DaLayer::Celestia => {
            get_celestia_commitment(&state.config.celestia_client, &context, &commitment).await
        }
        DaLayer::Eip4844 => {
            get_eip4844_commitment(
                &state.client,
                &state.config.beacon_rpc_url,
                &context,
                &commitment,
            )
            .await
        }
    }
}

async fn get_celestia_commitment(
    celestia_client: &celestia_rpc::Client,
    context: &Bytes,
    commitment: &[u8],
) -> DaResult<Vec<u8>> {
    let celestia_context = CelestiaContext::abi_decode(context, true)?;
    let namespace = celestia_types::nmt::Namespace::from_raw(&celestia_context.namespace.0)?;
    let commitment = celestia_types::Commitment(
        hex::decode(commitment)?
            .try_into()
            .map_err(|_| DaError::ByteConversion)?,
    );
    let blob = celestia_client
        .blob_get(celestia_context.height, namespace, commitment)
        .await?;

    Ok(blob.data)
}

async fn get_eip4844_commitment(
    client: &reqwest::Client,
    beacon_rpc_url: &Url,
    context: &Bytes,
    commitment: &[u8],
) -> DaResult<Vec<u8>> {
    let Eip4844Context { slot } = Eip4844Context::abi_decode(context, true)?;
    let response = client
        .get(beacon_rpc_url.join(&format!("eth/v1/beacon/blob_sidecars/{slot}"))?)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DaError::BeaconRpc);
    }

    let bundle = response.json::<BeaconBlobBundle>().await?;
    let blob = bundle
        .into_iter()
        .find(|blob| blob.kzg_commitment == commitment)
        .ok_or(DaError::BeaconRpc)?;

    Ok(blob.blob.to_vec())
}
