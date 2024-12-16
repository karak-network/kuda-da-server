use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, U256},
    providers::WsConnect,
};
use axum::{
    routing::{get, post},
    Router,
};
use celestia_rpc::client::Client;
use celestia_types::nmt::Namespace;
use config::Config;
use contract::Kuda::KudaInstance;
use eyre::Result;
use handlers::{get_commitment, put_commitment};
use model::DaLayer;
use serde::Deserialize;
use tokio::{net::TcpListener, signal};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;

mod config;
mod contract;
mod handlers;
mod model;

#[derive(Debug, Clone, Deserialize)]
struct EnvConfig {
    pub kuda_url: Url,
    pub namespace: Option<Namespace>,
    pub client_address: Address,
    pub reward_token: Address,
    pub reward_amount: U256,
    pub da_layers: Vec<DaLayer>,
    pub kuda_address: Address,
    pub kuda_rpc_url: Url,
    pub celestia_rpc_url: String,
    pub beacon_rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let config = envy::from_env::<EnvConfig>()?;

    let kuda_provider = alloy::providers::ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(WsConnect::new(config.kuda_rpc_url))
        .await?;

    let kuda_instance = KudaInstance::new(config.kuda_address, kuda_provider.clone());

    let celestia_client = Arc::new(Client::new(&config.celestia_rpc_url, None).await?);

    let state = Arc::new(handlers::ServerState {
        config: Config {
            kuda_url: config.kuda_url,
            namespace: config.namespace,
            client_address: config.client_address,
            reward_token: config.reward_token,
            reward_amount: config.reward_amount,
            da_layers: config.da_layers,
            celestia_client,
            beacon_rpc_url: config.beacon_rpc_url,
        },
        client: reqwest::Client::new(),
        kuda_instance,
        kuda_provider,
    });

    // log level filtering here
    let filter_layer = EnvFilter::from_default_env();

    // fmt layer - printing out logs
    let fmt_layer = fmt::layer().compact();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let app = Router::new()
        .route("/put", post(put_commitment))
        .route("/get/:commitment", get(get_commitment))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(300)));

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    // Run the server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, shutting down")
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, shutting down")
        },
    }
}
