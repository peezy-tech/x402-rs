//! Ignored end-to-end test for Hyperliquid integration.
//! Requires real payloads plus env configuration described below.
//!
//! Required env variables when running (example):
//! - `HYPERLIQUID_ENV=testnet`
//! - `HYPERLIQUID_BASE_URL=https://api.hyperliquid-testnet.xyz`
//! - `HYPERLIQUID_EXCHANGE_URL=https://api.hyperliquid-testnet.xyz/exchange`
//! - `HL_TEST_NETWORK=hyperliquid-testnet`
//! - `HL_TEST_VERIFY_REQUEST=<raw JSON VerifyRequest>`
//! - `HL_TEST_SETTLE_REQUEST=<raw JSON SettleRequest>`

use x402_rs::chain::hyperliquid::HyperliquidProvider;
use x402_rs::chain::FromEnvByNetworkBuild;
use x402_rs::network::Network;
use x402_rs::types::{SettleRequest, VerifyRequest, VerifyResponse};
use x402_rs::facilitator::Facilitator;

#[tokio::test]
#[ignore = "Requires Hyperliquid testnet credentials and payloads"]
async fn hyperliquid_verify_and_settle_e2e() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let network = std::env::var("HL_TEST_NETWORK")
        .ok()
        .as_deref()
        .map(parse_network)
        .transpose()?
        .unwrap_or(Network::HyperliquidTestnet);

    let provider = HyperliquidProvider::from_env(network)
        .await?
        .expect("Hyperliquid provider configured");

    let verify_request =
        std::env::var("HL_TEST_VERIFY_REQUEST").map_err(|_| "HL_TEST_VERIFY_REQUEST missing")?;
    let verify_request: VerifyRequest = serde_json::from_str(&verify_request)?;
    let verify_result = provider.verify(&verify_request).await?;
    match verify_result {
        VerifyResponse::Valid { .. } => {}
        other => panic!("Verify failed: {:?}", other),
    }

    if let Ok(settle_request) = std::env::var("HL_TEST_SETTLE_REQUEST") {
        let settle_request: SettleRequest = serde_json::from_str(&settle_request)?;
        let _ = provider.settle(&settle_request).await?;
    }

    Ok(())
}

fn parse_network(value: &str) -> Result<Network, Box<dyn std::error::Error>> {
    match value {
        "hyperliquid" => Ok(Network::HyperliquidMainnet),
        "hyperliquid-testnet" => Ok(Network::HyperliquidTestnet),
        other => Err(format!("Unknown Hyperliquid network {other}").into()),
    }
}
