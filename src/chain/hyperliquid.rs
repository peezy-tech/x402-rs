use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::hex;
use alloy::primitives::{
    Address as AlloyAddress, B256, Signature as AlloySignature, U256 as AlloyU256,
};
use async_trait::async_trait;
use ethers_core::types::{H160, transaction::eip712::Eip712};
use hyperliquid_rust_sdk::{Actions, BaseUrl, InfoClient, SpotSend, UserTokenBalanceResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::instrument;

use crate::chain::{FacilitatorLocalError, FromEnvByNetworkBuild, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::from_env::{
    hyperliquid_base_url_override, hyperliquid_env_from_env, hyperliquid_exchange_url_override,
    hyperliquid_poll_interval_ms, hyperliquid_poll_timeout_ms,
};
use crate::network::Network;
use crate::types::{
    EvmAddress, ExactHyperliquidPayload, ExactPaymentPayload, MixedAddress, PaymentRequirements,
    Scheme, SettleRequest, SettleResponse, SupportedPaymentKind, SupportedPaymentKindsResponse,
    TransactionHash, VerifyRequest, VerifyResponse, X402Version,
};

const DEFAULT_POLL_INTERVAL_MS: u64 = 500;
const DEFAULT_POLL_TIMEOUT_MS: u64 = 20_000;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

type DynInfo = Arc<dyn HyperliquidInfo + Send + Sync>;
type DynExchange = Arc<dyn HyperliquidExchange + Send + Sync>;

#[derive(Clone)]
pub struct HyperliquidProvider {
    network: Network,
    info: DynInfo,
    exchange: DynExchange,
    tokens: TokenRegistry,
    poll: HyperliquidPollConfig,
}

impl HyperliquidProvider {
    pub(crate) fn new(
        network: Network,
        info: DynInfo,
        exchange: DynExchange,
        tokens: TokenRegistry,
        poll: HyperliquidPollConfig,
    ) -> Self {
        Self {
            network,
            info,
            exchange,
            tokens,
            poll,
        }
    }

    async fn load_token_registry(info: &InfoClient) -> Result<TokenRegistry, BoxError> {
        let payload = json!({ "type": "spotMeta" });
        let response = info
            .http_client
            .post("/info", payload.to_string())
            .await
            .map_err(|err| -> BoxError { Box::new(err) })?;
        let meta: SpotMetaResponse =
            serde_json::from_str(&response).map_err(|err| -> BoxError { Box::new(err) })?;
        Ok(TokenRegistry::from_meta_entries(&meta.tokens))
    }

    async fn prepare_context(
        &self,
        request: &VerifyRequest,
    ) -> Result<HyperliquidPaymentContext, FacilitatorLocalError> {
        self.assert_scheme(request)?;
        self.assert_network(request)?;

        let payload = match &request.payment_payload.payload {
            ExactPaymentPayload::Hyperliquid(payload) => payload,
            _ => {
                return Err(FacilitatorLocalError::InvalidSignature(
                    MixedAddress::Offchain("hyperliquid".into()),
                    "Expected hyperliquid payload".into(),
                ));
            }
        };

        let payer_address = match payload.payer.clone() {
            MixedAddress::Evm(addr) => addr,
            MixedAddress::Offchain(_) | MixedAddress::Solana(_) => {
                return Err(FacilitatorLocalError::InvalidAddress(
                    "Hyperliquid payer must be an EVM address".into(),
                ));
            }
        };
        let payer_h160 = h160_from_evm(&payer_address);

        let action_value = payload.action.clone();
        let parsed_action =
            serde_json::from_value::<Actions>(action_value.clone()).map_err(|err| {
                FacilitatorLocalError::DecodingError(format!("Invalid Hyperliquid action: {err}"))
            })?;
        let spot_send = match parsed_action {
            Actions::SpotSend(spot_send) => spot_send,
            _ => {
                return Err(FacilitatorLocalError::DecodingError(
                    "Only spotSend actions are supported".into(),
                ));
            }
        };

        self.assert_chain_alignment(payload, &spot_send)?;
        self.assert_destination(&request.payment_requirements, &spot_send)?;
        self.assert_token_alignment(&request.payment_requirements, &spot_send)?;

        let token = spot_send.token.clone();
        let token_decimals = self.tokens.decimals(&token).ok_or_else(|| {
            FacilitatorLocalError::DecodingError(format!("Unknown token {token}"))
        })?;

        let required_amount = request.payment_requirements.max_amount_required.0;
        let action_amount =
            parse_decimal_amount(&spot_send.amount, token_decimals).map_err(|err| {
                FacilitatorLocalError::DecodingError(format!(
                    "Failed to parse Hyperliquid amount: {err}"
                ))
            })?;

        if action_amount < required_amount {
            return Err(FacilitatorLocalError::InsufficientValue(
                payer_address.into(),
            ));
        }

        let recovered = recover_action_signer(&spot_send, &payload.signature)
            .map_err(|err| FacilitatorLocalError::InvalidSignature(payer_address.into(), err))?;

        if recovered != payer_address {
            return Err(FacilitatorLocalError::InvalidSignature(
                payer_address.into(),
                "Recovered signer does not match payer".into(),
            ));
        }

        self.assert_balance(
            &token,
            token_decimals,
            &action_amount,
            payer_h160,
            &payload.payer,
        )
        .await?;

        let nonce = extract_nonce(&action_value, spot_send.time)?;
        Ok(HyperliquidPaymentContext {
            payer: payload.payer.clone(),
            payer_address,
            payload_signature: payload.signature.clone(),
            action_value,
            spot_send,
            token,
            nonce,
        })
    }

    async fn assert_balance(
        &self,
        token: &str,
        decimals: u32,
        amount_required: &AlloyU256,
        payer_h160: H160,
        payer: &MixedAddress,
    ) -> Result<(), FacilitatorLocalError> {
        let balances = self
            .info
            .user_token_balances(payer_h160)
            .await
            .map_err(FacilitatorLocalError::ContractCall)?;

        let maybe_entry = balances
            .balances
            .iter()
            .find(|entry| entry.coin.eq_ignore_ascii_case(token));

        let entry =
            maybe_entry.ok_or_else(|| FacilitatorLocalError::InsufficientFunds(payer.clone()))?;

        let balance = parse_decimal_amount(&entry.total, decimals).map_err(|err| {
            FacilitatorLocalError::DecodingError(format!(
                "Failed to parse Hyperliquid balance: {err}"
            ))
        })?;

        if balance < *amount_required {
            return Err(FacilitatorLocalError::InsufficientFunds(payer.clone()));
        }
        Ok(())
    }

    fn assert_scheme(&self, request: &VerifyRequest) -> Result<(), FacilitatorLocalError> {
        if request.payment_payload.scheme != Scheme::Exact {
            return Err(FacilitatorLocalError::SchemeMismatch(
                None,
                Scheme::Exact,
                request.payment_payload.scheme,
            ));
        }
        Ok(())
    }

    fn assert_network(&self, request: &VerifyRequest) -> Result<(), FacilitatorLocalError> {
        if request.payment_payload.network != self.network {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network,
                request.payment_payload.network,
            ));
        }
        Ok(())
    }

    fn assert_chain_alignment(
        &self,
        payload: &ExactHyperliquidPayload,
        action: &SpotSend,
    ) -> Result<(), FacilitatorLocalError> {
        if let Some(chain) = &payload.hyperliquid_chain {
            if !equals_ignore_case(chain, &action.hyperliquid_chain) {
                return Err(FacilitatorLocalError::InvalidSignature(
                    payload.payer.clone(),
                    "hyperliquidChain mismatch".into(),
                ));
            }
        }

        if let Some(chain) = expected_chain_name(self.network) {
            if !equals_ignore_case(chain, &action.hyperliquid_chain) {
                return Err(FacilitatorLocalError::InvalidSignature(
                    payload.payer.clone(),
                    format!(
                        "Hyperliquid chain mismatch: expected {chain}, got {}",
                        action.hyperliquid_chain
                    ),
                ));
            }
        }

        if let Some(sig_chain_id) = &payload.signature_chain_id {
            if let Ok(expected) = ethers_core::types::U256::from_str(sig_chain_id) {
                if expected != action.signature_chain_id {
                    return Err(FacilitatorLocalError::InvalidSignature(
                        payload.payer.clone(),
                        "signatureChainId mismatch".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn assert_destination(
        &self,
        requirements: &PaymentRequirements,
        action: &SpotSend,
    ) -> Result<(), FacilitatorLocalError> {
        let required_destination: AlloyAddress =
            requirements.pay_to.clone().try_into().map_err(|_| {
                FacilitatorLocalError::InvalidAddress("pay_to must be an EVM address".into())
            })?;
        let action_destination = alloy::primitives::Address::from_str(&action.destination)
            .map_err(|_| {
                FacilitatorLocalError::DecodingError("Invalid Hyperliquid destination".into())
            })?;

        if required_destination != action_destination {
            return Err(FacilitatorLocalError::ReceiverMismatch(
                MixedAddress::Evm(required_destination.into()),
                action.destination.clone(),
                requirements.pay_to.to_string(),
            ));
        }
        Ok(())
    }

    fn assert_token_alignment(
        &self,
        requirements: &PaymentRequirements,
        action: &SpotSend,
    ) -> Result<(), FacilitatorLocalError> {
        match &requirements.asset {
            MixedAddress::Offchain(symbol) => {
                if !equals_ignore_case(symbol, &action.token) {
                    return Err(FacilitatorLocalError::ReceiverMismatch(
                        requirements.pay_to.clone(),
                        action.token.clone(),
                        symbol.clone(),
                    ));
                }
            }
            MixedAddress::Evm(address) => {
                let token_address = token_address_from_action(&action.token).ok_or_else(|| {
                    FacilitatorLocalError::DecodingError(format!(
                        "Hyperliquid token {} missing EVM address",
                        action.token
                    ))
                })?;
                if token_address != *address {
                    return Err(FacilitatorLocalError::ReceiverMismatch(
                        requirements.pay_to.clone(),
                        token_address.to_string(),
                        address.to_string(),
                    ));
                }
            }
            MixedAddress::Solana(_) => {
                return Err(FacilitatorLocalError::InvalidAddress(
                    "Hyperliquid assets must be EVM or offchain identifiers".into(),
                ));
            }
        }
        Ok(())
    }

    async fn submit_and_wait(
        &self,
        ctx: &HyperliquidPaymentContext,
    ) -> Result<SettleResponse, FacilitatorLocalError> {
        let response = self
            .exchange
            .submit(&ctx.action_value, &ctx.payload_signature, ctx.nonce)
            .await
            .map_err(FacilitatorLocalError::ContractCall)?;

        let tx_hash = extract_tx_hash(&response).ok_or_else(|| {
            FacilitatorLocalError::ContractCall("Hyperliquid exchange response missing hash".into())
        })?;

        self.poll_for_confirmation(&tx_hash, ctx).await?;

        let transaction = parse_tx_hash(&tx_hash);
        Ok(SettleResponse {
            success: true,
            error_reason: None,
            payer: ctx.payer.clone(),
            transaction,
            network: self.network,
        })
    }

    async fn poll_for_confirmation(
        &self,
        tx_hash: &str,
        ctx: &HyperliquidPaymentContext,
    ) -> Result<(), FacilitatorLocalError> {
        let started = Instant::now();
        let deadline = started + self.poll.timeout;
        let sleep = self.poll.interval;

        loop {
            if Instant::now() > deadline {
                return Err(FacilitatorLocalError::ContractCall(
                    "Hyperliquid settlement timed out waiting for confirmation".into(),
                ));
            }

            match self.info.tx_details(tx_hash).await {
                Ok(Some(details)) => {
                    if self.matches_expected_tx(&details, ctx) {
                        return Ok(());
                    }
                }
                Ok(None) => {}
                Err(err) => return Err(FacilitatorLocalError::ContractCall(err)),
            }

            tokio::time::sleep(sleep).await;
        }
    }

    fn matches_expected_tx(
        &self,
        details: &HyperliquidTxDetails,
        ctx: &HyperliquidPaymentContext,
    ) -> bool {
        let user_matches = equals_ignore_case(&details.user, &ctx.payer_address.to_string());

        if !user_matches {
            return false;
        }

        let parsed = serde_json::from_value::<Actions>(details.action.clone());
        let Ok(Actions::SpotSend(action)) = parsed else {
            return false;
        };

        let destination_matches =
            equals_ignore_case(&action.destination, &ctx.spot_send.destination);
        let token_matches = equals_ignore_case(&action.token, &ctx.token);
        let amount_matches = equals_ignore_case(&action.amount, &ctx.spot_send.amount);

        destination_matches && token_matches && amount_matches
    }
}

impl FromEnvByNetworkBuild for HyperliquidProvider {
    async fn from_env(network: Network) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if !matches!(
            network,
            Network::HyperliquidMainnet | Network::HyperliquidTestnet
        ) {
            return Ok(None);
        }

        if let Some(env) = hyperliquid_env_from_env()? {
            if !env.matches(network) {
                return Ok(None);
            }
        }

        let default_base = match network {
            Network::HyperliquidMainnet => BaseUrl::Mainnet,
            Network::HyperliquidTestnet => BaseUrl::Testnet,
            _ => unreachable!(),
        };

        let mut info_client = InfoClient::new(None, Some(default_base)).await?;
        if let Some(custom) = hyperliquid_base_url_override() {
            info_client.http_client.base_url = custom;
        }

        let tokens = HyperliquidProvider::load_token_registry(&info_client)
            .await
            .map_err(|err| err as Box<dyn std::error::Error>)?;

        let exchange_url = hyperliquid_exchange_url_override()
            .unwrap_or_else(|| format!("{}/exchange", info_client.http_client.base_url));

        let exchange = Arc::new(HttpHyperliquidExchange::new(exchange_url));
        let info: Arc<dyn HyperliquidInfo + Send + Sync> = Arc::new(info_client);
        let poll = HyperliquidPollConfig::from_env();

        Ok(Some(HyperliquidProvider::new(
            network, info, exchange, tokens, poll,
        )))
    }
}

impl Facilitator for HyperliquidProvider {
    type Error = FacilitatorLocalError;

    #[instrument(skip_all, err)]
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let ctx = self.prepare_context(request).await?;
        Ok(VerifyResponse::valid(ctx.payer))
    }

    #[instrument(skip_all, err)]
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let ctx = self.prepare_context(request).await?;
        self.submit_and_wait(&ctx).await
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        Ok(SupportedPaymentKindsResponse {
            kinds: vec![SupportedPaymentKind {
                x402_version: X402Version::V1,
                scheme: Scheme::Exact,
                network: self.network.to_string(),
                extra: None,
            }],
        })
    }
}

impl NetworkProviderOps for HyperliquidProvider {
    fn signer_address(&self) -> MixedAddress {
        MixedAddress::Offchain("hyperliquid".into())
    }

    fn network(&self) -> Network {
        self.network
    }
}

#[async_trait]
pub(crate) trait HyperliquidInfo {
    async fn user_token_balances(&self, user: H160) -> Result<UserTokenBalanceResponse, String>;

    async fn tx_details(&self, hash: &str) -> Result<Option<HyperliquidTxDetails>, String>;
}

#[async_trait]
impl HyperliquidInfo for InfoClient {
    async fn user_token_balances(&self, user: H160) -> Result<UserTokenBalanceResponse, String> {
        InfoClient::user_token_balances(self, user)
            .await
            .map_err(|err| err.to_string())
    }

    async fn tx_details(&self, hash: &str) -> Result<Option<HyperliquidTxDetails>, String> {
        let request =
            serde_json::to_string(&TxDetailsRequest::new(hash)).map_err(|err| err.to_string())?;
        let response = self
            .http_client
            .post("/info", request)
            .await
            .map_err(|err| err.to_string())?;
        let value: Value = serde_json::from_str(&response).map_err(|err| err.to_string())?;
        Ok(parse_tx_details(value))
    }
}

#[async_trait]
pub(crate) trait HyperliquidExchange {
    async fn submit(&self, action: &Value, signature: &str, nonce: u64) -> Result<Value, String>;
}

#[derive(Clone)]
struct HttpHyperliquidExchange {
    client: reqwest::Client,
    url: String,
}

impl HttpHyperliquidExchange {
    fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }
}

#[async_trait]
impl HyperliquidExchange for HttpHyperliquidExchange {
    async fn submit(&self, action: &Value, signature: &str, nonce: u64) -> Result<Value, String> {
        let payload = json!({
            "action": action,
            "signature": signature,
            "nonce": nonce,
        });

        let response = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|err| err.to_string())?;

        let status = response.status();
        let text = response.text().await.map_err(|err| err.to_string())?;

        if !status.is_success() {
            return Err(format!("Exchange error {status}: {text}"));
        }

        serde_json::from_str(&text).map_err(|err| err.to_string())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HyperliquidPollConfig {
    interval: Duration,
    timeout: Duration,
}

impl HyperliquidPollConfig {
    fn from_env() -> Self {
        let interval_ms = hyperliquid_poll_interval_ms().unwrap_or(DEFAULT_POLL_INTERVAL_MS);
        let timeout_ms = hyperliquid_poll_timeout_ms().unwrap_or(DEFAULT_POLL_TIMEOUT_MS);
        Self {
            interval: Duration::from_millis(interval_ms),
            timeout: Duration::from_millis(timeout_ms),
        }
    }
}

#[derive(Debug, Clone)]
struct HyperliquidPaymentContext {
    payer: MixedAddress,
    payer_address: EvmAddress,
    payload_signature: String,
    action_value: Value,
    spot_send: SpotSend,
    token: String,
    nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxDetailsRequest<'a> {
    #[serde(rename = "type")]
    req_type: &'static str,
    hash: &'a str,
}

impl<'a> TxDetailsRequest<'a> {
    fn new(hash: &'a str) -> Self {
        Self {
            req_type: "txDetails",
            hash,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HyperliquidTxDetails {
    user: String,
    action: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpotMetaResponse {
    tokens: Vec<TokenMetaEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenMetaEntry {
    name: String,
    sz_decimals: u8,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenRegistry {
    decimals_by_name: HashMap<String, u32>,
}

impl TokenRegistry {
    fn from_meta_entries(entries: &[TokenMetaEntry]) -> Self {
        let mut decimals_by_name = HashMap::new();
        for token in entries {
            let normalized = token.name.to_ascii_lowercase();
            decimals_by_name.insert(normalized.clone(), u32::from(token.sz_decimals));
            if let Some((prefix, _)) = token.name.split_once(':') {
                decimals_by_name
                    .entry(prefix.to_ascii_lowercase())
                    .or_insert(u32::from(token.sz_decimals));
            }
        }
        Self { decimals_by_name }
    }

    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, u32)]) -> Self {
        let mut decimals_by_name = HashMap::new();
        for (name, decimals) in pairs {
            let normalized = name.to_ascii_lowercase();
            decimals_by_name.insert(normalized.clone(), *decimals);
            if let Some((prefix, _)) = name.split_once(':') {
                decimals_by_name
                    .entry(prefix.to_ascii_lowercase())
                    .or_insert(*decimals);
            }
        }
        Self { decimals_by_name }
    }

    fn decimals(&self, token: &str) -> Option<u32> {
        let normalized = token.to_ascii_lowercase();
        self.decimals_by_name.get(&normalized).copied().or_else(|| {
            token
                .split_once(':')
                .and_then(|(prefix, _)| self.decimals_by_name.get(&prefix.to_ascii_lowercase()))
                .copied()
        })
    }
}

fn recover_action_signer(action: &SpotSend, signature: &str) -> Result<EvmAddress, String> {
    let digest = action.encode_eip712().map_err(|err| err.to_string())?;
    let normalized = if signature.starts_with("0x") {
        signature.to_string()
    } else {
        format!("0x{signature}")
    };
    let sig = AlloySignature::from_str(&normalized).map_err(|err| err.to_string())?;
    let hash = B256::from_slice(&digest);
    let recovered = sig
        .recover_address_from_prehash(&hash)
        .map_err(|err| err.to_string())?;
    Ok(recovered.into())
}

fn equals_ignore_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn expected_chain_name(network: Network) -> Option<&'static str> {
    match network {
        Network::HyperliquidMainnet => Some("Mainnet"),
        Network::HyperliquidTestnet => Some("Testnet"),
        _ => None,
    }
}

fn extract_nonce(action: &Value, fallback: u64) -> Result<u64, FacilitatorLocalError> {
    if let Some(value) = action.get("nonce").and_then(Value::as_u64) {
        return Ok(value);
    }
    if let Some(value) = action.get("time").and_then(Value::as_u64) {
        return Ok(value);
    }
    Ok(fallback)
}

fn parse_decimal_amount(value: &str, decimals: u32) -> Result<AlloyU256, String> {
    if decimals == 0 {
        return AlloyU256::from_str_radix(value, 10).map_err(|err| err.to_string());
    }

    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or("0");
    let fraction = parts.next().unwrap_or("");

    if parts.next().is_some() {
        return Err("Invalid decimal format".into());
    }

    let mut frac = fraction.to_string();
    if frac.len() > decimals as usize {
        return Err("Too many fractional digits".into());
    }
    while frac.len() < decimals as usize {
        frac.push('0');
    }

    let base = AlloyU256::from(10).pow(AlloyU256::from(decimals));
    let integer_value = AlloyU256::from_str_radix(integer, 10).map_err(|err| err.to_string())?;
    let fraction_value = if frac.is_empty() {
        AlloyU256::ZERO
    } else {
        AlloyU256::from_str_radix(&frac, 10).map_err(|err| err.to_string())?
    };
    Ok(integer_value * base + fraction_value)
}

fn token_address_from_action(token: &str) -> Option<EvmAddress> {
    token
        .split_once(':')
        .and_then(|(_, address)| EvmAddress::from_str(address).ok())
}

fn h160_from_evm(address: &EvmAddress) -> H160 {
    H160::from_slice(address.0.as_slice())
}

fn parse_tx_hash(hash: &str) -> Option<TransactionHash> {
    let normalized = hash.strip_prefix("0x").unwrap_or(hash);
    let bytes = hex::decode(normalized).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(TransactionHash::Evm(array))
}

fn extract_tx_hash(response: &Value) -> Option<String> {
    response
        .get("response")
        .and_then(|value| value.get("hash"))
        .and_then(Value::as_str)
        .map(|value| value.to_string())
        .or_else(|| {
            response
                .get("hash")
                .and_then(Value::as_str)
                .map(|v| v.to_string())
        })
        .or_else(|| {
            response
                .get("txHash")
                .and_then(Value::as_str)
                .map(|v| v.to_string())
        })
}

fn parse_tx_details(value: Value) -> Option<HyperliquidTxDetails> {
    let root = if value.get("data").is_some() {
        value.get("data").cloned().unwrap()
    } else if value.get("response").is_some() {
        value.get("response").cloned().unwrap()
    } else {
        value.clone()
    };

    let user = root.get("user").and_then(Value::as_str)?.to_string();
    let action = root.get("action")?.clone();

    Some(HyperliquidTxDetails { user, action })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use hyperliquid_rust_sdk::UserTokenBalance;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use url::Url;
    use crate::types::{PaymentPayload, TokenAmount};

    #[derive(Clone, Default)]
    struct MockInfoClient {
        balances: Arc<Mutex<Vec<UserTokenBalance>>>,
        tx_details: Arc<Mutex<Option<HyperliquidTxDetails>>>,
    }

    impl MockInfoClient {
        async fn set_balances(&self, balances: Vec<UserTokenBalance>) {
            *self.balances.lock().await = balances;
        }

        async fn set_tx_details(&self, details: Option<HyperliquidTxDetails>) {
            *self.tx_details.lock().await = details;
        }
    }

    #[async_trait]
    impl HyperliquidInfo for MockInfoClient {
        async fn user_token_balances(
            &self,
            _user: H160,
        ) -> Result<UserTokenBalanceResponse, String> {
            let guard = self.balances.lock().await;
            let balances = guard
                .iter()
                .map(|balance| UserTokenBalance {
                    coin: balance.coin.clone(),
                    hold: balance.hold.clone(),
                    total: balance.total.clone(),
                    entry_ntl: balance.entry_ntl.clone(),
                })
                .collect();
            Ok(UserTokenBalanceResponse { balances })
        }

        async fn tx_details(&self, _hash: &str) -> Result<Option<HyperliquidTxDetails>, String> {
            Ok(self.tx_details.lock().await.clone())
        }
    }

    #[derive(Clone)]
    struct MockExchange {
        response: Arc<Mutex<Option<Value>>>,
    }

    impl Default for MockExchange {
        fn default() -> Self {
            Self {
                response: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl MockExchange {
        async fn set_response(&self, value: Value) {
            *self.response.lock().await = Some(value);
        }
    }

    #[async_trait]
    impl HyperliquidExchange for MockExchange {
        async fn submit(
            &self,
            _action: &Value,
            _signature: &str,
            _nonce: u64,
        ) -> Result<Value, String> {
            Ok(self
                .response
                .lock()
                .await
                .clone()
                .unwrap_or(json!({"response": {"hash": "0x1"}})))
        }
    }

    const TEST_KEY: &str = "0xe908f86dbb4d55ac876378565aafeabc187f6690f046459397b17d9b9a19688e";

    fn sample_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_str(TEST_KEY).unwrap()
    }

    fn sample_spot_send() -> (SpotSend, Value) {
        let spot_send = SpotSend {
            hyperliquid_chain: "Testnet".into(),
            signature_chain_id: 421614u64.into(),
            destination: "0x0D1d9635D0640821d15e323ac8AdADfA9c111414".into(),
            token: "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".into(),
            amount: "1".into(),
            time: 1_720_000_000,
        };
        let action_value =
            serde_json::to_value(&Actions::SpotSend(spot_send.clone())).expect("serialize");
        (spot_send, action_value)
    }

    fn sign_spot_send(spot_send: &SpotSend) -> String {
        let digest = spot_send.encode_eip712().expect("digest");
        let sig = sample_signer()
            .sign_hash_sync(&B256::from_slice(&digest))
            .expect("sign");
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    fn build_verify_request(amount: &str, required_base_units: u64) -> (VerifyRequest, SpotSend) {
        let (mut spot_send, _) = sample_spot_send();
        spot_send.amount = amount.into();
        let action_value =
            serde_json::to_value(&Actions::SpotSend(spot_send.clone())).expect("serialize");
        let signature = sign_spot_send(&spot_send);
        let payer_address: EvmAddress = sample_signer().address().into();
        let payload = ExactHyperliquidPayload {
            payer: MixedAddress::Evm(payer_address),
            action: action_value,
            signature,
            signature_chain_id: None,
            hyperliquid_chain: None,
        };
        let token_address = spot_send.token.split_once(':').unwrap().1.parse().unwrap();
        let requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::HyperliquidTestnet,
            max_amount_required: TokenAmount(AlloyU256::from(required_base_units)),
            resource: Url::parse("https://example.com/resource").unwrap(),
            description: "desc".into(),
            mime_type: "application/json".into(),
            output_schema: None,
            pay_to: MixedAddress::Evm(spot_send.destination.parse().unwrap()),
            max_timeout_seconds: 30,
            asset: MixedAddress::Evm(token_address),
            extra: None,
        };
        let request = VerifyRequest {
            x402_version: X402Version::V1,
            payment_payload: PaymentPayload {
                x402_version: X402Version::V1,
                scheme: Scheme::Exact,
                network: Network::HyperliquidTestnet,
                payload: ExactPaymentPayload::Hyperliquid(payload),
            },
            payment_requirements: requirements,
        };
        (request, spot_send)
    }

    #[tokio::test]
    async fn recovers_signer_from_spot_send() {
        let (request, _) = build_verify_request("1", 1_000_000);
        let info_backend = Arc::new(MockInfoClient::default());
        info_backend
            .set_balances(vec![UserTokenBalance {
                coin: "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".into(),
                hold: "0".into(),
                total: "10".into(),
                entry_ntl: "0".into(),
            }])
            .await;
        let info: DynInfo = info_backend.clone();
        let exchange: DynExchange = Arc::new(MockExchange::default());
        let provider = HyperliquidProvider::new(
            Network::HyperliquidTestnet,
            info,
            exchange,
            TokenRegistry::from_pairs(&[("PURR:0xc4bf3f870c0e9465323c0b6ed28096c2", 6)]),
            HyperliquidPollConfig::from_env(),
        );

        provider.verify(&request).await.expect("valid");
    }

    #[tokio::test]
    async fn insufficient_balance_returns_error() {
        let (request, _) = build_verify_request("1", 1_000_000);
        let info_backend = Arc::new(MockInfoClient::default());
        info_backend
            .set_balances(vec![UserTokenBalance {
                coin: "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".into(),
                hold: "0".into(),
                total: "0.0001".into(),
                entry_ntl: "0".into(),
            }])
            .await;
        let info: DynInfo = info_backend.clone();
        let exchange: DynExchange = Arc::new(MockExchange::default());
        let provider = HyperliquidProvider::new(
            Network::HyperliquidTestnet,
            info,
            exchange,
            TokenRegistry::from_pairs(&[("PURR:0xc4bf3f870c0e9465323c0b6ed28096c2", 6)]),
            HyperliquidPollConfig::from_env(),
        );

        let err = provider.verify(&request).await.unwrap_err();
        assert!(matches!(err, FacilitatorLocalError::InsufficientFunds(_)));
    }

    #[test]
    fn converts_decimal_amounts() {
        assert_eq!(
            parse_decimal_amount("1.23", 6).unwrap(),
            AlloyU256::from(1_230_000u64)
        );
        assert_eq!(
            parse_decimal_amount("0.00000042", 8).unwrap(),
            AlloyU256::from(42u64)
        );
        assert_eq!(
            parse_decimal_amount("3", 18).unwrap(),
            AlloyU256::from_str_radix("3000000000000000000", 10).unwrap()
        );
    }

    #[tokio::test]
    async fn settle_submits_and_confirms() {
        let (request, spot_send) = build_verify_request("1", 1_000_000);
        let info_backend = Arc::new(MockInfoClient::default());
        info_backend
            .set_balances(vec![UserTokenBalance {
                coin: "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".into(),
                hold: "0".into(),
                total: "10".into(),
                entry_ntl: "0".into(),
            }])
            .await;
        info_backend
            .set_tx_details(Some(HyperliquidTxDetails {
                user: sample_signer().address().to_string(),
                action: serde_json::to_value(&Actions::SpotSend(spot_send.clone())).unwrap(),
            }))
            .await;
        let info: DynInfo = info_backend.clone();

        let exchange_backend = Arc::new(MockExchange::default());
        exchange_backend
            .set_response(json!({ "hash": "0xabcde00000000000000000000000000000000000000000000000000000000000" }))
            .await;
        let exchange: DynExchange = exchange_backend.clone();

        let provider = HyperliquidProvider::new(
            Network::HyperliquidTestnet,
            info,
            exchange,
            TokenRegistry::from_pairs(&[("PURR:0xc4bf3f870c0e9465323c0b6ed28096c2", 6)]),
            HyperliquidPollConfig {
                interval: Duration::from_millis(5),
                timeout: Duration::from_millis(50),
            },
        );

        let response = provider.settle(&request).await.expect("settled");
        assert!(response.success);
        assert!(response.transaction.is_some());
    }
}
