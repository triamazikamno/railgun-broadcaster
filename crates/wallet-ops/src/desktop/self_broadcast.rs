use super::*;
use eyre::eyre;

const TREZOR_APP_PASSPHRASE_ERROR_TEXT: &str =
    "Trezor requested an app-entered passphrase but none was provided";
const TREZOR_SELF_BROADCAST_RESTART_GUIDANCE: &str = "Trezor app passphrase is required again. Re-unlock the hardware profile with the app passphrase, then restart this self-broadcast.";

pub(super) async fn submit_self_broadcast_plan(
    chain_id: u64,
    effective_chain: Option<&settings::EffectiveChainConfig>,
    view_session: &vault::DesktopViewSession,
    vault_store: &vault::DesktopVaultStore,
    vault_password: Option<&str>,
    trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    public_account_uuid: String,
    session: Arc<WalletSession>,
    to: Address,
    data: Bytes,
    pending_spent_inputs: Vec<Utxo>,
    gas_fee: SelfBroadcastGasFeeSelection,
    progress_tx: Option<TransactionGenerationProgressSender>,
    mut command_rx: Option<SelfBroadcastCommandReceiver>,
    event_tx: Option<SelfBroadcastSessionEventSender>,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let chain = effective_desktop_chain_config(chain_id, effective_chain)?;
    let gas_payer = self_broadcast_gas_payer(vault_store, view_session, &public_account_uuid)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    let signer = vaulted_public_signer(
        vault_store,
        view_session,
        vault_password,
        &public_account_uuid,
        None,
        trezor_pin_matrix_provider,
    )?;
    if signer.address() != gas_payer {
        return Err(eyre!(
            "selected public account signer address does not match account metadata"
        ));
    }
    let mut next_gas_fee = gas_fee;
    let mut submitted_attempts = Vec::new();
    let mut nonce = None;

    loop {
        update_transaction_generation_stage(
            progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingSelfBroadcastGas,
        );
        let preflight = match self_broadcast_preflight_from_rpc_pool(
            &query_rpc_pool,
            chain_id,
            gas_payer,
            to,
            data.clone(),
            next_gas_fee,
            &chain.gas,
            nonce,
            http.network_mode(),
        )
        .await
        {
            Ok(preflight) => preflight,
            Err(error) => {
                let message = report_chain_string(&error);
                emit_self_broadcast_event(
                    event_tx.as_ref(),
                    SelfBroadcastSessionEvent::StepFailed {
                        stage: TransactionGenerationStage::EstimatingSelfBroadcastGas,
                        message,
                    },
                );
                let Some(command) = recv_self_broadcast_command(&mut command_rx).await else {
                    return Err(error);
                };
                next_gas_fee = command.gas_fee;
                continue;
            }
        };
        nonce = Some(preflight.nonce);

        update_transaction_generation_stage(
            progress_tx.as_ref(),
            TransactionGenerationStage::SigningSelfBroadcast,
        );
        let attempt = match submit_self_broadcast_attempt(
            preflight,
            &query_rpc_pool,
            http.network_mode(),
            &signer,
            &session,
            &pending_spent_inputs,
            event_tx.as_ref(),
        )
        .await
        {
            Ok(attempt) => attempt,
            Err(error) => {
                if is_trezor_app_passphrase_required_error(&error) {
                    return Err(error.wrap_err(TREZOR_SELF_BROADCAST_RESTART_GUIDANCE));
                }
                let message = report_chain_string(&error);
                emit_self_broadcast_event(
                    event_tx.as_ref(),
                    SelfBroadcastSessionEvent::StepFailed {
                        stage: TransactionGenerationStage::SigningSelfBroadcast,
                        message,
                    },
                );
                let Some(command) = recv_self_broadcast_command(&mut command_rx).await else {
                    return Err(error);
                };
                next_gas_fee = command.gas_fee;
                continue;
            }
        };
        submitted_attempts.push(attempt);
        update_transaction_generation_stage(
            progress_tx.as_ref(),
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        );

        loop {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(3)) => {
                    if let Some((winner_index, receipt)) = poll_self_broadcast_attempt_receipts(&submitted_attempts).await? {
                        let winner = &submitted_attempts[winner_index];
                        session
                            .mark_pending_spent_utxos(
                                &pending_spent_inputs,
                                parse_submitted_tx_hash(&receipt.tx_hash),
                            )
                            .await;
                        return Ok(DesktopSelfBroadcastResult {
                            chain_id,
                            public_account_uuid,
                            gas_payer,
                            gas_limit: winner.info.gas_limit,
                            rpc_gas_price: winner.rpc_gas_price,
                            max_fee_per_gas: winner.info.max_fee_per_gas,
                            max_priority_fee_per_gas: winner.info.max_priority_fee_per_gas,
                            estimated_native_gas_cost: winner.estimated_native_gas_cost,
                            live_native_balance: winner.live_native_balance,
                            tx: receipt,
                            attempts: submitted_attempts
                                .iter()
                                .map(|attempt| attempt.info.clone())
                                .collect(),
                        });
                    }
                }
                command = recv_self_broadcast_command(&mut command_rx) => {
                    let Some(command) = command else {
                        continue;
                    };
                    let Some(nonce) = nonce else {
                        next_gas_fee = command.gas_fee;
                        break;
                    };
                    let gas_limit = submitted_attempts
                        .last()
                        .map_or(0, |attempt| attempt.info.gas_limit);
                    let replacement = match self_broadcast_replacement_preflight_from_rpc_pool(
                        &query_rpc_pool,
                        chain_id,
                        gas_payer,
                        to,
                        data.clone(),
                        command.gas_fee,
                        gas_limit,
                        nonce,
                    )
                    .await
                    {
                        Ok(preflight) => preflight,
                        Err(error) => {
                            emit_self_broadcast_event(
                                event_tx.as_ref(),
                                SelfBroadcastSessionEvent::AttemptRejected {
                                    stage: TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
                                    message: report_chain_string(&error),
                                },
                            );
                            continue;
                        }
                    };
                    update_transaction_generation_stage(
                        progress_tx.as_ref(),
                        TransactionGenerationStage::SigningSelfBroadcast,
                    );
                    match submit_self_broadcast_attempt(
                        replacement,
                        &query_rpc_pool,
                        http.network_mode(),
                        &signer,
                        &session,
                        &pending_spent_inputs,
                        event_tx.as_ref(),
                    )
                    .await
                    {
                        Ok(attempt) => submitted_attempts.push(attempt),
                        Err(error) => {
                            let message = self_broadcast_signing_error_message(&error);
                            emit_self_broadcast_event(
                                event_tx.as_ref(),
                                SelfBroadcastSessionEvent::AttemptRejected {
                                    stage: TransactionGenerationStage::SigningSelfBroadcast,
                                    message,
                                },
                            );
                        }
                    }
                    update_transaction_generation_stage(
                        progress_tx.as_ref(),
                        TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
                    );
                }
            }
        }
    }
}

pub(super) fn emit_self_broadcast_event(
    event_tx: Option<&SelfBroadcastSessionEventSender>,
    event: SelfBroadcastSessionEvent,
) {
    if let Some(event_tx) = event_tx {
        let _ = event_tx.send(event);
    }
}

fn emit_refreshed_self_broadcast_hardware_session(
    event_tx: Option<&SelfBroadcastSessionEventSender>,
    signer: &VaultedPublicSigner,
) {
    match signer.refreshed_trezor_hardware_session() {
        Ok(Some(session)) => emit_self_broadcast_event(
            event_tx,
            SelfBroadcastSessionEvent::HardwareProfileSessionRefreshed { session },
        ),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "failed to read refreshed self-broadcast signer session");
        }
    }
}

pub(crate) fn report_chain_string(error: &Report) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn self_broadcast_signing_error_message(error: &Report) -> String {
    let message = report_chain_string(error);
    if is_trezor_app_passphrase_required_error_message(&message) {
        format!("{message}: {TREZOR_SELF_BROADCAST_RESTART_GUIDANCE}")
    } else {
        message
    }
}

fn is_trezor_app_passphrase_required_error(error: &Report) -> bool {
    is_trezor_app_passphrase_required_error_message(&report_chain_string(error))
}

fn is_trezor_app_passphrase_required_error_message(message: &str) -> bool {
    message.contains(TREZOR_APP_PASSPHRASE_ERROR_TEXT)
}

pub(super) async fn recv_self_broadcast_command(
    command_rx: &mut Option<SelfBroadcastCommandReceiver>,
) -> Option<SelfBroadcastCommand> {
    let command_rx = command_rx.as_mut()?;
    command_rx.recv().await
}

pub(super) async fn submit_self_broadcast_attempt(
    preflight: SelfBroadcastPreflight,
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    signer: &VaultedPublicSigner,
    session: &WalletSession,
    pending_spent_inputs: &[Utxo],
    event_tx: Option<&SelfBroadcastSessionEventSender>,
) -> Result<SubmittedSelfBroadcastAttempt> {
    let sent = sign_send_self_broadcast_transaction(
        query_rpc_pool,
        network_mode,
        signer,
        preflight.tx_req,
        session,
        pending_spent_inputs,
        event_tx,
    )
    .await?;
    let info = SelfBroadcastAttemptInfo {
        tx_hash: sent.tx_hash_string,
        nonce: preflight.nonce,
        gas_limit: preflight.gas_limit,
        max_fee_per_gas: preflight.max_fee_per_gas,
        max_priority_fee_per_gas: preflight.max_priority_fee_per_gas,
    };
    emit_self_broadcast_event(
        event_tx,
        SelfBroadcastSessionEvent::AttemptSubmitted(info.clone()),
    );
    Ok(SubmittedSelfBroadcastAttempt {
        provider_handles: sent.provider_handles,
        tx_hash: sent.tx_hash,
        info,
        rpc_gas_price: preflight.rpc_gas_price,
        estimated_native_gas_cost: preflight.estimated_native_gas_cost,
        live_native_balance: preflight.live_native_balance,
    })
}

pub(super) async fn poll_self_broadcast_attempt_receipts(
    attempts: &[SubmittedSelfBroadcastAttempt],
) -> Result<Option<(usize, TxReceiptOutput)>> {
    for (index, attempt) in attempts.iter().enumerate() {
        for provider_handle in &attempt.provider_handles {
            match provider_handle
                .provider
                .get_transaction_receipt(attempt.tx_hash)
                .await
            {
                Ok(Some(receipt)) => {
                    return Ok(Some((index, tx_receipt_output(attempt.tx_hash, &receipt))));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        url = %provider_handle.url,
                        %error,
                        "self-broadcast receipt fetch failed"
                    );
                }
            }
        }
    }
    Ok(None)
}

pub(super) async fn self_broadcast_replacement_preflight_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    gas_limit: u64,
    nonce: u64,
) -> Result<SelfBroadcastPreflight> {
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match self_broadcast_replacement_preflight(
            provider_handle,
            chain_id,
            from,
            to,
            data.clone(),
            gas_fee,
            gas_limit,
            nonce,
        )
        .await
        {
            Ok(preflight) => return Ok(preflight),
            Err(error) if is_self_broadcast_insufficient_native_gas_error(&error) => {
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(%error, "self-broadcast replacement preflight failed");
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all self-broadcast replacement RPC attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

pub(super) async fn self_broadcast_replacement_preflight(
    provider_handle: ProviderHandle,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    gas_limit: u64,
    nonce: u64,
) -> Result<SelfBroadcastPreflight> {
    let provider = &provider_handle.provider;
    let quote = self_broadcast_gas_fee_quote(provider)
        .await
        .wrap_err("fetch self-broadcast gas price")?;
    let SelfBroadcastResolvedGasFee {
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    } = resolve_self_broadcast_gas_fee(gas_fee, quote)?;
    let estimated_native_gas_cost = self_broadcast_native_gas_cost(gas_limit, max_fee_per_gas);
    let live_native_balance = provider
        .get_balance(from)
        .await
        .wrap_err("fetch self-broadcast native balance")?;
    if live_native_balance < estimated_native_gas_cost {
        return Err(self_broadcast_insufficient_native_gas_error(
            live_native_balance,
            estimated_native_gas_cost,
        ));
    }
    Ok(SelfBroadcastPreflight {
        tx_req: self_broadcast_transaction_request(
            chain_id,
            from,
            to,
            data,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            nonce,
        )
        .with_gas_limit(gas_limit),
        nonce,
        gas_limit,
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        estimated_native_gas_cost,
        live_native_balance,
    })
}

pub(super) fn self_broadcast_gas_payer(
    vault_store: &vault::DesktopVaultStore,
    view_session: &vault::DesktopViewSession,
    public_account_uuid: &str,
) -> Result<Address> {
    vault_store
        .list_active_public_accounts_for_session(view_session)
        .wrap_err("load active public accounts")?
        .into_iter()
        .find(|account| account.public_account_uuid == public_account_uuid)
        .map(|account| account.address)
        .ok_or_else(|| eyre!("selected gas payer is not an active Public account"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelfBroadcastResolvedGasFee {
    pub(crate) rpc_gas_price: u128,
    pub(crate) max_fee_per_gas: u128,
    pub(crate) max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SelfBroadcastFeeQuoteTimeoutPolicy {
    pub(super) grace_after_first_usable: Duration,
    pub(super) hard_deadline: Duration,
}

impl SelfBroadcastFeeQuoteTimeoutPolicy {
    const fn for_network_mode(network_mode: WalletNetworkMode) -> Self {
        match network_mode {
            WalletNetworkMode::Tor => Self {
                grace_after_first_usable: SELF_BROADCAST_TOR_FEE_QUOTE_GRACE,
                hard_deadline: SELF_BROADCAST_TOR_FEE_QUOTE_DEADLINE,
            },
            WalletNetworkMode::Proxy | WalletNetworkMode::Direct => Self {
                grace_after_first_usable: SELF_BROADCAST_DIRECT_FEE_QUOTE_GRACE,
                hard_deadline: SELF_BROADCAST_DIRECT_FEE_QUOTE_DEADLINE,
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SelfBroadcastFeeSample {
    pub(crate) rpc_gas_price: Option<u128>,
    pub(crate) max_priority_fee_per_gas: Option<u128>,
    pub(crate) next_base_fee_per_gas: Option<u128>,
    pub(crate) priority_fee_rewards: Vec<u128>,
}

impl SelfBroadcastFeeSample {
    fn from_parts(
        rpc_gas_price: Option<u128>,
        max_priority_fee_per_gas: Option<u128>,
        fee_history: Option<FeeHistory>,
    ) -> Self {
        let Some(fee_history) = fee_history else {
            return Self {
                rpc_gas_price,
                max_priority_fee_per_gas,
                next_base_fee_per_gas: None,
                priority_fee_rewards: Vec::new(),
            };
        };
        let next_base_fee_per_gas = fee_history.base_fee_per_gas.last().copied();
        let priority_fee_rewards = fee_history
            .reward
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect();
        Self {
            rpc_gas_price,
            max_priority_fee_per_gas,
            next_base_fee_per_gas,
            priority_fee_rewards,
        }
    }

    fn has_non_zero_fee_history_tip(&self) -> bool {
        self.priority_fee_rewards.iter().any(|value| *value > 0)
    }

    const fn has_non_zero_priority_tip(&self) -> bool {
        matches!(self.max_priority_fee_per_gas, Some(value) if value > 0)
    }

    fn has_usable_tip(&self) -> bool {
        self.has_non_zero_fee_history_tip() || self.has_non_zero_priority_tip()
    }
}

pub(super) async fn self_broadcast_parallel_fee_samples(
    providers: Vec<ProviderHandle>,
    policy: SelfBroadcastFeeQuoteTimeoutPolicy,
) -> Vec<SelfBroadcastFeeSample> {
    let started_at = Instant::now();
    let mut join_set = JoinSet::new();
    for provider_handle in providers {
        join_set.spawn(self_broadcast_provider_fee_sample(
            provider_handle,
            policy.hard_deadline,
        ));
    }

    let mut samples = Vec::new();
    let mut grace_deadline = None;
    while !join_set.is_empty() {
        let now = Instant::now();
        let Some(hard_remaining) = policy
            .hard_deadline
            .checked_sub(now.saturating_duration_since(started_at))
        else {
            break;
        };
        let wait_for = grace_deadline.map_or(hard_remaining, |deadline: Instant| {
            deadline.saturating_duration_since(now).min(hard_remaining)
        });
        if wait_for.is_zero() {
            break;
        }
        match tokio::time::timeout(wait_for, join_set.join_next()).await {
            Ok(Some(Ok(sample))) => {
                let usable_tip = sample.has_usable_tip();
                samples.push(sample);
                if usable_tip && grace_deadline.is_none() {
                    grace_deadline = Some(Instant::now() + policy.grace_after_first_usable);
                }
                let non_zero_fee_history_sources = samples
                    .iter()
                    .filter(|sample| sample.has_non_zero_fee_history_tip())
                    .count();
                if non_zero_fee_history_sources >= 2 {
                    break;
                }
            }
            Ok(Some(Err(error))) => {
                tracing::warn!(%error, "self-broadcast gas fee quote task failed");
            }
            Ok(None) | Err(_) => break,
        }
    }
    join_set.abort_all();
    samples
}

pub(super) async fn self_broadcast_provider_fee_sample(
    provider_handle: ProviderHandle,
    timeout: Duration,
) -> SelfBroadcastFeeSample {
    let provider = provider_handle.provider;
    let gas_price = tokio::time::timeout(timeout, provider.get_gas_price());
    let max_priority_fee = tokio::time::timeout(timeout, provider.get_max_priority_fee_per_gas());
    let fee_history = tokio::time::timeout(
        timeout,
        provider.get_fee_history(
            SELF_BROADCAST_FEE_HISTORY_BLOCKS,
            BlockNumberOrTag::Latest,
            &SELF_BROADCAST_FEE_HISTORY_REWARD_PERCENTILES,
        ),
    );
    let (gas_price, max_priority_fee, fee_history) =
        tokio::join!(gas_price, max_priority_fee, fee_history);
    let rpc_gas_price = match gas_price {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::warn!(url = %provider_handle.url, %error, "self-broadcast eth_gasPrice failed");
            None
        }
        Err(_) => {
            tracing::warn!(url = %provider_handle.url, "self-broadcast eth_gasPrice timed out");
            None
        }
    };
    let max_priority_fee_per_gas = match max_priority_fee {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::debug!(url = %provider_handle.url, %error, "self-broadcast eth_maxPriorityFeePerGas failed");
            None
        }
        Err(_) => {
            tracing::debug!(url = %provider_handle.url, "self-broadcast eth_maxPriorityFeePerGas timed out");
            None
        }
    };
    let fee_history = match fee_history {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::debug!(url = %provider_handle.url, %error, "self-broadcast eth_feeHistory failed");
            None
        }
        Err(_) => {
            tracing::debug!(url = %provider_handle.url, "self-broadcast eth_feeHistory timed out");
            None
        }
    };
    SelfBroadcastFeeSample::from_parts(rpc_gas_price, max_priority_fee_per_gas, fee_history)
}

pub(crate) fn self_broadcast_quote_from_fee_samples(
    samples: &[SelfBroadcastFeeSample],
) -> Option<SelfBroadcastGasFeeQuote> {
    self_broadcast_quote_from_fee_samples_with_tip_fallback(
        samples,
        SelfBroadcastTipFallback::Minimum,
    )
}

pub(crate) fn self_broadcast_quote_from_fee_samples_with_tip_fallback(
    samples: &[SelfBroadcastFeeSample],
    tip_fallback: SelfBroadcastTipFallback,
) -> Option<SelfBroadcastGasFeeQuote> {
    if samples.is_empty() {
        return None;
    }
    let mut gas_prices = non_zero_values(samples.iter().filter_map(|sample| sample.rpc_gas_price));
    let mut fee_history_rewards = non_zero_values(
        samples
            .iter()
            .flat_map(|sample| sample.priority_fee_rewards.iter().copied()),
    );
    let mut priority_fee_suggestions = non_zero_values(
        samples
            .iter()
            .filter_map(|sample| sample.max_priority_fee_per_gas),
    );
    let mut next_base_fees = non_zero_values(
        samples
            .iter()
            .filter_map(|sample| sample.next_base_fee_per_gas),
    );

    let rpc_gas_price = upper_quartile(&mut gas_prices);
    let fallback_tip = match tip_fallback {
        SelfBroadcastTipFallback::Minimum => SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS,
        SelfBroadcastTipFallback::RpcGasPrice => rpc_gas_price
            .unwrap_or(SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS)
            .max(SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS),
    };
    let selected_tip = upper_quartile(&mut fee_history_rewards)
        .or_else(|| upper_quartile(&mut priority_fee_suggestions))
        .unwrap_or(fallback_tip)
        .max(SELF_BROADCAST_MIN_PRIORITY_FEE_PER_GAS);
    let gas_price_max_fee = rpc_gas_price.map_or(0, self_broadcast_auto_max_fee_per_gas);
    let fee_history_max_fee = upper_quartile(&mut next_base_fees).map_or(0, |base_fee| {
        self_broadcast_auto_max_fee_per_gas(base_fee).saturating_add(selected_tip)
    });
    let suggested_max_fee_per_gas = gas_price_max_fee.max(fee_history_max_fee).max(selected_tip);
    Some(SelfBroadcastGasFeeQuote {
        rpc_gas_price: rpc_gas_price.unwrap_or(suggested_max_fee_per_gas),
        suggested_max_fee_per_gas,
        suggested_max_priority_fee_per_gas: selected_tip.min(suggested_max_fee_per_gas),
    })
}

pub(super) fn non_zero_values(values: impl IntoIterator<Item = u128>) -> Vec<u128> {
    values.into_iter().filter(|value| *value > 0).collect()
}

pub(super) fn upper_quartile(values: &mut [u128]) -> Option<u128> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let index = values.len().saturating_mul(3).saturating_sub(1) / 4;
    values.get(index).copied()
}

pub(super) async fn self_broadcast_gas_fee_quote_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
) -> Result<SelfBroadcastGasFeeQuote> {
    self_broadcast_gas_fee_quote_from_rpc_pool_with_tip_fallback(
        query_rpc_pool,
        network_mode,
        SelfBroadcastTipFallback::Minimum,
    )
    .await
}

pub(crate) async fn self_broadcast_gas_fee_quote_from_rpc_pool_with_tip_fallback(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    tip_fallback: SelfBroadcastTipFallback,
) -> Result<SelfBroadcastGasFeeQuote> {
    let providers = query_rpc_pool.available_providers();
    if providers.is_empty() {
        return Err(eyre!("no healthy query RPC available"));
    }
    let policy = SelfBroadcastFeeQuoteTimeoutPolicy::for_network_mode(network_mode);
    let samples = self_broadcast_parallel_fee_samples(providers, policy).await;
    if let Some(quote) =
        self_broadcast_quote_from_fee_samples_with_tip_fallback(&samples, tip_fallback)
    {
        return Ok(quote);
    }

    Err(eyre!("all self-broadcast gas quote RPC attempts failed"))
}

pub(super) async fn self_broadcast_gas_fee_quote(
    provider: &impl Provider,
) -> Result<SelfBroadcastGasFeeQuote> {
    let rpc_gas_price = provider.get_gas_price().await.wrap_err("fetch gas price")?;
    let max_priority_fee_per_gas = provider.get_max_priority_fee_per_gas().await.ok();
    let fee_history = provider
        .get_fee_history(
            SELF_BROADCAST_FEE_HISTORY_BLOCKS,
            BlockNumberOrTag::Latest,
            &SELF_BROADCAST_FEE_HISTORY_REWARD_PERCENTILES,
        )
        .await
        .ok();
    let sample = SelfBroadcastFeeSample::from_parts(
        Some(rpc_gas_price),
        max_priority_fee_per_gas,
        fee_history,
    );
    self_broadcast_quote_from_fee_samples(&[sample])
        .ok_or_else(|| eyre!("self-broadcast gas fee quote returned no usable values"))
}

pub(crate) fn resolve_self_broadcast_gas_fee(
    selection: SelfBroadcastGasFeeSelection,
    quote: SelfBroadcastGasFeeQuote,
) -> Result<SelfBroadcastResolvedGasFee> {
    let (max_fee_per_gas, max_priority_fee_per_gas) = match selection {
        SelfBroadcastGasFeeSelection::Auto => (
            quote.suggested_max_fee_per_gas,
            quote.suggested_max_priority_fee_per_gas,
        ),
        SelfBroadcastGasFeeSelection::Custom {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => (max_fee_per_gas, max_priority_fee_per_gas),
    };
    validate_self_broadcast_gas_fee(max_fee_per_gas, max_priority_fee_per_gas)?;
    Ok(SelfBroadcastResolvedGasFee {
        rpc_gas_price: quote.rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    })
}

pub(crate) fn validate_self_broadcast_gas_fee(
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> Result<()> {
    if max_fee_per_gas == 0 {
        return Err(eyre!(
            "self-broadcast max fee per gas must be greater than zero"
        ));
    }
    if max_priority_fee_per_gas > max_fee_per_gas {
        return Err(eyre!(
            "self-broadcast max priority fee per gas cannot exceed max fee per gas"
        ));
    }
    Ok(())
}

pub(super) async fn self_broadcast_preflight_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    gas: &settings::EffectiveChainGasSettings,
    nonce: Option<u64>,
    network_mode: WalletNetworkMode,
) -> Result<SelfBroadcastPreflight> {
    let quote = self_broadcast_gas_fee_quote_from_rpc_pool(query_rpc_pool, network_mode)
        .await
        .wrap_err("fetch self-broadcast gas price")?;
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match self_broadcast_preflight(
            provider_handle,
            chain_id,
            from,
            to,
            data.clone(),
            gas_fee,
            quote,
            gas,
            nonce,
        )
        .await
        {
            Ok(preflight) => return Ok(preflight),
            Err(error) if is_self_broadcast_insufficient_native_gas_error(&error) => {
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(?error, "self-broadcast preflight failed");
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all self-broadcast query RPC attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

pub(super) async fn self_broadcast_preflight(
    provider_handle: ProviderHandle,
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    gas_fee: SelfBroadcastGasFeeSelection,
    quote: SelfBroadcastGasFeeQuote,
    gas: &settings::EffectiveChainGasSettings,
    nonce: Option<u64>,
) -> Result<SelfBroadcastPreflight> {
    let provider = &provider_handle.provider;
    let SelfBroadcastResolvedGasFee {
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    } = resolve_self_broadcast_gas_fee(gas_fee, quote)?;
    let nonce = if let Some(nonce) = nonce {
        nonce
    } else {
        provider
            .get_transaction_count(from)
            .await
            .wrap_err("fetch self-broadcast nonce")?
    };
    let tx_req = self_broadcast_transaction_request(
        chain_id,
        from,
        to,
        data,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        nonce,
    );
    let estimated_gas = provider
        .estimate_gas(tx_req.clone())
        .await
        .wrap_err("estimate self-broadcast gas")?;
    let gas_limit = self_broadcast_gas_limit_with_buffer(estimated_gas, gas.gas_limit_buffer);
    let estimated_native_gas_cost = self_broadcast_native_gas_cost(gas_limit, max_fee_per_gas);
    let live_native_balance = provider
        .get_balance(from)
        .await
        .wrap_err("fetch self-broadcast native balance")?;
    if live_native_balance < estimated_native_gas_cost {
        return Err(self_broadcast_insufficient_native_gas_error(
            live_native_balance,
            estimated_native_gas_cost,
        ));
    }
    Ok(SelfBroadcastPreflight {
        tx_req: tx_req.with_gas_limit(gas_limit),
        nonce,
        gas_limit,
        rpc_gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        estimated_native_gas_cost,
        live_native_balance,
    })
}

pub(crate) fn self_broadcast_transaction_request(
    chain_id: u64,
    from: Address,
    to: Address,
    data: Bytes,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    nonce: u64,
) -> TransactionRequest {
    TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_from(from)
        .with_to(to)
        .with_input(data)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
        .with_nonce(nonce)
}

pub(crate) const fn self_broadcast_gas_limit_with_buffer(
    estimated_gas: u64,
    gas_limit_buffer: u64,
) -> u64 {
    estimated_gas.saturating_add(gas_limit_buffer)
}

pub(crate) fn self_broadcast_native_gas_cost(gas_limit: u64, max_fee_per_gas: u128) -> U256 {
    U256::from(gas_limit) * U256::from(max_fee_per_gas)
}

pub(crate) fn self_broadcast_insufficient_native_gas_error(
    balance: U256,
    estimated_cost: U256,
) -> Report {
    eyre!(
        "insufficient native gas for self-broadcast: live balance {balance}, estimated cost {estimated_cost}"
    )
}

pub(crate) fn is_self_broadcast_insufficient_native_gas_error(error: &Report) -> bool {
    error
        .to_string()
        .starts_with("insufficient native gas for self-broadcast:")
}

pub(super) enum SelfBroadcastRawTxBroadcastOutcome {
    Accepted,
    AlreadyKnown,
    Rejected(String),
}

pub(super) struct SelfBroadcastRawTxBroadcastResult {
    pub(super) provider_handle: ProviderHandle,
    pub(super) outcome: SelfBroadcastRawTxBroadcastOutcome,
}

pub(super) async fn sign_send_self_broadcast_transaction(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    signer: &VaultedPublicSigner,
    tx_req: TransactionRequest,
    session: &WalletSession,
    pending_spent_inputs: &[Utxo],
    event_tx: Option<&SelfBroadcastSessionEventSender>,
) -> Result<SelfBroadcastSentTx> {
    tracing::info!(
        from = %tx_req.from.unwrap_or_default(),
        to = ?tx_req.to,
        gas = ?tx_req.gas,
        "signing and sending self-broadcast transaction",
    );
    let signed_tx = signer
        .sign_transaction_request(tx_req, "self-broadcast")
        .await?;
    emit_refreshed_self_broadcast_hardware_session(event_tx, signer);
    let tx_hash = keccak256(&signed_tx);
    let provider_handles = self_broadcast_send_raw_transaction_to_rpc_pool(
        query_rpc_pool,
        network_mode,
        signed_tx,
        tx_hash,
    )
    .await
    .wrap_err("self-broadcast: send")?;
    let tx_hash_string = hex::encode_prefixed(tx_hash);
    session
        .mark_pending_spent_utxos(
            pending_spent_inputs,
            parse_submitted_tx_hash(&tx_hash_string),
        )
        .await;
    tracing::info!(%tx_hash, providers = provider_handles.len(), "sent self-broadcast transaction");
    Ok(SelfBroadcastSentTx {
        tx_hash,
        tx_hash_string,
        provider_handles,
    })
}

pub(crate) async fn self_broadcast_send_raw_transaction_to_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    network_mode: WalletNetworkMode,
    signed_tx: Vec<u8>,
    tx_hash: FixedBytes<32>,
) -> Result<Vec<ProviderHandle>> {
    let providers = query_rpc_pool.available_providers();
    if providers.is_empty() {
        return Err(eyre!("no healthy query RPC available"));
    }

    let policy = SelfBroadcastFeeQuoteTimeoutPolicy::for_network_mode(network_mode);
    let started_at = Instant::now();
    let mut join_set = JoinSet::new();
    for provider_handle in providers {
        join_set.spawn(self_broadcast_send_raw_transaction_to_provider(
            provider_handle,
            signed_tx.clone(),
            tx_hash,
            policy.hard_deadline,
        ));
    }

    let mut accepted_provider_handles = Vec::new();
    let mut last_error = None;
    let mut grace_deadline = None;
    while !join_set.is_empty() {
        let now = Instant::now();
        let Some(hard_remaining) = policy
            .hard_deadline
            .checked_sub(now.saturating_duration_since(started_at))
        else {
            break;
        };
        let wait_for = grace_deadline.map_or(hard_remaining, |deadline: Instant| {
            deadline.saturating_duration_since(now).min(hard_remaining)
        });
        if wait_for.is_zero() {
            break;
        }

        match tokio::time::timeout(wait_for, join_set.join_next()).await {
            Ok(Some(Ok(result))) => match result.outcome {
                SelfBroadcastRawTxBroadcastOutcome::Accepted => {
                    tracing::info!(
                        url = %result.provider_handle.url,
                        %tx_hash,
                        "self-broadcast tx accepted by RPC"
                    );
                    accepted_provider_handles.push(result.provider_handle);
                    if grace_deadline.is_none() {
                        grace_deadline = Some(Instant::now() + policy.grace_after_first_usable);
                    }
                }
                SelfBroadcastRawTxBroadcastOutcome::AlreadyKnown => {
                    tracing::info!(
                        url = %result.provider_handle.url,
                        %tx_hash,
                        "self-broadcast tx already known by RPC"
                    );
                    accepted_provider_handles.push(result.provider_handle);
                    if grace_deadline.is_none() {
                        grace_deadline = Some(Instant::now() + policy.grace_after_first_usable);
                    }
                }
                SelfBroadcastRawTxBroadcastOutcome::Rejected(message) => {
                    tracing::warn!(
                        url = %result.provider_handle.url,
                        %tx_hash,
                        message,
                        "self-broadcast tx rejected by RPC"
                    );
                    last_error = Some(message);
                }
            },
            Ok(Some(Err(error))) => {
                last_error = Some(error.to_string());
            }
            Ok(None) | Err(_) => break,
        }
    }
    join_set.abort_all();

    if accepted_provider_handles.is_empty() {
        return Err(eyre!(last_error.unwrap_or_else(|| {
            "self-broadcast transaction was not accepted by any RPC before the deadline".to_string()
        })));
    }
    Ok(accepted_provider_handles)
}

pub(super) async fn self_broadcast_send_raw_transaction_to_provider(
    provider_handle: ProviderHandle,
    signed_tx: Vec<u8>,
    tx_hash: FixedBytes<32>,
    timeout: Duration,
) -> SelfBroadcastRawTxBroadcastResult {
    let send_result = tokio::time::timeout(
        timeout,
        provider_handle.provider.send_raw_transaction(&signed_tx),
    )
    .await;
    let outcome = match send_result {
        Ok(Ok(pending)) => {
            let returned_hash = pending.tx_hash().to_owned();
            if returned_hash == tx_hash {
                SelfBroadcastRawTxBroadcastOutcome::Accepted
            } else {
                SelfBroadcastRawTxBroadcastOutcome::Rejected(format!(
                    "RPC returned unexpected transaction hash {returned_hash}; expected {tx_hash}"
                ))
            }
        }
        Ok(Err(error)) if is_self_broadcast_tx_already_known_error(&error) => {
            SelfBroadcastRawTxBroadcastOutcome::AlreadyKnown
        }
        Ok(Err(error)) => SelfBroadcastRawTxBroadcastOutcome::Rejected(error.to_string()),
        Err(_) => SelfBroadcastRawTxBroadcastOutcome::Rejected(
            "self-broadcast send timed out".to_string(),
        ),
    };
    SelfBroadcastRawTxBroadcastResult {
        provider_handle,
        outcome,
    }
}

pub(super) fn is_self_broadcast_tx_already_known_error(
    error: &alloy::transports::TransportError,
) -> bool {
    error
        .as_error_resp()
        .is_some_and(|response| is_self_broadcast_tx_already_known_message(&response.message))
}

pub(crate) fn is_self_broadcast_tx_already_known_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("already known")
        || message.contains("already in mempool")
        || message.contains("known transaction")
        || message.contains("already imported")
        || message.contains("already have")
        || message.contains("already exists")
        || message.contains("transaction already")
}

pub(crate) fn tx_receipt_output(
    tx_hash: FixedBytes<32>,
    receipt: &TransactionReceipt,
) -> TxReceiptOutput {
    let status = receipt.status();
    let block_number = receipt.block_number.unwrap_or(0);
    let gas_used = receipt.gas_used;
    if status {
        tracing::info!(%tx_hash, block_number, gas_used, "self-broadcast transaction confirmed");
    } else {
        tracing::warn!(%tx_hash, block_number, gas_used, "self-broadcast transaction reverted");
    }
    TxReceiptOutput {
        tx_hash: hex::encode_prefixed(tx_hash),
        status,
        block_number,
        gas_used,
    }
}

pub(super) async fn mark_submitted_inputs_pending_spent(
    session: &WalletSession,
    inputs: &[Utxo],
    result: &PublicBroadcasterSubmissionResult,
) {
    let PublicBroadcasterResultKind::Submitted { tx_hash } = &result.result else {
        return;
    };
    session
        .mark_pending_spent_utxos(inputs, parse_submitted_tx_hash(tx_hash))
        .await;
}

pub(crate) fn parse_submitted_tx_hash(tx_hash: &str) -> Option<FixedBytes<32>> {
    tx_hash.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trezor_app_passphrase_self_broadcast_error_adds_restart_guidance() {
        let error = eyre!(TREZOR_APP_PASSPHRASE_ERROR_TEXT);
        let message = self_broadcast_signing_error_message(&error);

        assert!(is_trezor_app_passphrase_required_error(&error));
        assert!(message.contains(TREZOR_SELF_BROADCAST_RESTART_GUIDANCE));
    }
}
