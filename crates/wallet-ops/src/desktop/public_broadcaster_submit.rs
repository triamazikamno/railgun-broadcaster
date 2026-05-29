use super::*;
use eyre::eyre;

pub(super) async fn prepare_desktop_unshield_public_broadcaster(
    request: DesktopUnshieldPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PreparedPublicBroadcasterPlan<UnshieldPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain.as_ref())?;
    if request.unwrap && !is_effective_wrapped_native_token(request.chain_id, request.token, &chain)
    {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize public broadcaster unshield spend")?;

    let PublicBroadcasterSetup {
        chain,
        broadcaster,
        query_rpc_pool,
        min_gas_price,
        prover,
        forest,
        utxos,
    } = public_broadcaster_setup(
        &request.session,
        request.chain_id,
        request.effective_chain.as_ref(),
        request.fee_token,
        &request.fee_rows,
        &request.selection,
        request.unwrap,
        request.fee_policy,
        &request.trust_filter,
        request.anchor_cache.as_ref(),
        http,
    )
    .await?;
    let same_token_fee = request.fee_token == request.token;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let seeded_fee_amount =
        initial_public_broadcaster_fee_amount(&broadcaster, min_gas_price, same_token_fee, || {
            let seed_split = public_broadcaster_amount_split_for_tokens_and_protocol(
                request.amount,
                U256::ZERO,
                request.fee_mode,
                same_token_fee,
                RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
            )?;
            let selection = unshield_selection_info_with_separate_broadcaster_fee_seed(
                &utxos,
                request.token,
                request.fee_token,
                seed_split.receiver_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    U256::ZERO,
                    seed_split.fee_mode,
                    same_token_fee,
                    RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
                )
            })?;
            Ok(unshield_approximate_shape(
                &selection,
                selection.max_spendable,
                request.unwrap,
            ))
        })?;
    let initial_fee_estimate = match approximate_public_broadcaster_cost(
        broadcaster.clone(),
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        min_gas_price,
        seeded_fee_amount,
        |split| {
            let selection = unshield_selection_info_with_broadcaster_fee_token(
                &utxos,
                request.token,
                request.fee_token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    split.fee_amount,
                    split.fee_mode,
                    same_token_fee,
                    RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
                )
            })?;
            Ok(unshield_approximate_shape(
                &selection,
                selection.max_spendable,
                request.unwrap,
            ))
        },
    ) {
        Ok(estimate) => {
            tracing::info!(
                fee_amount = %estimate.fee_amount,
                gas_limit = estimate.gas_limit,
                min_gas_price,
                transaction_count = estimate.transaction_count,
                input_count = estimate.input_count,
                private_output_count = estimate.private_output_count,
                public_output_count = estimate.public_output_count,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "using approximate public broadcaster unshield fee for first proof"
            );
            Some(estimate)
        }
        Err(err) => {
            if !same_token_fee {
                return Err(err).wrap_err("estimate initial public broadcaster unshield fee");
            }
            tracing::warn!(
                ?err,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "failed to estimate initial same-token public broadcaster unshield fee; starting at zero"
            );
            None
        }
    };
    let initial_fee_amount = initial_fee_estimate
        .as_ref()
        .map_or(U256::ZERO, |estimate| estimate.fee_amount);

    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load public broadcaster unshield spend signer")?;

    let mode = if request.unwrap {
        UnshieldMode::UnwrapBase
    } else {
        UnshieldMode::Token
    };
    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    let mut fee_amount = initial_fee_amount;
    for attempt in 1..=PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split_for_tokens_and_protocol(
            request.amount,
            fee_amount,
            request.fee_mode,
            same_token_fee,
            RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        )?;
        let unshield_request = RailgunUnshieldRequest {
            token_address: request.token,
            amount: split.receiver_amount,
            recipient: request.recipient,
            mode,
            verify_proof: request.verify_proof,
            spend_up_to: false,
            broadcaster_fee: Some(BroadcasterFeeOutput {
                recipient: broadcaster.address_data,
                token_address: request.fee_token,
                amount: fee_amount,
            }),
            min_gas_price,
        };
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::ProvingTransaction,
        );
        let proof_started = Instant::now();
        let plan = tx_builder
            .build_unshield_plan_with_signer(
                &request.view_session.scan_keys(),
                &signer,
                &forest,
                &utxos,
                unshield_request,
                &prover,
            )
            .await
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    fee_amount,
                    split.fee_mode,
                    same_token_fee,
                    RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
                )
            })
            .wrap_err("build public broadcaster unshield proof")?;
        tracing::info!(
            attempt,
            fee_amount = %fee_amount,
            elapsed_ms = proof_started.elapsed().as_millis(),
            transaction_count = plan.transaction_count(),
            input_count = plan.input_count(),
            private_output_count = plan.private_output_count(),
            public_output_count = plan.public_output_count(),
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "built public broadcaster unshield proof"
        );
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingBroadcasterFee,
        );
        let gas_started = Instant::now();
        let (gas_limit, computed_fee) = estimate_public_broadcaster_fee_from_rpc_pool(
            &query_rpc_pool,
            request.chain_id,
            plan.call.to,
            &plan.call.data,
            broadcaster.fee,
            min_gas_price,
            chain.gas.gas_limit_buffer,
        )
        .await?;
        let gas_elapsed_ms = gas_started.elapsed().as_millis();
        tracing::info!(
            attempt,
            available_fee = %fee_amount,
            computed_fee = %computed_fee,
            gas_limit,
            min_gas_price,
            gas_elapsed_ms,
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "estimated public broadcaster unshield fee"
        );
        if broadcaster_fee_covers(fee_amount, computed_fee) {
            let protocol_fee_amount = railgun_protocol_fee_amount(
                split.receiver_amount,
                RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
            );
            tracing::info!(
                attempt,
                fee_amount = %fee_amount,
                computed_fee = %computed_fee,
                gas_limit,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "public broadcaster unshield fee stabilized"
            );
            update_transaction_generation_stage(
                request.progress_tx.as_ref(),
                TransactionGenerationStage::GeneratingPoiProofs,
            );
            let pre_transaction_pois = public_broadcaster_pre_transaction_pois(
                &plan.chunks,
                &broadcaster,
                request.session.as_ref(),
                request.chain_id,
                &prover,
                request.verify_proof,
                http,
            )
            .await?;
            let pending_persist_started = Instant::now();
            let pending_contexts = persist_pending_unshield_output_poi_contexts(
                request.session.db.as_ref(),
                request.chain_id,
                request.view_session.wallet_id(),
                &plan.chunks,
                &pre_transaction_pois.pending_pois,
                &pre_transaction_pois.pending_poi_list_keys,
                true,
                !same_token_fee,
            )?;
            tracing::info!(
                chain_id = request.chain_id,
                pending_contexts,
                elapsed_ms = pending_persist_started.elapsed().as_millis(),
                "persisted public broadcaster unshield pending output POI contexts"
            );
            return Ok(PreparedPublicBroadcasterPlan {
                plan,
                pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois.request_pois,
                broadcaster,
                action_token: request.token,
                fee_token: request.fee_token,
                entered_amount: split.entered_amount,
                receiver_amount: split.receiver_amount,
                recipient_amount: recipient_amount_after_protocol_fee(
                    split.receiver_amount,
                    protocol_fee_amount,
                ),
                total_private_spend: split.total_private_spend,
                fee_amount,
                protocol_fee_amount,
                protocol_fee_bps: RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
                fee_mode: split.fee_mode,
                gas_limit,
                min_gas_price,
            });
        }
        let next_fee = buffered_public_broadcaster_fee(computed_fee);
        log_public_broadcaster_fee_prediction_failure(
            "unshield",
            attempt,
            fee_amount,
            computed_fee,
            gas_limit,
            initial_fee_estimate.as_ref(),
            plan.transaction_count(),
            plan.input_count(),
            plan.private_output_count(),
            plan.public_output_count(),
            &broadcaster,
        );
        tracing::info!(
            attempt,
            previous_fee = %fee_amount,
            computed_fee = %computed_fee,
            next_fee = %next_fee,
            "retrying public broadcaster unshield proof with buffered fee"
        );
        fee_amount = next_fee;
    }

    Err(eyre!(
        "public broadcaster fee did not stabilize after bounded retries"
    ))
}

pub(super) async fn prepare_desktop_send_public_broadcaster(
    request: DesktopSendPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PreparedPublicBroadcasterPlan<SendPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }

    let mut grant = request
        .vault_store
        .create_spend_grant(request.vault_password.as_str())
        .wrap_err("authorize public broadcaster send spend")?;

    let recipient = parse_railgun_recipient(&request.recipient)?;
    let PublicBroadcasterSetup {
        chain,
        broadcaster,
        query_rpc_pool,
        min_gas_price,
        prover,
        forest,
        utxos,
    } = public_broadcaster_setup(
        &request.session,
        request.chain_id,
        request.effective_chain.as_ref(),
        request.fee_token,
        &request.fee_rows,
        &request.selection,
        false,
        request.fee_policy,
        &request.trust_filter,
        request.anchor_cache.as_ref(),
        http,
    )
    .await?;
    let same_token_fee = request.fee_token == request.token;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let seeded_fee_amount =
        initial_public_broadcaster_fee_amount(&broadcaster, min_gas_price, same_token_fee, || {
            let selection = send_selection_info_with_separate_broadcaster_fee_seed(
                &utxos,
                request.token,
                request.fee_token,
                request.amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    U256::ZERO,
                    FeeHandlingMode::AddToAmount,
                    same_token_fee,
                    U256::ZERO,
                )
            })?;
            Ok(send_approximate_shape(&selection, selection.max_spendable))
        })?;
    let initial_fee_estimate = match approximate_public_broadcaster_cost(
        broadcaster.clone(),
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        U256::ZERO,
        min_gas_price,
        seeded_fee_amount,
        |split| {
            let selection = send_selection_info_with_broadcaster_fee_token(
                &utxos,
                request.token,
                request.fee_token,
                split.receiver_amount,
                split.fee_amount,
                false,
            )
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    split.fee_amount,
                    split.fee_mode,
                    same_token_fee,
                    U256::ZERO,
                )
            })?;
            Ok(send_approximate_shape(&selection, selection.max_spendable))
        },
    ) {
        Ok(estimate) => {
            tracing::info!(
                fee_amount = %estimate.fee_amount,
                gas_limit = estimate.gas_limit,
                min_gas_price,
                transaction_count = estimate.transaction_count,
                input_count = estimate.input_count,
                private_output_count = estimate.private_output_count,
                public_output_count = estimate.public_output_count,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "using approximate public broadcaster send fee for first proof"
            );
            Some(estimate)
        }
        Err(err) => {
            if !same_token_fee {
                return Err(err).wrap_err("estimate initial public broadcaster send fee");
            }
            tracing::warn!(
                ?err,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "failed to estimate initial same-token public broadcaster send fee; starting at zero"
            );
            None
        }
    };
    let initial_fee_amount = initial_fee_estimate
        .as_ref()
        .map_or(U256::ZERO, |estimate| estimate.fee_amount);

    let signer = request
        .vault_store
        .railgun_spend_signer(&mut grant, request.view_session.wallet_id())
        .wrap_err("load public broadcaster send spend signer")?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    let mut fee_amount = initial_fee_amount;
    for attempt in 1..=PUBLIC_BROADCASTER_FEE_ATTEMPTS {
        let split = public_broadcaster_amount_split_for_tokens(
            request.amount,
            fee_amount,
            request.fee_mode,
            same_token_fee,
        )?;
        let send_request = RailgunSendRequest {
            token_address: request.token,
            amount: split.receiver_amount,
            recipient,
            verify_proof: request.verify_proof,
            spend_up_to: false,
            broadcaster_fee: Some(BroadcasterFeeOutput {
                recipient: broadcaster.address_data,
                token_address: request.fee_token,
                amount: fee_amount,
            }),
            min_gas_price,
        };
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::ProvingTransaction,
        );
        let proof_started = Instant::now();
        let plan = tx_builder
            .build_send_plan_with_signer(
                &request.view_session.scan_keys(),
                &signer,
                &forest,
                &utxos,
                send_request,
                &prover,
            )
            .await
            .map_err(|error| {
                public_broadcaster_build_error(
                    error,
                    fee_amount,
                    split.fee_mode,
                    same_token_fee,
                    U256::ZERO,
                )
            })
            .wrap_err("build public broadcaster send proof")?;
        let chunk_input_counts = plan
            .chunks
            .iter()
            .map(|chunk| chunk.inputs.len())
            .collect::<Vec<_>>();
        let chunk_output_counts = plan
            .chunks
            .iter()
            .map(|chunk| chunk.outputs.len())
            .collect::<Vec<_>>();
        let chunk_tree_numbers = plan
            .chunks
            .iter()
            .map(|chunk| chunk.tree_number)
            .collect::<Vec<_>>();
        tracing::info!(
            attempt,
            fee_amount = %fee_amount,
            elapsed_ms = proof_started.elapsed().as_millis(),
            transaction_count = plan.transaction_count(),
            input_count = plan.input_count(),
            private_output_count = plan.private_output_count(),
            public_output_count = plan.public_output_count(),
            same_token_fee,
            ?chunk_input_counts,
            ?chunk_output_counts,
            ?chunk_tree_numbers,
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "built public broadcaster send proof"
        );
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::EstimatingBroadcasterFee,
        );
        let gas_started = Instant::now();
        let (gas_limit, computed_fee) = estimate_public_broadcaster_fee_from_rpc_pool(
            &query_rpc_pool,
            request.chain_id,
            plan.call.to,
            &plan.call.data,
            broadcaster.fee,
            min_gas_price,
            chain.gas.gas_limit_buffer,
        )
        .await?;
        let gas_elapsed_ms = gas_started.elapsed().as_millis();
        tracing::info!(
            attempt,
            available_fee = %fee_amount,
            computed_fee = %computed_fee,
            gas_limit,
            min_gas_price,
            gas_elapsed_ms,
            broadcaster = %broadcaster.railgun_address,
            fees_id = %broadcaster.fees_id,
            "estimated public broadcaster send fee"
        );
        if broadcaster_fee_covers(fee_amount, computed_fee) {
            let protocol_fee_amount = U256::ZERO;
            tracing::info!(
                attempt,
                fee_amount = %fee_amount,
                computed_fee = %computed_fee,
                gas_limit,
                broadcaster = %broadcaster.railgun_address,
                fees_id = %broadcaster.fees_id,
                "public broadcaster send fee stabilized"
            );
            update_transaction_generation_stage(
                request.progress_tx.as_ref(),
                TransactionGenerationStage::GeneratingPoiProofs,
            );
            let pre_transaction_pois = public_broadcaster_pre_transaction_pois(
                &plan.chunks,
                &broadcaster,
                request.session.as_ref(),
                request.chain_id,
                &prover,
                request.verify_proof,
                http,
            )
            .await?;
            let pending_persist_started = Instant::now();
            let pending_contexts = persist_pending_send_output_poi_contexts(
                request.session.db.as_ref(),
                request.chain_id,
                request.view_session.wallet_id(),
                &plan.chunks,
                &pre_transaction_pois.pending_pois,
                &pre_transaction_pois.pending_poi_list_keys,
                true,
                !same_token_fee,
            )?;
            tracing::info!(
                chain_id = request.chain_id,
                pending_contexts,
                elapsed_ms = pending_persist_started.elapsed().as_millis(),
                "persisted public broadcaster send pending output POI contexts"
            );
            return Ok(PreparedPublicBroadcasterPlan {
                plan,
                pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois.request_pois,
                broadcaster,
                action_token: request.token,
                fee_token: request.fee_token,
                entered_amount: split.entered_amount,
                receiver_amount: split.receiver_amount,
                recipient_amount: recipient_amount_after_protocol_fee(
                    split.receiver_amount,
                    protocol_fee_amount,
                ),
                total_private_spend: split.total_private_spend,
                fee_amount,
                protocol_fee_amount,
                protocol_fee_bps: U256::ZERO,
                fee_mode: split.fee_mode,
                gas_limit,
                min_gas_price,
            });
        }
        let next_fee = buffered_public_broadcaster_fee(computed_fee);
        log_public_broadcaster_fee_prediction_failure(
            "send",
            attempt,
            fee_amount,
            computed_fee,
            gas_limit,
            initial_fee_estimate.as_ref(),
            plan.transaction_count(),
            plan.input_count(),
            plan.private_output_count(),
            plan.public_output_count(),
            &broadcaster,
        );
        tracing::info!(
            attempt,
            previous_fee = %fee_amount,
            computed_fee = %computed_fee,
            next_fee = %next_fee,
            "retrying public broadcaster send proof with buffered fee"
        );
        fee_amount = next_fee;
    }

    Err(eyre!(
        "public broadcaster fee did not stabilize after bounded retries"
    ))
}

pub(super) async fn estimate_public_broadcaster_fee(
    provider: &(impl Provider + Clone),
    chain_id: u64,
    to: Address,
    data: &Bytes,
    token_fee_per_unit_gas: U256,
    min_gas_price: u128,
    gas_limit_buffer: u64,
) -> Result<(u64, U256)> {
    let tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_to(to)
        .with_input(data.clone())
        .with_gas_price(min_gas_price);
    let estimated_gas = provider
        .estimate_gas(tx_req)
        .await
        .wrap_err("estimate public broadcaster gas")?;
    let gas_limit = public_broadcaster_gas_limit_with_buffer(estimated_gas, gas_limit_buffer);
    let service_gas_price = public_broadcaster_service_gas_price(min_gas_price);
    Ok((
        gas_limit,
        broadcaster_fee_amount(token_fee_per_unit_gas, gas_limit, service_gas_price),
    ))
}

pub(super) async fn estimate_public_broadcaster_fee_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    chain_id: u64,
    to: Address,
    data: &Bytes,
    token_fee_per_unit_gas: U256,
    min_gas_price: u128,
    gas_limit_buffer: u64,
) -> Result<(u64, U256)> {
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match estimate_public_broadcaster_fee(
            &provider_handle.provider,
            chain_id,
            to,
            data,
            token_fee_per_unit_gas,
            min_gas_price,
            gas_limit_buffer,
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(error) => {
                tracing::warn!(%error, rpc = %provider_handle.url, "estimate public broadcaster gas failed");
                query_rpc_pool.mark_bad_provider(&provider_handle);
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all query RPC public broadcaster gas estimate attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

pub(crate) const fn public_broadcaster_gas_limit_with_buffer(
    estimated_gas: u64,
    gas_limit_buffer: u64,
) -> u64 {
    estimated_gas.saturating_add(gas_limit_buffer)
}

pub(crate) fn public_broadcaster_transact_params(
    broadcaster: &PublicBroadcasterCandidate,
    to: Address,
    data: Bytes,
    min_gas_price: u128,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoiMap,
) -> BroadcasterRawParamsTransact {
    BroadcasterRawParamsTransact {
        chain_type: 0,
        chain_id: broadcaster.chain_id,
        min_gas_price: Some(U256::from(min_gas_price)),
        fees_id: Some(broadcaster.fees_id.clone()),
        to,
        data,
        broadcaster_viewing_key: FixedBytes::from(broadcaster.viewing_public_key),
        txid_version: Some(DEFAULT_TXID_VERSION.to_string()),
        pre_transaction_pois_per_txid_leaf_per_list,
    }
}

pub(super) async fn publish_public_broadcaster_payload(
    waku: &WakuClient,
    pubsub_path: &str,
    transact_topic: &str,
    payload: &[u8],
    attempt: usize,
) -> Result<()> {
    tracing::info!(
        pubsub_path = %pubsub_path,
        transact_topic = %transact_topic,
        payload_len = payload.len(),
        attempt,
        "publishing public broadcaster transact request"
    );
    let publish_started = Instant::now();
    waku.publish(transact_topic, payload)
        .await
        .wrap_err("publish public broadcaster transact request")?;
    tracing::info!(
        pubsub_path = %pubsub_path,
        transact_topic = %transact_topic,
        elapsed_ms = publish_started.elapsed().as_millis(),
        attempt,
        "published public broadcaster transact request"
    );
    Ok(())
}

pub(crate) async fn public_broadcaster_republish_loop<F, Fut>(
    mut stop_rx: oneshot::Receiver<()>,
    republish_interval: Duration,
    mut publish: F,
) where
    F: FnMut(usize) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    let mut attempt = 1usize;
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            () = tokio::time::sleep(republish_interval) => {
                attempt = attempt.saturating_add(1);
                if let Err(error) = publish(attempt).await {
                    tracing::warn!(%error, attempt, "republish public broadcaster transact request failed");
                }
            }
        }
    }
}

pub(super) async fn submit_public_broadcaster_plan(
    waku: Arc<WakuClient>,
    to: Address,
    data: Bytes,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoiMap,
    broadcaster: PublicBroadcasterCandidate,
    action_token: Address,
    fee_token: Address,
    entered_amount: U256,
    receiver_amount: U256,
    recipient_amount: U256,
    total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    protocol_fee_bps: U256,
    fee_mode: FeeHandlingMode,
    gas_limit: u64,
    min_gas_price: u128,
    progress_tx: Option<TransactionGenerationProgressSender>,
    timeout: Duration,
    republish_interval: Duration,
) -> Result<PublicBroadcasterSubmissionResult> {
    let transact_topic = transact_topic(broadcaster.chain_id);
    let response_topic = transact_response_topic(broadcaster.chain_id);
    tracing::info!(
        chain_id = broadcaster.chain_id,
        broadcaster = %broadcaster.railgun_address,
        broadcaster_identifier = ?broadcaster.identifier.as_deref(),
        fees_id = %broadcaster.fees_id,
        token = ?broadcaster.token,
        to = ?to,
        fee_amount = %fee_amount,
        gas_limit,
        min_gas_price,
        data_len = data.len(),
        transact_topic = %transact_topic,
        response_topic = %response_topic,
        "preparing public broadcaster transact request"
    );
    update_transaction_generation_stage(
        progress_tx.as_ref(),
        TransactionGenerationStage::PublishingToBroadcaster,
    );
    let params = public_broadcaster_transact_params(
        &broadcaster,
        to,
        data,
        min_gas_price,
        pre_transaction_pois_per_txid_leaf_per_list,
    );
    let encrypt_started = Instant::now();
    let encrypted = EncryptedTransactRequest::encrypt(broadcaster.viewing_public_key, &params)
        .wrap_err("encrypt public broadcaster transact request")?;
    let payload = encrypted
        .to_transact_payload()
        .wrap_err("serialize public broadcaster transact request")?;
    tracing::info!(
        chain_id = broadcaster.chain_id,
        broadcaster = %broadcaster.railgun_address,
        fees_id = %broadcaster.fees_id,
        payload_len = payload.len(),
        elapsed_ms = encrypt_started.elapsed().as_millis(),
        "built public broadcaster encrypted Waku payload"
    );
    let pubsub_path = waku.pubsub_path().to_string();
    tracing::info!(
        pubsub_path = %pubsub_path,
        response_topic = %response_topic,
        "subscribing to public broadcaster response topic"
    );
    let subscribe_started = Instant::now();
    let mut response_rx = waku
        .subscribe(vec![response_topic.clone()])
        .await
        .wrap_err("subscribe to public broadcaster response topic")?;
    tracing::info!(
        response_topic = %response_topic,
        elapsed_ms = subscribe_started.elapsed().as_millis(),
        "subscribed to public broadcaster response topic"
    );
    publish_public_broadcaster_payload(&waku, &pubsub_path, &transact_topic, &payload, 1)
        .await
        .wrap_err("publish initial public broadcaster transact request")?;
    update_transaction_generation_stage(
        progress_tx.as_ref(),
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

    let (republish_stop_tx, republish_stop_rx) = oneshot::channel();
    let republish_waku = Arc::clone(&waku);
    let republish_pubsub_path = pubsub_path.clone();
    let republish_transact_topic = transact_topic.clone();
    let republish_payload = payload.clone();
    let republish_handle = tokio::spawn(public_broadcaster_republish_loop(
        republish_stop_rx,
        republish_interval,
        move |attempt| {
            let waku = Arc::clone(&republish_waku);
            let pubsub_path = republish_pubsub_path.clone();
            let transact_topic = republish_transact_topic.clone();
            let payload = republish_payload.clone();
            async move {
                publish_public_broadcaster_payload(
                    &waku,
                    &pubsub_path,
                    &transact_topic,
                    &payload,
                    attempt,
                )
                .await
            }
        },
    ));

    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    let result = loop {
        tokio::select! {
            () = &mut sleep => {
                tracing::warn!(
                    chain_id = broadcaster.chain_id,
                    broadcaster = %broadcaster.railgun_address,
                    fees_id = %broadcaster.fees_id,
                    response_topic = %response_topic,
                    timeout_ms = timeout.as_millis(),
                    "timed out waiting for public broadcaster response"
                );
                break PublicBroadcasterResultKind::TimedOut;
            },
            msg = response_rx.recv() => {
                let Some(msg) = msg else {
                    tracing::warn!(response_topic = %response_topic, "public broadcaster response channel closed");
                    break PublicBroadcasterResultKind::TimedOut;
                };
                tracing::info!(
                    content_topic = %msg.content_topic,
                    payload_len = msg.payload.len(),
                    "received public broadcaster response candidate"
                );
                match decode_public_broadcaster_response(&encrypted.shared_key, &msg.payload) {
                    Ok(Some(result)) => {
                        tracing::info!(?result, "decrypted public broadcaster response");
                        break result;
                    }
                    Ok(None) => tracing::debug!("public broadcaster response was not decryptable with request key"),
                    Err(error) => tracing::debug!(%error, "ignoring undecryptable public broadcaster response"),
                }
            }
        }
    };
    let _ = republish_stop_tx.send(());
    republish_handle.abort();

    Ok(PublicBroadcasterSubmissionResult {
        broadcaster,
        action_token,
        fee_token,
        entered_amount,
        receiver_amount,
        recipient_amount,
        total_private_spend,
        fee_amount,
        protocol_fee_amount,
        protocol_fee_bps,
        fee_mode,
        gas_limit,
        min_gas_price,
        result,
    })
}
