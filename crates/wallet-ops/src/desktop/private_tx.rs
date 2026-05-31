use super::*;
use eyre::eyre;

pub(super) async fn prepare_desktop_unshield_plan_without_broadcaster_fee(
    request: DesktopUnshieldPlanRequest<'_>,
    http: &HttpContext,
) -> Result<PreparedPrivatePlan<UnshieldPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain)?;
    if request.unwrap && !is_effective_wrapped_native_token(request.chain_id, request.token, &chain)
    {
        return Err(eyre!("selected token does not support unwrap-to-native"));
    }

    let artifact_source = artifact_source(http, request.session.db.as_ref());
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session.db));
    let chain_handle = request
        .session
        .sync_manager
        .chain_handle(&request.session.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", request.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let utxos = request.session.unspent_utxos().await;
    let mode = if request.unwrap {
        UnshieldMode::UnwrapBase
    } else {
        UnshieldMode::Token
    };
    let receiver_amount = unshield_receiver_amount_for_fee_mode(request.amount, request.fee_mode)?;
    let unshield_request = RailgunUnshieldRequest {
        token_address: request.token,
        amount: receiver_amount,
        recipient: request.recipient,
        mode,
        verify_proof: request.verify_proof,
        spend_up_to: false,
        broadcaster_fee: None,
        min_gas_price: 0,
    };
    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = unshield_selection_info(&utxos, request.token, receiver_amount, false)
        .wrap_err("select POI-verified unshield notes")?;

    let signer = request.spend_authorization.into_signer(
        request.vault_store,
        request.view_session.wallet_id(),
        "unshield",
    )?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::ProvingTransaction,
    );
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
        .wrap_err("build desktop unshield calldata")?;

    Ok(PreparedPrivatePlan {
        plan,
        max_spendable: selection_info.max_spendable,
        prover,
    })
}

pub async fn prepare_blocked_shield_rescue_preview(
    request: BlockedShieldRescuePreviewRequest,
    http: &HttpContext,
) -> Result<BlockedShieldRescuePreview> {
    let utxo = selected_blocked_shield_rescue_utxo(&request.session, &request.utxo_id).await?;
    let eligibility = resolve_blocked_shield_rescue_eligibility(
        BlockedShieldRescueEligibilityRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain,
            view_session: request.view_session,
            session: request.session,
            vault_store: request.vault_store,
            utxo_id: request.utxo_id,
        },
        http,
    )
    .await?;
    let origin_address = eligibility
        .origin_address
        .ok_or_else(|| eyre!("blocked Shield refund origin is unresolved"))?;
    let public_account_uuid = eligibility
        .public_account_uuid
        .ok_or_else(|| eyre!("blocked Shield refund origin Public account is unavailable"))?;
    if !eligibility.eligible {
        return Err(eyre!(
            "blocked Shield refund is unavailable: {}",
            eligibility
                .disabled_reason
                .as_deref()
                .unwrap_or("eligibility check failed")
        ));
    }

    Ok(BlockedShieldRescuePreview {
        chain_id: request.chain_id,
        utxo_id: request.utxo_id,
        token: utxo.token_address(),
        amount: utxo.note.value,
        source_tx_hash: utxo.source.tx_hash,
        origin_address,
        public_account_uuid,
        public_account_label: eligibility.public_account_label,
    })
}

pub(super) async fn prepare_blocked_shield_rescue_plan(
    request: &BlockedShieldRescueSelfBroadcastRequest,
    http: &HttpContext,
) -> Result<PreparedBlockedShieldRescuePlan> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain.as_ref())?;
    let utxo = selected_blocked_shield_rescue_utxo(&request.session, &request.utxo_id).await?;
    let token = utxo.token_address();
    let amount = utxo.note.value;
    let eligibility = resolve_blocked_shield_rescue_eligibility(
        BlockedShieldRescueEligibilityRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.clone(),
            view_session: Arc::clone(&request.view_session),
            session: Arc::clone(&request.session),
            vault_store: Arc::clone(&request.vault_store),
            utxo_id: request.utxo_id,
        },
        http,
    )
    .await?;
    if !eligibility.eligible {
        return Err(eyre!(
            "blocked Shield refund is unavailable: {}",
            eligibility
                .disabled_reason
                .as_deref()
                .unwrap_or("eligibility check failed")
        ));
    }
    let origin_address = eligibility
        .origin_address
        .ok_or_else(|| eyre!("blocked Shield refund origin is unresolved"))?;
    let public_account_uuid = matched_blocked_shield_rescue_public_account_uuid(
        eligibility.public_account_uuid.as_deref(),
        request.requested_public_account_uuid.as_deref(),
    )?;

    let artifact_source = artifact_source(http, request.session.db.as_ref());
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session.db));
    let chain_handle = request
        .session
        .sync_manager
        .chain_handle(&request.session.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", request.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let rescue_utxos = vec![utxo.clone()];
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = unshield_selection_info(&rescue_utxos, token, amount, false)
        .wrap_err("select blocked Shield refund note")?;
    if selection_info.input_count != 1 || selection_info.max_spendable != amount {
        return Err(eyre!(
            "blocked Shield refund must select exactly the chosen UTXO"
        ));
    }

    let signer = request.spend_authorization.signer(
        request.vault_store.as_ref(),
        request.view_session.wallet_id(),
        "blocked Shield refund",
    )?;
    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };
    let unshield_request = RailgunUnshieldRequest {
        token_address: token,
        amount,
        recipient: origin_address,
        mode: UnshieldMode::Token,
        verify_proof: request.verify_proof,
        spend_up_to: false,
        broadcaster_fee: None,
        min_gas_price: 0,
    };

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::ProvingTransaction,
    );
    let plan = tx_builder
        .build_unshield_plan_with_signer(
            &request.view_session.scan_keys(),
            &signer,
            &forest,
            &rescue_utxos,
            unshield_request,
            &prover,
        )
        .await
        .wrap_err("build blocked Shield refund calldata")?;
    validate_blocked_shield_rescue_plan(&plan, &request.utxo_id, token, amount, origin_address)?;

    Ok(PreparedBlockedShieldRescuePlan {
        plan,
        public_account_uuid,
    })
}

pub(super) async fn selected_blocked_shield_rescue_utxo(
    session: &WalletSession,
    utxo_id: &BlockedShieldRescueUtxoId,
) -> Result<Utxo> {
    let utxos = session.handle.utxos.read().await.clone();
    let pending_overlay = session.handle.pending_overlay().await;
    blocked_shield_rescue_candidate_from_records(&utxos, &pending_overlay, utxo_id)
        .ok_or_else(|| eyre!("selected UTXO is not an unspent blocked Shield that can be refunded"))
}

pub(crate) fn matched_blocked_shield_rescue_public_account_uuid(
    matched: Option<&str>,
    requested: Option<&str>,
) -> Result<String> {
    let matched =
        matched.ok_or_else(|| eyre!("blocked Shield refund origin account is unavailable"))?;
    if let Some(requested) = requested
        && requested != matched
    {
        return Err(eyre!(
            "blocked Shield refund gas payer must be the matched origin Public account"
        ));
    }
    Ok(matched.to_string())
}

pub(crate) fn validate_blocked_shield_rescue_plan(
    plan: &UnshieldPlan,
    utxo_id: &BlockedShieldRescueUtxoId,
    token: Address,
    amount: U256,
    origin_address: Address,
) -> Result<()> {
    if plan.inputs.len() != 1 {
        return Err(eyre!(
            "blocked Shield refund must spend exactly one private input"
        ));
    }
    let input = &plan.inputs[0].utxo;
    if !blocked_shield_rescue_utxo_matches(input, utxo_id) {
        return Err(eyre!("blocked Shield refund selected an unexpected UTXO"));
    }
    if input.note.value != amount || plan.unshield_note.value != amount {
        return Err(eyre!(
            "blocked Shield refund must spend the full UTXO value"
        ));
    }
    let expected_unshield = Note::new_unshield(origin_address, token, amount);
    if plan.unshield_note.token_hash != expected_unshield.token_hash
        || plan.unshield_note.npk != expected_unshield.npk
    {
        return Err(eyre!(
            "blocked Shield refund must unshield the exact token to the origin address"
        ));
    }
    if plan.unshield_notes.len() != 1 {
        return Err(eyre!(
            "blocked Shield refund must have exactly one public output"
        ));
    }
    if plan.broadcaster_fee_note.is_some() {
        return Err(eyre!(
            "blocked Shield refund cannot include a broadcaster fee note"
        ));
    }
    if plan.change_note.is_some() {
        return Err(eyre!("blocked Shield refund cannot create private change"));
    }
    for chunk in &plan.chunks {
        if chunk.private_output_count() != Some(0) {
            return Err(eyre!("blocked Shield refund cannot create private outputs"));
        }
    }
    Ok(())
}

pub(super) async fn prepare_desktop_send_plan_without_broadcaster_fee(
    request: DesktopSendPlanRequest<'_>,
    http: &HttpContext,
) -> Result<PreparedPrivatePlan<SendPlan>> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }

    let recipient = request.recipient.trim();
    let recipient_data = parse_railgun_recipient(recipient)?;
    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain)?;
    let artifact_source = artifact_source(http, request.session.db.as_ref());
    let prover = ProverService::new_with_db(artifact_source, Arc::clone(&request.session.db));
    let chain_handle = request
        .session
        .sync_manager
        .chain_handle(&request.session.chain_key)
        .await
        .ok_or_else(|| eyre!("chain handle not found for chain {}", request.chain_id))?;
    let mut forest = chain_handle.forest.read().await.clone();
    forest.compute_roots();

    let utxos = request.session.unspent_utxos().await;
    let send_request = RailgunSendRequest {
        token_address: request.token,
        amount: request.amount,
        recipient: recipient_data,
        verify_proof: request.verify_proof,
        spend_up_to: false,
        broadcaster_fee: None,
        min_gas_price: 0,
    };
    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::SelectingPrivateNotes,
    );
    let selection_info = send_selection_info(&utxos, request.token, request.amount, false)
        .wrap_err("select POI-verified send notes")?;

    let signer = request.spend_authorization.into_signer(
        request.vault_store,
        request.view_session.wallet_id(),
        "send",
    )?;

    let tx_builder = TransactionBuilder {
        chain_type: 0,
        chain_id: request.chain_id,
        railgun_contract: chain.railgun_contract,
        relay_adapt_contract: chain.relay_adapt_contract,
    };

    update_transaction_generation_stage(
        request.progress_tx,
        TransactionGenerationStage::ProvingTransaction,
    );
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
        .wrap_err("build desktop send calldata")?;

    Ok(PreparedPrivatePlan {
        plan,
        max_spendable: selection_info.max_spendable,
        prover,
    })
}

pub(super) async fn persist_manual_unshield_pending_pois(
    plan: &UnshieldPlan,
    session: &WalletSession,
    chain_id: u64,
    wallet_id: &str,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    operation_label: &'static str,
) -> Result<()> {
    let (pending_poi_list_keys, pending_pois) = active_list_pre_transaction_pois(
        &plan.chunks,
        session,
        chain_id,
        prover,
        verify_proof,
        http,
        operation_label,
    )
    .await?;
    persist_pending_unshield_output_poi_contexts(
        session.db.as_ref(),
        chain_id,
        wallet_id,
        &plan.chunks,
        &pending_pois,
        &pending_poi_list_keys,
        false,
        false,
    )?;
    Ok(())
}

pub(super) async fn persist_manual_send_pending_pois(
    plan: &SendPlan,
    session: &WalletSession,
    chain_id: u64,
    wallet_id: &str,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    operation_label: &'static str,
) -> Result<()> {
    let (pending_poi_list_keys, pending_pois) = active_list_pre_transaction_pois(
        &plan.chunks,
        session,
        chain_id,
        prover,
        verify_proof,
        http,
        operation_label,
    )
    .await?;
    persist_pending_send_output_poi_contexts(
        session.db.as_ref(),
        chain_id,
        wallet_id,
        &plan.chunks,
        &pending_pois,
        &pending_poi_list_keys,
        false,
        false,
    )?;
    Ok(())
}

pub(crate) fn unshield_chunks_require_pending_output_pois(chunks: &[TransactionPlanChunk]) -> bool {
    chunks
        .iter()
        .any(|chunk| chunk.private_output_count().is_none_or(|count| count > 0))
}

pub(super) fn prepared_unshield_call_from_plan(
    chain_id: u64,
    token: Address,
    amount: U256,
    recipient: Address,
    unwrap: bool,
    max_spendable: U256,
    plan: &UnshieldPlan,
) -> PreparedUnshieldCall {
    PreparedUnshieldCall {
        chain_id,
        token,
        amount,
        recipient,
        unwrap,
        max_spendable,
        transaction_count: plan.transaction_count(),
        input_count: plan.input_count(),
        private_output_count: plan.private_output_count(),
        public_output_count: plan.public_output_count(),
        to: plan.call.to,
        data: hex::encode_prefixed(&plan.call.data),
    }
}

pub(super) fn prepared_send_call_from_plan(
    chain_id: u64,
    token: Address,
    amount: U256,
    recipient: String,
    max_spendable: U256,
    plan: &SendPlan,
) -> PreparedSendCall {
    PreparedSendCall {
        chain_id,
        token,
        amount,
        recipient,
        max_spendable,
        transaction_count: plan.transaction_count(),
        input_count: plan.input_count(),
        private_output_count: plan.private_output_count(),
        public_output_count: plan.public_output_count(),
        to: plan.call.to,
        data: hex::encode_prefixed(&plan.call.data),
    }
}

pub async fn prepare_desktop_unshield_calldata(
    request: DesktopUnshieldCalldataRequest,
    http: &HttpContext,
) -> Result<PreparedUnshieldCall> {
    let prepared = prepare_desktop_unshield_plan_without_broadcaster_fee(
        DesktopUnshieldPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            spend_authorization: request.spend_authorization,
            token: request.token,
            amount: request.amount,
            fee_mode: request.fee_mode,
            recipient: request.recipient,
            unwrap: request.unwrap,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_unshield_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate manual unshield pending output pre-transaction POI",
    )
    .await?;

    Ok(prepared_unshield_call_from_plan(
        request.chain_id,
        request.token,
        request.amount,
        request.recipient,
        request.unwrap,
        prepared.max_spendable,
        &prepared.plan,
    ))
}

pub async fn prepare_desktop_send_calldata(
    request: DesktopSendCalldataRequest,
    http: &HttpContext,
) -> Result<PreparedSendCall> {
    let recipient = request.recipient.trim().to_string();
    let prepared = prepare_desktop_send_plan_without_broadcaster_fee(
        DesktopSendPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            spend_authorization: request.spend_authorization,
            token: request.token,
            amount: request.amount,
            recipient: &recipient,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;

    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_send_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate manual send pending output pre-transaction POI",
    )
    .await?;

    Ok(prepared_send_call_from_plan(
        request.chain_id,
        request.token,
        request.amount,
        recipient,
        prepared.max_spendable,
        &prepared.plan,
    ))
}

pub async fn estimate_desktop_unshield_public_broadcaster_cost(
    request: DesktopUnshieldPublicBroadcasterEstimateRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterCostEstimate> {
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

    let policy = request.fee_policy;
    let anchor_rate = public_broadcaster_anchor_rate_for_policy(
        request.anchor_cache.as_ref(),
        request.chain_id,
        request.fee_token,
    );
    let candidates = public_broadcaster_candidates(
        &request.fee_rows,
        request.chain_id,
        request.fee_token,
        if request.unwrap {
            Some(chain.relay_adapt_contract)
        } else {
            None
        },
        SystemTime::now(),
        policy,
        anchor_rate,
    );
    let broadcaster = select_public_broadcaster_with_policy_and_trust(
        &candidates,
        &request.selection,
        policy,
        &request.trust_filter,
    )?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls.clone(), http);
    let min_gas_price = buffered_gas_price_from_rpc_pool(&query_rpc_pool, &chain.gas).await?;
    let utxos = request.session.unspent_utxos().await;
    let same_token_fee = request.fee_token == request.token;
    let initial_fee_amount =
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

    approximate_public_broadcaster_cost(
        broadcaster,
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        min_gas_price,
        initial_fee_amount,
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
    )
}

pub async fn estimate_desktop_send_public_broadcaster_cost(
    request: DesktopSendPublicBroadcasterEstimateRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterCostEstimate> {
    if request.session.chain_id != request.chain_id {
        return Err(eyre!(
            "selected wallet session is for chain {}, not {}",
            request.session.chain_id,
            request.chain_id
        ));
    }
    parse_railgun_recipient(&request.recipient)?;

    let chain = effective_desktop_chain_config(request.chain_id, request.effective_chain.as_ref())?;
    let policy = request.fee_policy;
    let anchor_rate = public_broadcaster_anchor_rate_for_policy(
        request.anchor_cache.as_ref(),
        request.chain_id,
        request.fee_token,
    );
    let candidates = public_broadcaster_candidates(
        &request.fee_rows,
        request.chain_id,
        request.fee_token,
        None,
        SystemTime::now(),
        policy,
        anchor_rate,
    );
    let broadcaster = select_public_broadcaster_with_policy_and_trust(
        &candidates,
        &request.selection,
        policy,
        &request.trust_filter,
    )?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls.clone(), http);
    let min_gas_price = buffered_gas_price_from_rpc_pool(&query_rpc_pool, &chain.gas).await?;
    let utxos = request.session.unspent_utxos().await;
    let same_token_fee = request.fee_token == request.token;
    let initial_fee_amount =
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

    approximate_public_broadcaster_cost(
        broadcaster,
        request.token,
        request.fee_token,
        request.amount,
        request.fee_mode,
        U256::ZERO,
        min_gas_price,
        initial_fee_amount,
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
    )
}

pub async fn submit_desktop_unshield_public_broadcaster(
    request: DesktopUnshieldPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterSubmissionResult> {
    let waku = Arc::clone(&request.waku);
    let timeout = request.response_timeout;
    let republish_interval = request.republish_interval;
    let progress_tx = request.progress_tx.clone();
    let session = Arc::clone(&request.session);
    let prepared = prepare_desktop_unshield_public_broadcaster(request, http).await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    let result = submit_public_broadcaster_plan(
        waku,
        prepared.plan.call.to,
        prepared.plan.call.data,
        prepared.pre_transaction_pois_per_txid_leaf_per_list,
        prepared.broadcaster,
        prepared.action_token,
        prepared.fee_token,
        prepared.entered_amount,
        prepared.receiver_amount,
        prepared.recipient_amount,
        prepared.total_private_spend,
        prepared.fee_amount,
        prepared.protocol_fee_amount,
        prepared.protocol_fee_bps,
        prepared.fee_mode,
        prepared.gas_limit,
        prepared.min_gas_price,
        progress_tx,
        timeout,
        republish_interval,
    )
    .await?;
    mark_submitted_inputs_pending_spent(&session, &pending_spent_inputs, &result).await;
    Ok(result)
}

pub async fn submit_desktop_send_public_broadcaster(
    request: DesktopSendPublicBroadcasterRequest,
    http: &HttpContext,
) -> Result<PublicBroadcasterSubmissionResult> {
    let waku = Arc::clone(&request.waku);
    let timeout = request.response_timeout;
    let republish_interval = request.republish_interval;
    let progress_tx = request.progress_tx.clone();
    let session = Arc::clone(&request.session);
    let prepared = prepare_desktop_send_public_broadcaster(request, http).await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    let result = submit_public_broadcaster_plan(
        waku,
        prepared.plan.call.to,
        prepared.plan.call.data,
        prepared.pre_transaction_pois_per_txid_leaf_per_list,
        prepared.broadcaster,
        prepared.action_token,
        prepared.fee_token,
        prepared.entered_amount,
        prepared.receiver_amount,
        prepared.recipient_amount,
        prepared.total_private_spend,
        prepared.fee_amount,
        prepared.protocol_fee_amount,
        prepared.protocol_fee_bps,
        prepared.fee_mode,
        prepared.gas_limit,
        prepared.min_gas_price,
        progress_tx,
        timeout,
        republish_interval,
    )
    .await?;
    mark_submitted_inputs_pending_spent(&session, &pending_spent_inputs, &result).await;
    Ok(result)
}

pub async fn submit_desktop_unshield_self_broadcast(
    request: DesktopUnshieldSelfBroadcastRequest,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let prepared = prepare_desktop_unshield_plan_without_broadcaster_fee(
        DesktopUnshieldPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            spend_authorization: request.spend_authorization,
            token: request.token,
            amount: request.amount,
            fee_mode: request.fee_mode,
            recipient: request.recipient,
            unwrap: request.unwrap,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;
    let pending_output_pois_required =
        unshield_chunks_require_pending_output_pois(&prepared.plan.chunks);
    emit_self_broadcast_event(
        request.event_tx.as_ref(),
        SelfBroadcastSessionEvent::PendingOutputPoiProofsRequired {
            required: pending_output_pois_required,
        },
    );
    if pending_output_pois_required {
        update_transaction_generation_stage(
            request.progress_tx.as_ref(),
            TransactionGenerationStage::GeneratingPoiProofs,
        );
        persist_manual_unshield_pending_pois(
            &prepared.plan,
            request.session.as_ref(),
            request.chain_id,
            request.view_session.wallet_id(),
            &prepared.prover,
            request.verify_proof,
            http,
            "generate self-broadcast unshield pending output pre-transaction POI",
        )
        .await?;
    }
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    submit_self_broadcast_plan(
        request.chain_id,
        request.effective_chain.as_ref(),
        request.view_session.as_ref(),
        request.vault_store.as_ref(),
        request
            .vault_password
            .as_ref()
            .map(|password| password.as_str()),
        request.trezor_pin_matrix_provider,
        request.public_account_uuid,
        Arc::clone(&request.session),
        prepared.plan.call.to,
        prepared.plan.call.data,
        pending_spent_inputs,
        request.gas_fee,
        request.progress_tx,
        request.command_rx,
        request.event_tx,
        http,
    )
    .await
}

pub async fn submit_blocked_shield_rescue_self_broadcast(
    request: BlockedShieldRescueSelfBroadcastRequest,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let prepared = prepare_blocked_shield_rescue_plan(&request, http).await?;
    let pending_output_pois_required =
        unshield_chunks_require_pending_output_pois(&prepared.plan.chunks);
    emit_self_broadcast_event(
        request.event_tx.as_ref(),
        SelfBroadcastSessionEvent::PendingOutputPoiProofsRequired {
            required: pending_output_pois_required,
        },
    );
    if pending_output_pois_required {
        return Err(eyre!(
            "blocked Shield refund plan unexpectedly requires private output POI proofs"
        ));
    }
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    submit_self_broadcast_plan(
        request.chain_id,
        request.effective_chain.as_ref(),
        request.view_session.as_ref(),
        request.vault_store.as_ref(),
        Some(request.vault_password.as_str()),
        request.trezor_pin_matrix_provider,
        prepared.public_account_uuid,
        Arc::clone(&request.session),
        prepared.plan.call.to,
        prepared.plan.call.data,
        pending_spent_inputs,
        request.gas_fee,
        request.progress_tx,
        request.command_rx,
        request.event_tx,
        http,
    )
    .await
}

pub async fn submit_desktop_send_self_broadcast(
    request: DesktopSendSelfBroadcastRequest,
    http: &HttpContext,
) -> Result<DesktopSelfBroadcastResult> {
    let recipient = request.recipient.trim().to_string();
    let prepared = prepare_desktop_send_plan_without_broadcaster_fee(
        DesktopSendPlanRequest {
            chain_id: request.chain_id,
            effective_chain: request.effective_chain.as_ref(),
            view_session: request.view_session.as_ref(),
            session: request.session.as_ref(),
            vault_store: request.vault_store.as_ref(),
            spend_authorization: request.spend_authorization,
            token: request.token,
            amount: request.amount,
            recipient: &recipient,
            verify_proof: request.verify_proof,
            progress_tx: request.progress_tx.as_ref(),
        },
        http,
    )
    .await?;
    update_transaction_generation_stage(
        request.progress_tx.as_ref(),
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    persist_manual_send_pending_pois(
        &prepared.plan,
        request.session.as_ref(),
        request.chain_id,
        request.view_session.wallet_id(),
        &prepared.prover,
        request.verify_proof,
        http,
        "generate self-broadcast send pending output pre-transaction POI",
    )
    .await?;
    let pending_spent_inputs = prepared
        .plan
        .inputs
        .iter()
        .map(|input| input.utxo.clone())
        .collect::<Vec<_>>();
    submit_self_broadcast_plan(
        request.chain_id,
        request.effective_chain.as_ref(),
        request.view_session.as_ref(),
        request.vault_store.as_ref(),
        request
            .vault_password
            .as_ref()
            .map(|password| password.as_str()),
        request.trezor_pin_matrix_provider,
        request.public_account_uuid,
        Arc::clone(&request.session),
        prepared.plan.call.to,
        prepared.plan.call.data,
        pending_spent_inputs,
        request.gas_fee,
        request.progress_tx,
        request.command_rx,
        request.event_tx,
        http,
    )
    .await
}
