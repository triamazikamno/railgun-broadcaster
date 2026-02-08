use serde::Deserialize;
use thiserror::Error;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key};

use crate::transact::pad_with_merkle_zero;
use crate::transact::{PreTxPoi, SnarkJsProof};
use alloy::primitives::U256;

#[derive(Debug, Error)]
pub enum SnarkProofError {
    #[error("invalid POI circuit variant: {variant}")]
    InvalidVariant { variant: String },
    #[error("fetch vkey failed: {0}")]
    FetchVkey(#[from] reqwest::Error),
    #[error("parse vkey failed: {0}")]
    ParseVkey(#[from] serde_json::Error),
    #[error("G1 needs at least [x,y], got len={len}")]
    InvalidG1Len { len: usize },
    #[error("G1 point not on curve")]
    G1NotOnCurve,
    #[error("G1 point not in subgroup")]
    G1InvalidSubgroup,
    #[error("Fq2 needs [c1,c0], got len={len}")]
    InvalidFq2Len { len: usize },
    #[error("G2 needs at least [[x..],[y..]]")]
    InvalidG2Shape,
    #[error("G2 point invalid: {reason}")]
    InvalidG2 { reason: String },
    #[error("unsupported protocol: {protocol}")]
    UnsupportedProtocol { protocol: String },
    #[error("pi_a invalid")]
    InvalidProofA,
    #[error("pi_c invalid")]
    InvalidProofC,
    #[error("public_inputs len mismatch: got {got}, expected {expected} (vk.ic len={vk_len})")]
    PublicInputsMismatch {
        got: usize,
        expected: usize,
        vk_len: usize,
    },
    #[error("groth16 verify failed")]
    VerifyFailed,
}

#[derive(Debug, Clone, Deserialize)]
struct VKeyJson {
    pub protocol: String,
    pub vk_alpha_1: Vec<U256>,
    pub vk_beta_2: Vec<Vec<U256>>,
    pub vk_gamma_2: Vec<Vec<U256>>,
    pub vk_delta_2: Vec<Vec<U256>>,

    #[serde(rename = "IC")]
    pub ic: Vec<Vec<U256>>,
}

impl VKeyJson {
    fn try_into_ark(&self) -> Result<VerifyingKey<Bn254>, SnarkProofError> {
        if self.protocol.to_lowercase() != "groth16" {
            return Err(SnarkProofError::UnsupportedProtocol {
                protocol: self.protocol.clone(),
            });
        }

        let alpha_g1 = g1_from_xyz(&self.vk_alpha_1)?;
        let beta_g2 = g2_from_snarkjs_xy(&self.vk_beta_2)?;
        let gamma_g2 = g2_from_snarkjs_xy(&self.vk_gamma_2)?;
        let delta_g2 = g2_from_snarkjs_xy(&self.vk_delta_2)?;

        let mut gamma_abc_g1 = Vec::with_capacity(self.ic.len());
        for icp in &self.ic {
            gamma_abc_g1.push(g1_from_xyz(icp)?);
        }

        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
}

const IPFS_GATEWAY: &str = "https://ipfs-lb.com";
const IPFS_HASH_ARTIFACTS_POI: &str = "QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr";

async fn fetch_poi_vkey_json(
    max_inputs: usize,
    max_outputs: usize,
) -> Result<VKeyJson, SnarkProofError> {
    let variant = format!("POI_{max_inputs}x{max_outputs}");
    if !(variant == "POI_3x3" || variant == "POI_13x13") {
        return Err(SnarkProofError::InvalidVariant { variant });
    }

    let url = format!("{IPFS_GATEWAY}/ipfs/{IPFS_HASH_ARTIFACTS_POI}/{variant}/vkey.json",);

    let response = reqwest::get(&url).await?;
    let body = response.bytes().await?;
    let vkey = serde_json::from_slice(&body)?;

    Ok(vkey)
}

fn fq_from_dec(u: U256) -> Fq {
    let b: [u8; 32] = u.to_be_bytes();
    Fq::from_be_bytes_mod_order(&b)
}

fn fr_from_dec(u: U256) -> Fr {
    let b: [u8; 32] = u.to_be_bytes();
    Fr::from_be_bytes_mod_order(&b)
}
fn g1_from_xyz(v: &[U256]) -> Result<G1Affine, SnarkProofError> {
    if v.len() < 2 {
        return Err(SnarkProofError::InvalidG1Len { len: v.len() });
    }
    let x = fq_from_dec(v[0]);
    let y = fq_from_dec(v[1]);
    let p = G1Affine::new_unchecked(x, y);

    if !p.is_on_curve() {
        return Err(SnarkProofError::G1NotOnCurve);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SnarkProofError::G1InvalidSubgroup);
    }
    Ok(p)
}

fn fq2_from_pair_c1c0(pair: &[U256]) -> Result<Fq2, SnarkProofError> {
    if pair.len() < 2 {
        return Err(SnarkProofError::InvalidFq2Len { len: pair.len() });
    }
    let c0 = fq_from_dec(pair[1]);
    let c1 = fq_from_dec(pair[0]);
    Ok(Fq2::new(c0, c1))
}

fn fq2_from_pair_c0c1(pair: &[U256]) -> Result<Fq2, SnarkProofError> {
    if pair.len() < 2 {
        return Err(SnarkProofError::InvalidFq2Len { len: pair.len() });
    }
    let c0 = fq_from_dec(pair[0]);
    let c1 = fq_from_dec(pair[1]);
    Ok(Fq2::new(c0, c1))
}
fn g2_from_snarkjs_pi_b(pi_b: &[[U256; 2]; 2]) -> Result<G2Affine, SnarkProofError> {
    let candidates: [([U256; 2], [U256; 2]); 4] = [
        (pi_b[0], pi_b[1]),
        (pi_b[1], pi_b[0]),
        ([pi_b[0][1], pi_b[0][0]], [pi_b[1][1], pi_b[1][0]]),
        ([pi_b[1][1], pi_b[1][0]], [pi_b[0][1], pi_b[0][0]]),
    ];

    let mut last = None;

    for (xpair, ypair) in candidates {
        let v = vec![xpair.to_vec(), ypair.to_vec()];
        match g2_from_snarkjs_xy(&v) {
            Ok(p) => return Ok(p),
            Err(e) => last = Some(e),
        }
    }

    Err(SnarkProofError::InvalidG2 {
        reason: format!("pi_b invalid: no layout matched: {last:?}"),
    })
}

/// Try common snarkjs/solidity encodings until one yields a valid G2 point.
fn g2_from_snarkjs_xy(v: &[Vec<U256>]) -> Result<G2Affine, SnarkProofError> {
    if v.len() < 2 {
        return Err(SnarkProofError::InvalidG2Shape);
    }

    let candidates = [
        (
            fq2_from_pair_c1c0 as fn(&[U256]) -> Result<Fq2, SnarkProofError>,
            fq2_from_pair_c1c0 as fn(&[U256]) -> Result<Fq2, SnarkProofError>,
        ),
        (
            fq2_from_pair_c0c1 as fn(&[U256]) -> Result<Fq2, SnarkProofError>,
            fq2_from_pair_c0c1 as fn(&[U256]) -> Result<Fq2, SnarkProofError>,
        ),
    ];

    let mut last_err: Option<String> = None;

    for (fx, fy) in candidates {
        let x = fx(&v[0])?;
        let y = fy(&v[1])?;
        let p = G2Affine::new_unchecked(x, y);

        if !p.is_on_curve() {
            last_err = Some("not on curve".into());
            continue;
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            last_err = Some("not in subgroup".into());
            continue;
        }
        return Ok(p);
    }

    Err(SnarkProofError::InvalidG2 {
        reason: last_err.unwrap_or_else(|| "unknown".into()),
    })
}

impl SnarkJsProof {
    fn try_into_ark(&self) -> Result<Proof<Bn254>, SnarkProofError> {
        let a = {
            let x = fq_from_dec(self.pi_a[0]);
            let y = fq_from_dec(self.pi_a[1]);
            let pa = G1Affine::new_unchecked(x, y);
            if !pa.is_on_curve() || !pa.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SnarkProofError::InvalidProofA);
            }
            pa
        };

        let b = g2_from_snarkjs_pi_b(&self.pi_b)?;

        let c = {
            let x = fq_from_dec(self.pi_c[0]);
            let y = fq_from_dec(self.pi_c[1]);
            let pc = G1Affine::new_unchecked(x, y);
            if !pc.is_on_curve() || !pc.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SnarkProofError::InvalidProofC);
            }
            pc
        };

        Ok(Proof { a, b, c })
    }
}

fn pad_hex32_zero(mut v: Vec<U256>, target: usize) -> Vec<U256> {
    while v.len() < target {
        v.push(U256::ZERO);
    }
    v.truncate(target);
    v
}

fn build_poi_public_signals(
    max_inputs: usize,
    max_outputs: usize,
    txid_merkleroot: U256,
    railgun_txid_if_has_unshield: U256,
    blinded_commitments_out: &[U256],
    poi_merkleroots: &[U256],
) -> Vec<Fr> {
    let bco = pad_hex32_zero(blinded_commitments_out.to_vec(), max_outputs);
    let pmr = pad_with_merkle_zero(poi_merkleroots.to_vec(), max_inputs);

    let mut out = Vec::with_capacity(max_outputs + 1 + 1 + max_inputs);

    for x in bco {
        out.push(fr_from_dec(x));
    }
    out.push(fr_from_dec(txid_merkleroot));
    out.push(fr_from_dec(railgun_txid_if_has_unshield));
    for x in pmr {
        out.push(fr_from_dec(x));
    }

    out
}

pub struct Prover {
    pvk_3_3: PreparedVerifyingKey<Bn254>,
    pvk_13_13: PreparedVerifyingKey<Bn254>,
}

impl Prover {
    pub async fn new() -> Result<Self, SnarkProofError> {
        Ok(Self {
            pvk_3_3: Self::make_pvk(3, 3).await?,
            pvk_13_13: Self::make_pvk(13, 13).await?,
        })
    }
    async fn make_pvk(
        max_inputs: usize,
        max_outputs: usize,
    ) -> Result<PreparedVerifyingKey<Bn254>, SnarkProofError> {
        let vkey_json = fetch_poi_vkey_json(max_inputs, max_outputs).await?;
        vkey_json
            .try_into_ark()
            .map(|vk| prepare_verifying_key(&vk))
    }

    const fn pvk(&self, max_inputs: usize, max_outputs: usize) -> &PreparedVerifyingKey<Bn254> {
        if max_inputs <= 3 && max_outputs <= 3 {
            &self.pvk_3_3
        } else {
            &self.pvk_13_13
        }
    }

    pub fn verify(
        &self,
        tx_nullifiers_len: usize,
        tx_commitments_out_len: usize,
        proof_data: &PreTxPoi,
    ) -> Result<bool, SnarkProofError> {
        let (max_inputs, max_outputs) = if tx_nullifiers_len <= 3 && tx_commitments_out_len <= 3 {
            (3usize, 3usize)
        } else {
            (13usize, 13usize)
        };

        let pvk = self.pvk(max_inputs, max_outputs);

        let proof = proof_data.snark_proof.try_into_ark()?;

        let public_inputs = build_poi_public_signals(
            max_inputs,
            max_outputs,
            U256::from_be_bytes(proof_data.txid_merkleroot.0),
            U256::from_be_slice(proof_data.railgun_txid_if_has_unshield.iter().as_slice()),
            &proof_data
                .blinded_commitments_out
                .iter()
                .map(|v| U256::from_be_bytes(v.0))
                .collect::<Vec<_>>(),
            &proof_data
                .poi_merkleroots
                .iter()
                .map(|v| U256::from_be_bytes(v.0))
                .collect::<Vec<_>>(),
        );
        let expected = pvk.vk.gamma_abc_g1.len().saturating_sub(1);
        if public_inputs.len() != expected {
            return Err(SnarkProofError::PublicInputsMismatch {
                got: public_inputs.len(),
                expected,
                vk_len: pvk.vk.gamma_abc_g1.len(),
            });
        }
        let ok = Groth16::<Bn254>::verify_proof(pvk, &proof, &public_inputs)
            .map_err(|_| SnarkProofError::VerifyFailed)?;

        Ok(ok)
    }
}
