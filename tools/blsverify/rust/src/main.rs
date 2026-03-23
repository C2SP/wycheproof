use std::env;
use std::fs;
use std::path::Path;
use std::process;

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SigVerifyFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<SigVerifyGroup>,
}

#[derive(Deserialize)]
struct SigVerifyGroup {
    ciphersuite: String,
    #[serde(rename = "publicKey")]
    public_key: PkInfo,
    tests: Vec<SigVerifyTest>,
}

#[derive(Deserialize)]
struct PkInfo {
    pk: String,
}

#[derive(Deserialize)]
struct SigVerifyTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    msg: String,
    sig: String,
    result: String,
}

#[derive(Deserialize)]
struct AggVerifyFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<AggVerifyGroup>,
}

#[derive(Deserialize)]
struct AggVerifyGroup {
    ciphersuite: String,
    tests: Vec<AggVerifyTest>,
}

#[derive(Deserialize)]
struct AggVerifyTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    pubkeys: Vec<String>,
    messages: Vec<String>,
    sig: String,
    result: String,
}

#[derive(Deserialize)]
struct HashToG2File {
    #[serde(rename = "testGroups")]
    test_groups: Vec<HashToG2Group>,
}

#[derive(Deserialize)]
struct HashToG2Group {
    dst: String,
    tests: Vec<HashToG2Test>,
}

#[derive(Deserialize)]
struct HashToG2Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    msg: String,
    expected: String,
    result: String,
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

struct Stats {
    pass: u32,
    fail: u32,
    skip: u32,
}

impl Stats {
    fn new() -> Self {
        Stats {
            pass: 0,
            fail: 0,
            skip: 0,
        }
    }

    fn merge(&mut self, other: &Stats) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
    }
}

// ---------------------------------------------------------------------------
// DST mapping
// ---------------------------------------------------------------------------

fn ciphersuite_to_dst(cs: &str) -> &[u8] {
    match cs {
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_" => {
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
        }
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" => {
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
        }
        other => {
            eprintln!("WARNING: unknown ciphersuite: {other}");
            other.as_bytes()
        }
    }
}

/// Returns true when the identity (point-at-infinity) is encoded in
/// compressed G1 (48 bytes) or G2 (96 bytes) format.
fn is_identity(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // Compressed infinity flag: top byte is 0xc0, rest zeros.
    if bytes[0] != 0xc0 {
        return false;
    }
    bytes[1..].iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------------------
// Single signature verification
// ---------------------------------------------------------------------------

fn run_sig_verify(path: &Path, label: &str) -> Stats {
    let mut stats = Stats::new();

    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read {}: {e}", path.display());
        process::exit(1);
    });
    let file: SigVerifyFile = serde_json::from_str(&data)
        .unwrap_or_else(|e| {
            eprintln!(
                "ERROR: cannot parse {}: {e}",
                path.display()
            );
            process::exit(1);
        });

    for group in &file.test_groups {
        let dst = ciphersuite_to_dst(&group.ciphersuite);
        let pk_bytes = match hex::decode(&group.public_key.pk) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "[{label}] bad hex for group PK: {e}"
                );
                continue;
            }
        };

        // Reject identity public key up front.
        let pk_is_identity = is_identity(&pk_bytes);

        let pk = if pk_is_identity {
            None
        } else {
            PublicKey::from_bytes(&pk_bytes).ok()
        };

        for tc in &group.tests {
            let expected_valid = tc.result == "valid";
            let acceptable = tc.result == "acceptable";

            let sig_bytes = match hex::decode(&tc.sig) {
                Ok(b) => b,
                Err(_) => {
                    // Malformed hex => must be invalid.
                    check(
                        &mut stats,
                        label,
                        tc.tc_id,
                        &tc.comment,
                        false,
                        expected_valid,
                        acceptable,
                    );
                    continue;
                }
            };
            let msg = hex::decode(&tc.msg).unwrap_or_default();

            // Identity sig must be rejected.
            if is_identity(&sig_bytes) || pk_is_identity {
                check(
                    &mut stats,
                    label,
                    tc.tc_id,
                    &tc.comment,
                    false,
                    expected_valid,
                    acceptable,
                );
                continue;
            }

            let pk_ref = match &pk {
                Some(p) => p,
                None => {
                    check(
                        &mut stats,
                        label,
                        tc.tc_id,
                        &tc.comment,
                        false,
                        expected_valid,
                        acceptable,
                    );
                    continue;
                }
            };

            let sig = match Signature::from_bytes(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    check(
                        &mut stats,
                        label,
                        tc.tc_id,
                        &tc.comment,
                        false,
                        expected_valid,
                        acceptable,
                    );
                    continue;
                }
            };

            let err = sig.verify(
                true,  // sig_groupcheck
                &msg,
                dst,
                &[],   // aug
                pk_ref,
                true,  // pk_validate
            );
            let verified = err == BLST_ERROR::BLST_SUCCESS;

            check(
                &mut stats,
                label,
                tc.tc_id,
                &tc.comment,
                verified,
                expected_valid,
                acceptable,
            );
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// Aggregate verification
// ---------------------------------------------------------------------------

fn run_agg_verify(path: &Path, label: &str) -> Stats {
    let mut stats = Stats::new();

    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read {}: {e}", path.display());
        process::exit(1);
    });
    let file: AggVerifyFile = serde_json::from_str(&data)
        .unwrap_or_else(|e| {
            eprintln!(
                "ERROR: cannot parse {}: {e}",
                path.display()
            );
            process::exit(1);
        });

    for group in &file.test_groups {
        let dst = ciphersuite_to_dst(&group.ciphersuite);

        for tc in &group.tests {
            let expected_valid = tc.result == "valid";
            let acceptable = tc.result == "acceptable";

            // n=0 signers => invalid per spec.
            if tc.pubkeys.is_empty() || tc.messages.is_empty() {
                check(
                    &mut stats,
                    label,
                    tc.tc_id,
                    &tc.comment,
                    false,
                    expected_valid,
                    acceptable,
                );
                continue;
            }

            // Mismatched counts => invalid.
            if tc.pubkeys.len() != tc.messages.len() {
                check(
                    &mut stats,
                    label,
                    tc.tc_id,
                    &tc.comment,
                    false,
                    expected_valid,
                    acceptable,
                );
                continue;
            }

            // Decode sig.
            let sig_bytes = match hex::decode(&tc.sig) {
                Ok(b) => b,
                Err(_) => {
                    check(
                        &mut stats,
                        label,
                        tc.tc_id,
                        &tc.comment,
                        false,
                        expected_valid,
                        acceptable,
                    );
                    continue;
                }
            };

            if is_identity(&sig_bytes) {
                check(
                    &mut stats,
                    label,
                    tc.tc_id,
                    &tc.comment,
                    false,
                    expected_valid,
                    acceptable,
                );
                continue;
            }

            let sig = match Signature::from_bytes(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    check(
                        &mut stats,
                        label,
                        tc.tc_id,
                        &tc.comment,
                        false,
                        expected_valid,
                        acceptable,
                    );
                    continue;
                }
            };

            // Decode all public keys.
            let mut pks: Vec<PublicKey> = Vec::new();
            let mut bad_pk = false;
            for pk_hex in &tc.pubkeys {
                let pk_bytes = match hex::decode(pk_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        bad_pk = true;
                        break;
                    }
                };
                if is_identity(&pk_bytes) {
                    bad_pk = true;
                    break;
                }
                match PublicKey::from_bytes(&pk_bytes) {
                    Ok(p) => pks.push(p),
                    Err(_) => {
                        bad_pk = true;
                        break;
                    }
                }
            }
            if bad_pk {
                check(
                    &mut stats,
                    label,
                    tc.tc_id,
                    &tc.comment,
                    false,
                    expected_valid,
                    acceptable,
                );
                continue;
            }

            // Decode all messages.
            let msgs: Vec<Vec<u8>> = tc
                .messages
                .iter()
                .map(|m| hex::decode(m).unwrap_or_default())
                .collect();
            let msg_refs: Vec<&[u8]> =
                msgs.iter().map(|m| m.as_slice()).collect();
            let pk_refs: Vec<&PublicKey> =
                pks.iter().collect();

            let err = sig.aggregate_verify(
                true,          // sig_groupcheck
                &msg_refs,
                dst,
                &pk_refs,
                true,          // pks_validate
            );
            let verified = err == BLST_ERROR::BLST_SUCCESS;

            check(
                &mut stats,
                label,
                tc.tc_id,
                &tc.comment,
                verified,
                expected_valid,
                acceptable,
            );
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// Hash-to-G2
// ---------------------------------------------------------------------------

fn run_hash_to_g2(path: &Path, label: &str) -> Stats {
    let mut stats = Stats::new();

    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read {}: {e}", path.display());
        process::exit(1);
    });
    let file: HashToG2File = serde_json::from_str(&data)
        .unwrap_or_else(|e| {
            eprintln!(
                "ERROR: cannot parse {}: {e}",
                path.display()
            );
            process::exit(1);
        });

    for group in &file.test_groups {
        let dst = group.dst.as_bytes();

        for tc in &group.tests {
            let expected_valid = tc.result == "valid";
            let acceptable = tc.result == "acceptable";

            let msg = hex::decode(&tc.msg).unwrap_or_default();
            let expected =
                match hex::decode(&tc.expected) {
                    Ok(b) => b,
                    Err(_) => {
                        check(
                            &mut stats,
                            label,
                            tc.tc_id,
                            &tc.comment,
                            false,
                            expected_valid,
                            acceptable,
                        );
                        continue;
                    }
                };

            // Use the low-level blst_hash_to_g2 via unsafe FFI,
            // then compress the result and compare.
            let mut out = blst::blst_p2::default();
            unsafe {
                blst::blst_hash_to_g2(
                    &mut out,
                    msg.as_ptr(),
                    msg.len(),
                    dst.as_ptr(),
                    dst.len(),
                    std::ptr::null(),
                    0,
                );
            }

            // Compress the resulting G2 point (96 bytes).
            let mut compressed = [0u8; 96];
            unsafe {
                blst::blst_p2_compress(
                    compressed.as_mut_ptr(),
                    &out,
                );
            }

            let matched = compressed[..] == expected[..];

            check(
                &mut stats,
                label,
                tc.tc_id,
                &tc.comment,
                matched,
                expected_valid,
                acceptable,
            );
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// Result checking helper
// ---------------------------------------------------------------------------

fn check(
    stats: &mut Stats,
    label: &str,
    tc_id: u32,
    comment: &str,
    got_valid: bool,
    expected_valid: bool,
    acceptable: bool,
) {
    if acceptable {
        // Either outcome is fine for "acceptable" vectors.
        stats.skip += 1;
        return;
    }
    if got_valid == expected_valid {
        stats.pass += 1;
    } else {
        stats.fail += 1;
        eprintln!(
            "FAIL [{label}] tc {tc_id} ({comment}): \
             expected={expected_valid} got={got_valid}"
        );
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <vectors-dir>", args[0]);
        process::exit(2);
    }
    let dir = Path::new(&args[1]);

    let mut total = Stats::new();

    // Single-signature verification: basic scheme.
    let basic = dir.join("bls_sig_g2_basic_verify_test.json");
    let s = run_sig_verify(&basic, "basic");
    print_file_summary("basic", &s);
    total.merge(&s);

    // Single-signature verification: POP scheme.
    let pop = dir.join("bls_sig_g2_pop_verify_test.json");
    let s = run_sig_verify(&pop, "pop");
    print_file_summary("pop", &s);
    total.merge(&s);

    // Aggregate verification.
    let agg = dir.join("bls_sig_g2_aggregate_verify_test.json");
    let s = run_agg_verify(&agg, "aggregate");
    print_file_summary("aggregate", &s);
    total.merge(&s);

    // Hash-to-G2.
    let h2g2 = dir.join("bls_hash_to_g2_test.json");
    let s = run_hash_to_g2(&h2g2, "hash_to_g2");
    print_file_summary("hash_to_g2", &s);
    total.merge(&s);

    // Summary.
    println!("---");
    println!(
        "TOTAL: {} pass, {} fail, {} acceptable (skipped)",
        total.pass, total.fail, total.skip
    );

    if total.fail > 0 {
        println!("RESULT: FAIL");
        process::exit(1);
    }
    println!("RESULT: PASS");
}

fn print_file_summary(label: &str, s: &Stats) {
    println!(
        "[{label}] {pass} pass, {fail} fail, \
         {skip} acceptable (skipped)",
        pass = s.pass,
        fail = s.fail,
        skip = s.skip,
    );
}
