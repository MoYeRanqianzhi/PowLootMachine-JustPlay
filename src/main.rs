//! PowLoot Machine — 本地多赛道 PoW 计算引擎
//!
//! 通过 WebSocket 接收浏览器端的挖矿任务，利用原生多线程加速 PoW 计算。
//! 5 个简单赛道使用原生 Rust SHA256（SHA-NI 硬件加速），
//! VM_CHAIN 和 ARGON2D_CHAIN 使用 wasmtime 调用原始 WASM 二进制。

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use wasmtime::{Engine, Instance, Memory, Module, Store, TypedFunc};

const CODE_FILE: &str = "powloot_codes.txt";
const DEFAULT_PORT: u16 = 19527;

// ============================================================
// WS 协议 — 浏览器 → Rust
// ============================================================

/// round_id 可能是字符串或整数，统一反序列化为 String
fn deserialize_to_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        other => Ok(other.to_string()),
    }
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum ClientMsg {
    #[serde(rename = "mine")]
    Mine {
        #[serde(deserialize_with = "deserialize_to_string")]
        round_id: String,
        track: String,
        params: serde_json::Value,
    },
    #[serde(rename = "stop")]
    Stop,
    #[serde(rename = "save_code")]
    SaveCode { code: String },
}

// ============================================================
// WS 协议 — Rust → 浏览器
// ============================================================

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMsg {
    #[serde(rename = "ready")]
    Ready { threads: u32 },
    #[serde(rename = "status")]
    Status {
        #[serde(rename = "hashRate")]
        hash_rate: f64,
        attempts: u64,
    },
    #[serde(rename = "solution")]
    Solution { nonce: String, round_id: String },
    #[serde(rename = "stopped")]
    Stopped,
}

// ============================================================
// 赛道参数定义
// ============================================================

#[derive(Clone, Debug)]
enum TrackParams {
    CpuHash {
        challenge: String,
        bits: u32,
    },
    Chain {
        challenge: String,
        seed_bytes: Vec<u8>, // hex-decoded
        steps: u32,
        bits: u32,
    },
    BranchyMix {
        challenge: String,
        seed: String, // UTF-8
        rounds: u32,
        bits: u32,
    },
    MemWork {
        challenge: String,
        seed_bytes: Vec<u8>, // hex-decoded
        steps: u32,
        lanes: u32,
        lane_size: u32,
        bits: u32,
    },
    TinyVm {
        challenge: String,
        seed: String, // UTF-8
        program: Vec<u8>, // hex-decoded
        steps: u32,
        bits: u32,
    },
    VmChain {
        challenge: String,
        seed: String,
        program_hex: String,
        steps: u32,
        mem_words: u32,
        chain_update_every: u32,
        sample_words: u32,
        bits: u32,
    },
    Argon2dChain {
        challenge: String,
        seed: String,
        mem_blocks: u32,
        passes: u32,
        lanes: u32,
        bits: u32,
    },
}

fn parse_track_params(track: &str, params: &serde_json::Value) -> Result<TrackParams> {
    let get_str = |key: &str| -> Result<String> {
        params
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("missing param: {}", key))
    };
    let get_u32 = |key: &str| -> Result<u32> {
        params
            .get(key)
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or_else(|| anyhow::anyhow!("missing param: {}", key))
    };

    match track {
        "CPU_HASH" => Ok(TrackParams::CpuHash {
            challenge: get_str("challenge")?,
            bits: get_u32("bits")?,
        }),
        "CHAIN" => Ok(TrackParams::Chain {
            challenge: get_str("challenge")?,
            seed_bytes: hex::decode(get_str("seed")?)?,
            steps: get_u32("steps")?,
            bits: get_u32("bits")?,
        }),
        "BRANCHY_MIX" => Ok(TrackParams::BranchyMix {
            challenge: get_str("challenge")?,
            seed: get_str("seed")?,
            rounds: get_u32("rounds")?,
            bits: get_u32("bits")?,
        }),
        "MEM_WORK" => Ok(TrackParams::MemWork {
            challenge: get_str("challenge")?,
            seed_bytes: hex::decode(get_str("seed")?)?,
            steps: get_u32("steps")?,
            lanes: get_u32("lanes")?,
            lane_size: get_u32("laneSize")?,
            bits: get_u32("bits")?,
        }),
        "TINY_VM" => Ok(TrackParams::TinyVm {
            challenge: get_str("challenge")?,
            seed: get_str("seed")?,
            program: hex::decode(get_str("program_hex")?)?,
            steps: get_u32("steps")?,
            bits: get_u32("bits")?,
        }),
        "VM_CHAIN" => Ok(TrackParams::VmChain {
            challenge: get_str("challenge")?,
            seed: get_str("seed")?,
            program_hex: get_str("program_hex")?,
            steps: get_u32("steps")?,
            mem_words: get_u32("memWords")?,
            chain_update_every: get_u32("chainUpdateEvery")?,
            sample_words: get_u32("sampleWords")?,
            bits: get_u32("bits")?,
        }),
        "ARGON2D_CHAIN" => Ok(TrackParams::Argon2dChain {
            challenge: get_str("challenge")?,
            seed: get_str("seed")?,
            mem_blocks: get_u32("memBlocks")?,
            passes: get_u32("passes")?,
            lanes: get_u32("lanes")?,
            bits: get_u32("bits")?,
        }),
        _ => Err(anyhow::anyhow!("unknown track: {}", track)),
    }
}

// ============================================================
// 工具函数
// ============================================================

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

#[inline(always)]
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0u32;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            return bits;
        }
    }
    bits
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256_multi(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

// ============================================================
// 原生赛道实现 — CPU_HASH
// ============================================================

fn verify_cpu_hash(challenge: &[u8], nonce: &[u8], bits: u32) -> bool {
    let hash = sha256_multi(&[challenge, nonce]);
    leading_zero_bits(&hash) >= bits
}

// ============================================================
// 原生赛道实现 — CHAIN
// ============================================================

fn verify_chain(challenge: &[u8], seed_bytes: &[u8], nonce: &[u8], steps: u32, bits: u32) -> bool {
    // JS: buf = concat(ch, seed, nonce); for(0..steps) buf = sha256(buf);
    // 共做 steps 次 SHA256，不是 steps+1 次
    if steps == 0 {
        let concat: Vec<u8> = [challenge, seed_bytes, nonce].concat();
        return leading_zero_bits(&concat) >= bits;
    }
    let mut buf = sha256_multi(&[challenge, seed_bytes, nonce]); // 第 1 次
    for _ in 1..steps {
        buf = sha256(&buf); // 第 2..steps 次
    }
    leading_zero_bits(&buf) >= bits
}

// ============================================================
// 原生赛道实现 — BRANCHY_MIX
// ============================================================

#[inline(always)]
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

fn verify_branchy_mix(challenge: &str, seed: &str, nonce: &str, rounds: u32, bits: u32) -> bool {
    let init_str = format!("{}{}{}", challenge, seed, nonce);
    let d = sha256(init_str.as_bytes());

    let mut a = u32::from_le_bytes(d[0..4].try_into().unwrap());
    let mut b = u32::from_le_bytes(d[4..8].try_into().unwrap());
    let mut c = u32::from_le_bytes(d[8..12].try_into().unwrap());
    let mut dd = u32::from_le_bytes(d[12..16].try_into().unwrap());
    let mut t0 = u32::from_le_bytes(d[16..20].try_into().unwrap());
    let mut t1 = u32::from_le_bytes(d[20..24].try_into().unwrap());
    let mut t2 = u32::from_le_bytes(d[24..28].try_into().unwrap());
    let mut t3 = u32::from_le_bytes(d[28..32].try_into().unwrap());

    let mut table = [0u32; 16];
    for i in 0u32..16 {
        t0 ^= t0 << 13;
        t0 ^= t0 >> 17;
        t0 ^= t0 << 5;
        t1 = t1.wrapping_add(0x9e3779b9u32.wrapping_add(t0 ^ i));
        t2 = rotl32(t2 ^ t1, (i % 31) + 1);
        t3 ^= t2.wrapping_add(0x7f4a7c15);
        table[i as usize] = t0 ^ t1 ^ t2 ^ t3;
    }

    for i in 0..rounds {
        let s = a ^ rotl32(b, 7) ^ c.wrapping_mul(0x9e3779b9u32) ^ i;
        let sel = s & 3;

        match sel {
            0 => {
                a = a.wrapping_add(rotl32(dd, 11));
                b ^= rotl32(a, 3);
                c = c.wrapping_add(b ^ 0x85ebca6b);
                dd ^= rotl32(c, 17);
            }
            1 => {
                a = (a ^ 0x27d4eb2d).wrapping_mul(b | 1).wrapping_add(c);
                b = (b ^ 0x165667b1).wrapping_mul(c | 1).wrapping_add(dd);
                c = (c ^ 0xd3a2646c).wrapping_mul(dd | 1).wrapping_add(a);
                dd = (dd ^ 0xfd7046c5).wrapping_mul(a | 1).wrapping_add(b);
            }
            2 => {
                let idx = (rotl32(s, 5) ^ (b >> 3)) & 15;
                let v = table[idx as usize];
                a ^= v;
                b = b.wrapping_add(rotl32(v, (a & 15) + 1));
                c ^= v.wrapping_add(i);
                dd = dd.wrapping_add(a ^ c);
            }
            _ => {
                let idx = (s ^ rotl32(a, 9)) & 15;
                let v = table[idx as usize] ^ rotl32(table[((idx + 7) & 15) as usize], 13);
                a = rotl32(a ^ v, 9).wrapping_add(b);
                b = rotl32(b.wrapping_add(v), 5) ^ c;
                c = rotl32(c ^ a.wrapping_add(i), 3).wrapping_add(dd);
                dd = rotl32(dd.wrapping_add(b ^ i), 7) ^ a;
            }
        }

        let tmp = a;
        a = a.wrapping_add(c);
        c ^= b;
        b = b.wrapping_add(dd);
        dd ^= tmp;
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&dd.to_le_bytes());

    let digest = sha256(&out);
    leading_zero_bits(&digest) >= bits
}

// ============================================================
// 原生赛道实现 — MEM_WORK
// ============================================================

/// 从 seed 构建 MEM_WORK 的基础内存（仅取决于 seed，每轮只需构建一次）
fn build_mem_work_base(seed_bytes: &[u8], total: usize) -> Vec<u8> {
    let mut mem = vec![0u8; total];
    let mut st = sha256_multi(&[b"init:", seed_bytes]);
    let mut off = 0usize;
    while off < total {
        st = sha256(&st);
        let copy_len = 32.min(total - off);
        mem[off..off + copy_len].copy_from_slice(&st[..copy_len]);
        off += 32;
    }
    mem
}

/// 在已有的内存副本上执行 MEM_WORK 验证（mem 会被修改）
fn verify_mem_work_on(
    challenge: &[u8],
    seed_bytes: &[u8],
    nonce: &[u8],
    mem: &mut [u8],
    steps: u32,
    bits: u32,
) -> bool {
    let total = mem.len();
    let payload_buf: Vec<u8> = [challenge, nonce].concat();
    let mut acc = sha256_multi(&[b"acc:", seed_bytes, &payload_buf]);
    let mut idx = u32::from_le_bytes(acc[0..4].try_into().unwrap()) as usize % total;

    for i in 0..steps {
        let slice_end = (idx + 32).min(total);
        let mut hasher = Sha256::new();
        hasher.update(&acc);
        hasher.update(&mem[idx..slice_end]);
        hasher.update(&i.to_le_bytes());
        let new_acc: [u8; 32] = hasher.finalize().into();

        let slice_len = slice_end - idx;
        for j in 0..slice_len {
            mem[idx + j] ^= new_acc[j];
        }
        acc = new_acc;
        idx = (idx + 1 + u32::from_le_bytes(acc[0..4].try_into().unwrap()) as usize) % total;
    }

    leading_zero_bits(&acc) >= bits
}

// ============================================================
// 原生赛道实现 — TINY_VM
// ============================================================

fn tiny_vm_init_state(challenge: &str, seed: &str, nonce: &str) -> (Vec<u32>, Vec<u32>) {
    let init_str = format!("{}|{}|{}", challenge, seed, nonce);
    let init = sha256(init_str.as_bytes());

    let mut regs = vec![0u32; 16];
    for i in 0..16usize {
        let u = u32::from_le_bytes(init[(i * 4) % 32..(i * 4) % 32 + 4].try_into().unwrap());
        regs[i] = u ^ 0x9e3779b9u32.wrapping_mul((i as u32) + 1);
    }

    let mut mem = vec![0u32; 1024];
    let mut st = sha256_multi(&[b"mem:", &init]);
    for i in 0..1024usize {
        if (i & 7) == 0 {
            st = sha256(&st);
        }
        mem[i] = u32::from_le_bytes(st[(i & 7) * 4..(i & 7) * 4 + 4].try_into().unwrap());
    }

    (regs, mem)
}

fn tiny_vm_run(program: &[u8], regs: &mut [u32], mem: &mut [u32], steps: u32) -> bool {
    if program.len() % 4 != 0 {
        return false;
    }
    let ins_n = program.len() / 4;
    let mut pc: usize = 0;
    let mem_mask = (mem.len() - 1) as u32;

    for _ in 0..steps {
        if pc >= ins_n {
            return false;
        }
        let off = pc * 4;
        let op = program[off];
        let a = (program[off + 1] & 15) as usize;
        let b_byte = program[off + 2];
        let b = (b_byte & 15) as usize;
        let target = b_byte as usize;
        let imm = program[off + 3] as u32;

        match op {
            0 => {
                regs[a] = regs[a].wrapping_add(regs[b]).wrapping_add(imm);
                pc += 1;
            }
            1 => {
                regs[a] = regs[a] ^ regs[b] ^ imm;
                pc += 1;
            }
            2 => {
                regs[a] = (regs[a] ^ imm).wrapping_mul(regs[b] | 1);
                pc += 1;
            }
            3 => {
                regs[a] = rotl32(regs[a] ^ regs[b], imm & 31);
                pc += 1;
            }
            4 => {
                let idx = (regs[b].wrapping_add(imm)) & mem_mask;
                regs[a] = mem[idx as usize];
                pc += 1;
            }
            5 => {
                let idx = (regs[b].wrapping_add(imm)) & mem_mask;
                mem[idx as usize] = regs[a];
                pc += 1;
            }
            6 => {
                let bit = imm & 31;
                regs[a] = if (regs[b] & (1 << bit)) != 0 { 1 } else { 0 };
                pc += 1;
            }
            7 => {
                let mask = 1u32 << (imm & 31);
                if (regs[a] & mask) != 0 {
                    pc = target;
                } else {
                    pc += 1;
                }
            }
            8 => {
                pc = target;
            }
            9 => break,
            _ => return false,
        }
    }
    true
}

fn tiny_vm_digest(regs: &[u32], mem: &[u32]) -> [u8; 32] {
    // hash regs + sparse sample of mem (same as JS: 16 regs + 32 sampled words)
    let mut bytes = vec![0u8; (16 + 32) * 4];
    let mut off = 0;
    for i in 0..regs.len() {
        bytes[off..off + 4].copy_from_slice(&regs[i].to_le_bytes());
        off += 4;
    }
    let stride = (mem.len() / 32).max(1);
    for i in 0..32 {
        let idx = (i * stride) & (mem.len() - 1);
        bytes[off..off + 4].copy_from_slice(&mem[idx].to_le_bytes());
        off += 4;
    }
    sha256(&bytes[..off])
}

fn verify_tiny_vm(
    challenge: &str,
    seed: &str,
    program: &[u8],
    steps: u32,
    bits: u32,
    nonce: &str,
) -> bool {
    let (mut regs, mut mem) = tiny_vm_init_state(challenge, seed, nonce);
    if !tiny_vm_run(program, &mut regs, &mut mem, steps) {
        return false;
    }
    let digest = tiny_vm_digest(&regs, &mem);
    leading_zero_bits(&digest) >= bits
}

// ============================================================
// WASM 引擎 — VM_CHAIN + ARGON2D_CHAIN
// ============================================================

const WASM_BYTES: &[u8] =
    include_bytes!("../PowLoot/static/wasm/powloot_wasm.wasm-0002330e");

struct WasmWorker {
    store: Store<()>,
    memory: Memory,
    malloc_fn: TypedFunc<i32, i32>,
    free_fn: TypedFunc<(i32, i32), ()>,
    vm_chain_verify_fn: TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>,
    argon2d_chain_verify_fn: TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>,
}

impl WasmWorker {
    fn new(engine: &Engine, module: &Module) -> Result<Self> {
        let mut store = Store::new(engine, ());
        let instance = Instance::new(&mut store, module, &[])?;
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        let malloc_fn = instance.get_typed_func::<i32, i32>(&mut store, "malloc")?;
        let free_fn = instance.get_typed_func::<(i32, i32), ()>(&mut store, "free")?;
        let vm_chain_verify_fn = instance.get_typed_func(&mut store, "vm_chain_verify")?;
        let argon2d_chain_verify_fn = instance.get_typed_func(&mut store, "argon2d_chain_verify")?;
        Ok(Self {
            store,
            memory,
            malloc_fn,
            free_fn,
            vm_chain_verify_fn,
            argon2d_chain_verify_fn,
        })
    }

    fn alloc(&mut self, data: &[u8]) -> Result<(i32, i32)> {
        let len = data.len() as i32;
        let ptr = self.malloc_fn.call(&mut self.store, len)?;
        let mem_data = self.memory.data_mut(&mut self.store);
        mem_data[ptr as usize..ptr as usize + data.len()].copy_from_slice(data);
        Ok((ptr, len))
    }

    fn free_buf(&mut self, ptr: i32, cap: i32) {
        let _ = self.free_fn.call(&mut self.store, (ptr, cap));
    }

    fn verify_vm_chain(
        &mut self,
        challenge: &[u8],
        seed: &[u8],
        program: &[u8],
        steps: u32,
        mem_words: u32,
        chain_update_every: u32,
        sample_words: u32,
        bits: u32,
        nonce: &[u8],
    ) -> Result<bool> {
        let (ch_ptr, ch_len) = self.alloc(challenge)?;
        let (seed_ptr, seed_len) = self.alloc(seed)?;
        let (prog_ptr, prog_len) = self.alloc(program)?;
        let (n_ptr, n_len) = self.alloc(nonce)?;

        let ok = self.vm_chain_verify_fn.call(
            &mut self.store,
            (
                ch_ptr,
                ch_len,
                seed_ptr,
                seed_len,
                prog_ptr,
                prog_len,
                steps as i32,
                mem_words as i32,
                chain_update_every as i32,
                sample_words as i32,
                bits as i32,
                n_ptr,
                n_len,
            ),
        )?;

        self.free_buf(n_ptr, n_len);
        self.free_buf(prog_ptr, prog_len);
        self.free_buf(seed_ptr, seed_len);
        self.free_buf(ch_ptr, ch_len);

        Ok(ok == 1)
    }

    fn verify_argon2d_chain(
        &mut self,
        challenge: &[u8],
        seed: &[u8],
        mem_blocks: u32,
        passes: u32,
        lanes: u32,
        bits: u32,
        nonce: &[u8],
    ) -> Result<bool> {
        let (ch_ptr, ch_len) = self.alloc(challenge)?;
        let (seed_ptr, seed_len) = self.alloc(seed)?;
        let (n_ptr, n_len) = self.alloc(nonce)?;

        let ok = self.argon2d_chain_verify_fn.call(
            &mut self.store,
            (
                ch_ptr,
                ch_len,
                seed_ptr,
                seed_len,
                mem_blocks as i32,
                passes as i32,
                lanes as i32,
                bits as i32,
                n_ptr,
                n_len,
            ),
        )?;

        self.free_buf(n_ptr, n_len);
        self.free_buf(seed_ptr, seed_len);
        self.free_buf(ch_ptr, ch_len);

        Ok(ok == 1)
    }
}

// ============================================================
// 挖矿线程
// ============================================================

struct MiningResult {
    nonce: String,
    round_id: String,
}

fn mine_worker(
    track_params: TrackParams,
    round_id: String,
    found: Arc<AtomicBool>,
    tx: tokio::sync::mpsc::Sender<MiningResult>,
    hash_counter: Arc<AtomicU64>,
    wasm_engine: Option<Arc<Engine>>,
    wasm_module: Option<Arc<Module>>,
) {
    match track_params {
        TrackParams::CpuHash { challenge, bits } => {
            let ch = challenge.as_bytes();
            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                if verify_cpu_hash(ch, nonce.as_bytes(), bits) {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrackParams::Chain {
            challenge,
            seed_bytes,
            steps,
            bits,
        } => {
            let ch = challenge.as_bytes();
            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                if verify_chain(ch, &seed_bytes, nonce.as_bytes(), steps, bits) {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrackParams::BranchyMix {
            challenge,
            seed,
            rounds,
            bits,
        } => {
            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                if verify_branchy_mix(&challenge, &seed, &nonce, rounds, bits) {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrackParams::MemWork {
            challenge,
            seed_bytes,
            steps,
            lanes,
            lane_size,
            bits,
        } => {
            let ch = challenge.as_bytes();
            let total = (lanes * lane_size) as usize;
            // 预建基础内存（仅取决于 seed，每轮固定）
            let base_mem = build_mem_work_base(&seed_bytes, total);
            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                let mut mem = base_mem.clone();
                if verify_mem_work_on(ch, &seed_bytes, nonce.as_bytes(), &mut mem, steps, bits)
                {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrackParams::TinyVm {
            challenge,
            seed,
            program,
            steps,
            bits,
        } => {
            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                if verify_tiny_vm(&challenge, &seed, &program, steps, bits, &nonce) {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrackParams::VmChain {
            challenge,
            seed,
            program_hex,
            steps,
            mem_words,
            chain_update_every,
            sample_words,
            bits,
        } => {
            let engine = wasm_engine.expect("wasm engine needed for VM_CHAIN");
            let module = wasm_module.expect("wasm module needed for VM_CHAIN");
            let mut w = WasmWorker::new(&engine, &module).expect("wasm init");
            let prog_bytes = hex::decode(&program_hex).expect("bad program_hex");
            let ch_bytes = challenge.as_bytes();
            let seed_bytes = seed.as_bytes();

            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                let ok = w
                    .verify_vm_chain(
                        ch_bytes,
                        seed_bytes,
                        &prog_bytes,
                        steps,
                        mem_words,
                        chain_update_every,
                        sample_words,
                        bits,
                        nonce.as_bytes(),
                    )
                    .unwrap_or(false);
                if ok {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrackParams::Argon2dChain {
            challenge,
            seed,
            mem_blocks,
            passes,
            lanes,
            bits,
        } => {
            let engine = wasm_engine.expect("wasm engine needed for ARGON2D_CHAIN");
            let module = wasm_module.expect("wasm module needed for ARGON2D_CHAIN");
            let mut w = WasmWorker::new(&engine, &module).expect("wasm init");
            let ch_bytes = challenge.as_bytes();
            let seed_bytes = seed.as_bytes();

            while !found.load(Ordering::Relaxed) {
                let nonce = random_nonce();
                let ok = w
                    .verify_argon2d_chain(
                        ch_bytes, seed_bytes, mem_blocks, passes, lanes, bits,
                        nonce.as_bytes(),
                    )
                    .unwrap_or(false);
                if ok {
                    if !found.swap(true, Ordering::SeqCst) {
                        let _ = tx.blocking_send(MiningResult { nonce, round_id });
                    }
                    return;
                }
                hash_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ============================================================
// 挖矿任务管理
// ============================================================

struct MiningJob {
    found: Arc<AtomicBool>,
    hash_counter: Arc<AtomicU64>,
    handles: Vec<std::thread::JoinHandle<()>>,
    start_time: Instant,
    last_count: u64,
    last_time: Instant,
}

impl MiningJob {
    fn start(
        track_params: TrackParams,
        round_id: &str,
        thread_count: u32,
        solution_tx: tokio::sync::mpsc::Sender<MiningResult>,
        wasm_engine: Option<Arc<Engine>>,
        wasm_module: Option<Arc<Module>>,
    ) -> Self {
        let found = Arc::new(AtomicBool::new(false));
        let hash_counter = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::with_capacity(thread_count as usize);

        for _ in 0..thread_count {
            let found = found.clone();
            let tx = solution_tx.clone();
            let counter = hash_counter.clone();
            let params = track_params.clone();
            let rid = round_id.to_string();
            let eng = wasm_engine.clone();
            let mod_ = wasm_module.clone();

            handles.push(std::thread::spawn(move || {
                mine_worker(params, rid, found, tx, counter, eng, mod_);
            }));
        }

        let now = Instant::now();
        MiningJob {
            found,
            hash_counter,
            handles,
            start_time: now,
            last_count: 0,
            last_time: now,
        }
    }

    fn stop(&mut self) {
        self.found.store(true, Ordering::SeqCst);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }

    fn get_status(&mut self) -> ServerMsg {
        let now = Instant::now();
        let current_count = self.hash_counter.load(Ordering::Relaxed);
        let elapsed = now.duration_since(self.last_time).as_secs_f64();

        let hash_rate = if elapsed > 0.1 {
            (current_count - self.last_count) as f64 / elapsed
        } else {
            0.0
        };

        self.last_count = current_count;
        self.last_time = now;

        ServerMsg::Status {
            hash_rate,
            attempts: current_count,
        }
    }
}

// ============================================================
// 兑换码保存
// ============================================================

fn save_code(code: &str) {
    use std::fs::OpenOptions;
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(CODE_FILE) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{} | {}", timestamp, code);
        println!("[+] 兑换码已保存: {} ({})", code, CODE_FILE);
    }
}

// ============================================================
// HTTP/WS 连接处理 — 同端口服务 HTML 中继页和 WebSocket
// ============================================================

const RELAY_HTML: &str = r#"<!DOCTYPE html><html><head><title>PowLoot Relay</title></head>
<body style="background:#1a1a2e;color:#eee;font-family:monospace;padding:20px">
<pre id="log">PowLoot Relay - 连接中...</pre>
<script>
const log = document.getElementById('log');
function addLog(msg) { log.textContent += '\n' + msg; }
const ws = new WebSocket('ws://' + location.host + '/ws');
ws.onopen = () => { addLog('已连接 Rust 引擎'); window.opener?.postMessage({_r:1, t:'open'}, '*'); };
ws.onmessage = e => window.opener?.postMessage({_r:1, t:'msg', d:e.data}, '*');
ws.onerror = () => { addLog('连接错误'); window.opener?.postMessage({_r:1, t:'err'}, '*'); };
ws.onclose = () => { addLog('连接断开'); window.opener?.postMessage({_r:1, t:'close'}, '*'); };
window.addEventListener('message', e => {
  if (e.data?._r !== 1) return;
  if (e.data.t === 'send' && ws.readyState === 1) ws.send(e.data.d);
});
</script></body></html>"#;

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    thread_count: u32,
    wasm_engine: Arc<Engine>,
    wasm_module: Arc<Module>,
) -> Result<()> {
    // Peek at request to determine if it's WS upgrade or plain HTTP
    let mut buf = vec![0u8; 4096];
    let n = stream.peek(&mut buf).await?;
    let request_str = std::str::from_utf8(&buf[..n]).unwrap_or("");

    if request_str.contains("Upgrade: websocket") || request_str.contains("upgrade: websocket") {
        // WebSocket upgrade
        let ws = tokio_tungstenite::accept_async(stream).await?;
        handle_ws(ws, thread_count, wasm_engine, wasm_module).await?;
    } else if request_str.starts_with("GET") {
        // Serve relay HTML
        let body = RELAY_HTML;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            body.len(),
            body
        );
        // Read the full request first
        let _ = stream.read(&mut buf).await;
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
    } else {
        // Unknown — close
        let _ = stream.read(&mut buf).await;
        let response = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }
    Ok(())
}

async fn handle_ws(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    thread_count: u32,
    wasm_engine: Arc<Engine>,
    wasm_module: Arc<Module>,
) -> Result<()> {
    let (mut write, mut read) = ws.split();

    // 发送 ready
    let ready = serde_json::to_string(&ServerMsg::Ready {
        threads: thread_count,
    })?;
    write.send(Message::Text(ready.into())).await?;
    println!("[+] 已发送 ready (threads={})", thread_count);

    let (solution_tx, mut solution_rx) = tokio::sync::mpsc::channel::<MiningResult>(4);
    let mut mining_job: Option<MiningJob> = None;
    let mut status_interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let text_str = text.to_string();
                        match serde_json::from_str::<ClientMsg>(&text_str) {
                            Ok(ClientMsg::Mine { round_id, track, params }) => {
                                // 停止旧任务
                                if let Some(mut job) = mining_job.take() {
                                    job.stop();
                                    println!("[*] 停止旧任务");
                                }
                                // 排空旧 solution
                                while solution_rx.try_recv().is_ok() {}

                                match parse_track_params(&track, &params) {
                                    Ok(track_params) => {
                                        println!(
                                            "[*] 开始挖矿: track={} round={} bits={} threads={}",
                                            track,
                                            &round_id[..8.min(round_id.len())],
                                            params.get("bits").and_then(|v| v.as_u64()).unwrap_or(0),
                                            thread_count,
                                        );

                                        mining_job = Some(MiningJob::start(
                                            track_params,
                                            &round_id,
                                            thread_count,
                                            solution_tx.clone(),
                                            Some(wasm_engine.clone()),
                                            Some(wasm_module.clone()),
                                        ));
                                        status_interval.reset();
                                    }
                                    Err(e) => {
                                        eprintln!("[!] 参数解析失败: {} (track={})", e, track);
                                    }
                                }
                            }
                            Ok(ClientMsg::Stop) => {
                                if let Some(mut job) = mining_job.take() {
                                    let elapsed = job.start_time.elapsed();
                                    job.stop();
                                    println!("[*] 停止挖矿: 耗时={:.1}s", elapsed.as_secs_f64());
                                    let msg = serde_json::to_string(&ServerMsg::Stopped)?;
                                    write.send(Message::Text(msg.into())).await?;
                                }
                            }
                            Ok(ClientMsg::SaveCode { code }) => {
                                save_code(&code);
                            }
                            Err(e) => {
                                eprintln!("[!] 消息解析失败: {}", e);
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = write.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        println!("[*] 浏览器断开连接");
                        break;
                    }
                    Some(Err(e)) => {
                        eprintln!("[!] WebSocket 错误: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            // 挖矿线程找到解 — 立即响应
            result = solution_rx.recv() => {
                if let Some(result) = result {
                    if let Some(job) = mining_job.as_ref() {
                        let elapsed = job.start_time.elapsed();
                        let attempts = job.hash_counter.load(Ordering::Relaxed);
                        println!(
                            "[+] 找到解! nonce={}... round={} 耗时={:.2}s 尝试={}",
                            &result.nonce[..8],
                            &result.round_id[..8.min(result.round_id.len())],
                            elapsed.as_secs_f64(),
                            attempts,
                        );
                    }
                    let msg = serde_json::to_string(&ServerMsg::Solution {
                        nonce: result.nonce,
                        round_id: result.round_id,
                    })?;
                    write.send(Message::Text(msg.into())).await?;

                    if let Some(mut job) = mining_job.take() {
                        job.stop();
                    }
                }
            }
            // 定时推送状态
            _ = status_interval.tick() => {
                if let Some(job) = mining_job.as_mut() {
                    let msg = serde_json::to_string(&job.get_status())?;
                    write.send(Message::Text(msg.into())).await?;
                }
            }
        }
    }

    if let Some(mut job) = mining_job.take() {
        job.stop();
        println!("[*] 连接断开，挖矿已停止");
    }

    Ok(())
}

// ============================================================
// 主函数
// ============================================================

fn print_banner() {
    println!();
    println!("  ╔═══════════════════════════════════════════════╗");
    println!("  ║   PowLoot Machine — 本地多赛道 PoW 计算引擎    ║");
    println!("  ║   等待浏览器 JS 桥接脚本连接                    ║");
    println!("  ╚═══════════════════════════════════════════════╝");
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    print_banner();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("用法: powloot-machine [选项]");
        println!();
        println!("选项:");
        println!("  --threads=<N>   挖矿线程数 (默认: CPU 核心数)");
        println!("  --port=<PORT>   服务端口 (默认: {})", DEFAULT_PORT);
        println!("  --bind=<ADDR>   绑定地址 (默认: localhost)");
        println!("  --help          显示帮助");
        println!();
        println!("启动后在浏览器控制台粘贴 bridge.js 即可开始挖矿。");
        println!("兑换码自动保存到 {}", CODE_FILE);
        return Ok(());
    }

    let thread_count: u32 = args
        .iter()
        .find(|a| a.starts_with("--threads="))
        .and_then(|a| a.trim_start_matches("--threads=").parse().ok())
        .unwrap_or(num_cpus::get() as u32);

    let port: u16 = args
        .iter()
        .find(|a| a.starts_with("--port="))
        .and_then(|a| a.trim_start_matches("--port=").parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let bind_addr: String = args
        .iter()
        .find(|a| a.starts_with("--bind="))
        .map(|a| a.trim_start_matches("--bind=").to_string())
        .unwrap_or_else(|| "localhost".to_string());

    // 初始化 WASM 引擎
    println!("[*] 初始化 WASM 引擎...");
    let engine = Arc::new(Engine::default());
    let module = Arc::new(Module::new(&engine, WASM_BYTES)?);
    println!("[*] WASM 模块加载成功 ({} bytes)", WASM_BYTES.len());

    println!("[*] 线程数: {}", thread_count);
    println!("[*] 监听: {}:{}", bind_addr, port);
    println!("[*] 兑换码保存: {}", CODE_FILE);
    println!();
    println!("[*] 等待浏览器连接...");

    let listener = TcpListener::bind(format!("{}:{}", bind_addr, port)).await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let engine = engine.clone();
        let module = module.clone();

        tokio::spawn(async move {
            match handle_tcp_connection(stream, thread_count, engine, module).await {
                Ok(()) => {}
                Err(e) => {
                    // 中继页 HTML 请求断开是正常的，不打印
                    let msg = format!("{}", e);
                    if !msg.contains("Connection reset") {
                        eprintln!("[!] 连接错误 ({}): {}", addr, e);
                    }
                }
            }
        });
    }
}
