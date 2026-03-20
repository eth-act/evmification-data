# Precompile Usage Data

Browse and download parquet files: https://s3-dcl1.ethquokkaops.io/evm-parquet/

Parquet files containing every EVM precompile call on Ethereum mainnet, covering blocks 2,400,000 to 24,699,999.

Each file covers a 100K block range: `blocks_{start}_{end}.parquet`.

## Schema

| Column | Type | Description |
|---|---|---|
| `block_number` | uint64 | Block number where the call occurred |
| `block_timestamp` | uint64 | Unix timestamp of the block |
| `tx_hash` | string | Transaction hash containing the precompile call |
| `precompile_address` | string | Address of the precompile contract (e.g. `0x0000...0001` for ecrecover) |
| `precompile_name` | string | Human-readable name (e.g. `ecrecover`, `sha256`, `modexp`, `ecpairing`) |
| `caller` | string | Address of the contract that called the precompile |
| `input` | string | Hex-encoded input data passed to the precompile |
| `precompile_gas_used` | uint64 | Gas consumed by the precompile execution |
| `tx_gas_used` | uint64 | Total gas used by the entire transaction |

## Precompile Names

| Name | Address | Fork |
|---|---|---|
| `ecrecover` | 0x01 | Genesis |
| `sha256` | 0x02 | Genesis |
| `ripemd160` | 0x03 | Genesis |
| `identity` | 0x04 | Genesis |
| `modexp` | 0x05 | Byzantium |
| `ecadd` | 0x06 | Byzantium |
| `ecmul` | 0x07 | Byzantium |
| `ecpairing` | 0x08 | Byzantium |
| `blake2f` | 0x09 | Istanbul |
| `pointEval` | 0x0a | Dencun |
| `bls12_g1add` | 0x0b | Pectra |
| `bls12_g1mul` | 0x0c | Pectra |
| `bls12_g1msm` | 0x0d | Pectra |
| `bls12_g2add` | 0x0e | Pectra |
| `bls12_g2mul` | 0x0f | Pectra |
| `bls12_g2msm` | 0x10 | Pectra |
| `bls12_pairing_check` | 0x11 | Pectra |
| `bls12_map_fp_to_g1` | 0x12 | Pectra |
| `bls12_map_fp2_to_g2` | 0x13 | Pectra |
| `p256verify` | 0x100 | Fusaka |

## Notes

- Data includes rows where ETH was sent to precompile addresses before the precompile was deployed (pre-fork). The analysis script filters these out using known activation blocks.
- The `input` field contains the raw calldata in hex, including the `0x` prefix.
