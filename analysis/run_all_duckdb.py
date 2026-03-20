"""Run all analysis modules using DuckDB — parallel, columnar, fast.

Replaces the pandas chunked approach with SQL queries over parquet files.
DuckDB auto-parallelises across all cores and only reads needed columns.
"""
import json
import os
import sys
import time
from collections import Counter, defaultdict

import duckdb

TOP_N_CALLERS = 30

# Activation blocks per precompile (fork where they became available)
ACTIVATION_BLOCK = {
    'ecrecover': 0, 'sha256': 0, 'ripemd160': 0, 'identity': 0,
    'ecadd': 4_370_000, 'ecmul': 4_370_000, 'ecpairing': 4_370_000,
    'modexp': 4_370_000, 'modexp_le256': 4_370_000, 'modexp_gt256': 4_370_000,
    'blake2f': 9_069_000,
    'pointEval': 19_426_587,
    'p256verify': 23_935_694,
    'bls12_g1add': 22_431_000, 'bls12_g1mul': 22_431_000, 'bls12_g1msm': 22_431_000,
    'bls12_g2add': 22_431_000, 'bls12_g2mul': 22_431_000, 'bls12_g2msm': 22_431_000,
    'bls12_pairing': 22_431_000, 'bls12_pairing_check': 22_431_000,
    'bls12_map_fp_to_g1': 22_431_000, 'bls12_map_fp2_to_g2': 22_431_000,
}


def write_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'  Wrote {path}')


def build_top_callers(callers, total_calls, total_gas, n=TOP_N_CALLERS, extra_fn=None):
    """Build a sorted top-N caller list with percentages."""
    sorted_callers = sorted(callers, key=lambda x: -x['calls'])
    result = []
    for c in sorted_callers[:n]:
        entry = {
            'address': c['address'],
            'calls': c['calls'],
            'gas': c['gas'],
            'tx_gas': c.get('tx_gas', 0),
            'pct_calls': round(100 * c['calls'] / total_calls, 2) if total_calls > 0 else 0,
            'pct_gas': round(100 * c['gas'] / total_gas, 2) if total_gas > 0 else 0,
        }
        if extra_fn:
            entry.update(extra_fn(c))
        result.append(entry)
    return result


def build_input_entry(p, sizes_counter, modexp_c, pairing_c, blake2f_c, bls_c):
    """Build an input analysis entry for a precompile."""
    top_sizes = dict(Counter(sizes_counter).most_common(20))
    entry = {'input_size_distribution': {str(k): v for k, v in sorted(top_sizes.items(), key=lambda x: -x[1])}}

    if p in ('modexp_le256', 'modexp_gt256') and modexp_c:
        entry['top_size_combinations'] = [
            {'base_size': c[0], 'exp_size': c[1], 'mod_size': c[2], 'count': n}
            for c, n in modexp_c.most_common(20)
        ]
    if p == 'ecpairing' and pairing_c:
        entry['pair_count_distribution'] = {str(k): v for k, v in sorted(pairing_c.items())}
    if p == 'blake2f' and blake2f_c:
        entry['rounds_distribution'] = {str(k): v for k, v in sorted(blake2f_c.items())}
    if 'msm' in p and bls_c:
        entry['point_count_distribution'] = {str(k): v for k, v in sorted(bls_c.items())}
    return entry


def main():
    t0 = time.time()
    directory = sys.argv[1] if len(sys.argv) > 1 else '.'
    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), '..', 'dashboard', 'data')
    os.makedirs(out_dir, exist_ok=True)

    glob_pattern = f'{directory}/blocks_*.parquet'

    con = duckdb.connect()

    # Build per-precompile activation filter (drop rows before the fork they were introduced)
    activation_clauses = " AND ".join(
        f"NOT (precompile_name = '{name}' AND block_number < {block})"
        for name, block in ACTIVATION_BLOCK.items() if block > 0
    )

    # Create base view with filtering, derived columns, and pre-computed hex fields
    con.execute(f"""
        CREATE VIEW base AS
        SELECT
            block_number,
            tx_hash,
            precompile_address,
            CASE
                WHEN precompile_name != 'modexp' THEN precompile_name
                WHEN length(replace(input, '0x', '')) < 192 THEN 'modexp_le256'
                WHEN TRY_CAST(('0x' || substring(replace(input, '0x', ''), 129, 64)) AS BIGINT) > 32 THEN 'modexp_gt256'
                WHEN TRY_CAST(('0x' || substring(replace(input, '0x', ''), 129, 64)) AS BIGINT) IS NULL THEN 'modexp_gt256'
                ELSE 'modexp_le256'
            END AS precompile_name,
            caller,
            input,
            replace(input, '0x', '') AS input_hex,
            length(replace(input, '0x', '')) // 2 AS input_byte_len,
            precompile_gas_used AS gas_used,
            tx_gas_used,
            strftime(to_timestamp(block_timestamp), '%Y-%m') AS month,
            strftime(to_timestamp(block_timestamp), '%Y') AS year
        FROM read_parquet('{glob_pattern}', union_by_name=true)
        WHERE {activation_clauses}
    """)

    row_count = con.execute("SELECT count(*) FROM base").fetchone()[0]
    block_range = con.execute("SELECT min(block_number), max(block_number) FROM base").fetchone()
    min_block, max_block = int(block_range[0]), int(block_range[1])
    print(f'Loaded {row_count:,} rows, blocks {min_block:,} - {max_block:,}  ({time.time()-t0:.1f}s)', flush=True)

    # --- Overview ---
    print('Generating overview...', flush=True)
    total_unique_txs = con.execute("SELECT count(DISTINCT tx_hash) FROM base").fetchone()[0]

    overview_rows = con.execute("""
        SELECT
            precompile_name,
            count(*) AS calls,
            sum(gas_used) AS gas,
            count(DISTINCT caller) AS unique_callers,
            count(DISTINCT tx_hash) AS unique_txs
        FROM base
        GROUP BY precompile_name
        ORDER BY calls DESC
    """).fetchall()

    # Count unique txs from each precompile's activation block onwards in a single query
    activation_blocks_needed = sorted(set(
        ACTIVATION_BLOCK.get(r[0], 0) for r in overview_rows
    ))
    case_exprs = ", ".join(
        f"count(DISTINCT CASE WHEN block_number >= {block} THEN tx_hash END) AS txs_{block}"
        for block in activation_blocks_needed
    )
    txs_row = con.execute(f"SELECT {case_exprs} FROM base").fetchone()
    txs_from_block = {block: int(txs_row[i]) for i, block in enumerate(activation_blocks_needed)}

    precompiles_list = []
    for r in overview_rows:
        pc_name = r[0]
        activation = ACTIVATION_BLOCK.get(pc_name, 0)
        pc_txs_total = txs_from_block[activation]
        precompiles_list.append({
            'precompile': pc_name,
            'calls': int(r[1]),
            'gas': int(r[2]),
            'unique_callers': int(r[3]),
            'unique_txs': int(r[4]),
            'one_in_n_txs': round(pc_txs_total / r[4], 1) if r[4] > 0 else None,
        })

    ov_calls = {r['precompile']: r['calls'] for r in precompiles_list}
    ov_gas = {r['precompile']: r['gas'] for r in precompiles_list}

    write_json({
        'block_range': [min_block, max_block],
        'total_precompile_calls': int(row_count),
        'total_unique_txs': int(total_unique_txs),
        'precompiles': precompiles_list,
    }, os.path.join(out_dir, 'overview.json'))
    print(f'  ({time.time()-t0:.1f}s)', flush=True)

    # --- Timeseries ---
    print('Generating timeseries...', flush=True)
    ts_rows = con.execute("""
        SELECT month, precompile_name, count(*) AS calls, sum(gas_used) AS gas
        FROM base
        GROUP BY month, precompile_name
        ORDER BY month, precompile_name
    """).fetchall()

    month_total_calls = defaultdict(int)
    month_total_gas = defaultdict(int)
    ts_data = defaultdict(dict)
    all_months = set()
    all_precompiles = set()

    for month, pc, calls, gas in ts_rows:
        month_total_calls[month] += int(calls)
        month_total_gas[month] += int(gas)
        ts_data[pc][month] = (int(calls), int(gas))
        all_months.add(month)
        all_precompiles.add(pc)

    all_months = sorted(all_months)
    all_precompiles = sorted(all_precompiles)

    series = {}
    for p in all_precompiles:
        series[p] = []
        for m in all_months:
            calls, gas = ts_data[p].get(m, (0, 0))
            tc = month_total_calls[m]
            tg = month_total_gas[m]
            series[p].append({
                'month': m,
                'calls': calls,
                'gas': gas,
                'pct_calls': round(100 * calls / tc, 2) if tc > 0 else 0,
                'pct_gas': round(100 * gas / tg, 2) if tg > 0 else 0,
            })

    write_json({
        'block_range': [min_block, max_block],
        'months': all_months,
        'series': series,
    }, os.path.join(out_dir, 'timeseries.json'))
    print(f'  ({time.time()-t0:.1f}s)', flush=True)

    # --- Callers (all-time + per-year + migration, unified) ---
    print('Generating callers...', flush=True)

    # All-time caller data (includes first/last block for migration)
    caller_rows = con.execute("""
        SELECT
            precompile_name, caller,
            count(*) AS calls,
            sum(gas_used) AS gas,
            sum(tx_gas_used) AS tx_gas,
            min(block_number) AS first_block,
            max(block_number) AS last_block
        FROM base
        GROUP BY precompile_name, caller
    """).fetchall()

    caller_data = defaultdict(list)
    for pc, caller, calls, gas, tx_gas, fb, lb in caller_rows:
        caller_data[pc].append({
            'address': caller,
            'calls': int(calls),
            'gas': int(gas),
            'tx_gas': int(tx_gas),
            'first_block': int(fb),
            'last_block': int(lb),
        })

    # Sort once per precompile, reuse for callers + migration
    for pc in caller_data:
        caller_data[pc].sort(key=lambda x: -x['calls'])

    callers_result = {}
    for p in sorted(caller_data):
        total_c = ov_calls.get(p, 0)
        total_g = ov_gas.get(p, 0)

        top_list = build_top_callers(
            caller_data[p], total_c, total_g,
            extra_fn=lambda c: {'first_block': c['first_block'], 'last_block': c['last_block']},
        )

        callers_result[p] = {
            'total_calls': total_c,
            'total_gas': total_g,
            'unique_callers': len(caller_data[p]),
            'top_callers': top_list,
        }

    # Per-year unique txs (for "1 in N" calculation)
    yearly_txs_rows = con.execute("""
        SELECT year, precompile_name,
            count(DISTINCT tx_hash) AS unique_txs
        FROM base
        GROUP BY year, precompile_name
    """).fetchall()
    yearly_pc_txs = defaultdict(dict)
    for year, pc, txs in yearly_txs_rows:
        yearly_pc_txs[pc][year] = int(txs)

    yearly_total_txs_rows = con.execute("""
        SELECT year, count(DISTINCT tx_hash) AS total_txs
        FROM base
        GROUP BY year
    """).fetchall()
    yearly_total_txs = {r[0]: int(r[1]) for r in yearly_total_txs_rows}

    # Per-year caller data
    yearly_caller_rows = con.execute("""
        SELECT
            precompile_name, year, caller,
            count(*) AS calls,
            sum(gas_used) AS gas,
            sum(tx_gas_used) AS tx_gas
        FROM base
        GROUP BY precompile_name, year, caller
    """).fetchall()

    yearly_callers = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {'calls': 0, 'gas': 0, 'tx_gas': 0})))
    for pc, year, caller, calls, gas, tx_gas in yearly_caller_rows:
        yearly_callers[pc][year][caller]['calls'] += int(calls)
        yearly_callers[pc][year][caller]['gas'] += int(gas)
        yearly_callers[pc][year][caller]['tx_gas'] += int(tx_gas)

    for pc in sorted(yearly_callers):
        by_year = {}
        for year in sorted(yearly_callers[pc]):
            year_data = yearly_callers[pc][year]
            total_c = sum(d['calls'] for d in year_data.values())
            total_g = sum(d['gas'] for d in year_data.values())
            year_callers = [{'address': a, **d} for a, d in year_data.items()]
            top_list = build_top_callers(year_callers, total_c, total_g)

            pc_txs = yearly_pc_txs.get(pc, {}).get(year, 0)
            total_txs = yearly_total_txs.get(year, 0)
            by_year[year] = {
                'total_calls': total_c,
                'total_gas': total_g,
                'unique_callers': len(year_data),
                'unique_txs': pc_txs,
                'total_txs': total_txs,
                'one_in_n_txs': round(total_txs / pc_txs, 1) if pc_txs > 0 else None,
                'top_callers': top_list,
            }
        if pc in callers_result:
            callers_result[pc]['by_year'] = by_year

    write_json({
        'block_range': [min_block, max_block],
        'precompiles': callers_result,
    }, os.path.join(out_dir, 'callers.json'))
    print(f'  ({time.time()-t0:.1f}s)', flush=True)

    # --- Per-precompile block stats (single query, derive all-time from per-year) ---
    print('Generating usage-patterns...', flush=True)

    # Get per-block call counts grouped by precompile and year
    pp_block_yearly = con.execute("""
        SELECT
            precompile_name, year,
            median(calls) AS median_calls,
            quantile_cont(calls, 0.95) AS p95_calls,
            max(calls) AS max_calls,
            count(*) AS blocks_with_calls
        FROM (
            SELECT precompile_name, year, block_number, count(*) AS calls
            FROM base
            GROUP BY precompile_name, year, block_number
        )
        GROUP BY precompile_name, year
    """).fetchall()

    per_precompile_block_yearly = defaultdict(dict)
    for pc, year, median_c, p95_c, max_c, blocks in pp_block_yearly:
        per_precompile_block_yearly[pc][year] = {
            'median_per_block': float(median_c),
            'p95_per_block': float(p95_c),
            'max_per_block': int(max_c),
            'blocks_with_calls': int(blocks),
        }

    # All-time block stats (need a separate query since median/p95 can't be derived from yearly)
    pp_block = con.execute("""
        SELECT
            precompile_name,
            median(calls) AS median_calls,
            quantile_cont(calls, 0.95) AS p95_calls,
            max(calls) AS max_calls,
            count(*) AS blocks_with_calls
        FROM (
            SELECT precompile_name, block_number, count(*) AS calls
            FROM base
            GROUP BY precompile_name, block_number
        )
        GROUP BY precompile_name
    """).fetchall()

    per_precompile_block = {}
    for pc, median_c, p95_c, max_c, blocks in pp_block:
        per_precompile_block[pc] = {
            'median_per_block': float(median_c),
            'p95_per_block': float(p95_c),
            'max_per_block': int(max_c),
            'blocks_with_calls': int(blocks),
            'by_year': per_precompile_block_yearly.get(pc, {}),
        }

    write_json({
        'block_range': [min_block, max_block],
        'per_precompile': per_precompile_block,
    }, os.path.join(out_dir, 'usage-patterns.json'))
    print(f'  ({time.time()-t0:.1f}s)', flush=True)

    # --- Inputs (per-year only, derive all-time by summing) ---
    print('Generating inputs...', flush=True)

    # Input sizes by year (single query instead of all-time + per-year)
    input_size_rows = con.execute("""
        SELECT precompile_name, year, input_byte_len AS input_size, count(*) AS cnt
        FROM base
        GROUP BY precompile_name, year, input_size
    """).fetchall()

    yearly_input_sizes = defaultdict(lambda: defaultdict(Counter))
    input_sizes = defaultdict(Counter)  # all-time, derived by summing
    for pc, year, size, cnt in input_size_rows:
        yearly_input_sizes[pc][year][int(size)] += int(cnt)
        input_sizes[pc][int(size)] += int(cnt)

    # Modexp combos by year
    modexp_rows = con.execute("""
        SELECT
            precompile_name, year,
            ('0x' || substring(input_hex, 1, 64))::BIGINT AS base_size,
            ('0x' || substring(input_hex, 65, 64))::BIGINT AS exp_size,
            ('0x' || substring(input_hex, 129, 64))::BIGINT AS mod_size,
            count(*) AS cnt
        FROM base
        WHERE precompile_name IN ('modexp_le256', 'modexp_gt256')
          AND length(input_hex) >= 192
        GROUP BY precompile_name, year, base_size, exp_size, mod_size
        ORDER BY cnt DESC
    """).fetchall()

    yearly_modexp = defaultdict(lambda: defaultdict(Counter))
    modexp_combos = defaultdict(Counter)
    for pc, year, bs, es, ms, cnt in modexp_rows:
        key = (int(bs), int(es), int(ms))
        yearly_modexp[pc][year][key] += int(cnt)
        modexp_combos[pc][key] += int(cnt)

    # Ecpairing pair counts by year
    pairing_rows = con.execute("""
        SELECT year, input_byte_len // 192 AS pairs, count(*) AS cnt
        FROM base
        WHERE precompile_name = 'ecpairing'
        GROUP BY year, pairs
    """).fetchall()

    yearly_pairing = defaultdict(Counter)
    pairing_pairs = Counter()
    for year, pairs, cnt in pairing_rows:
        yearly_pairing[year][int(pairs)] += int(cnt)
        pairing_pairs[int(pairs)] += int(cnt)

    # Blake2f rounds by year
    blake2f_rows = con.execute("""
        SELECT year,
            ('0x' || substring(input_hex, 1, 8))::BIGINT AS rounds,
            count(*) AS cnt
        FROM base
        WHERE precompile_name = 'blake2f'
          AND length(input_hex) >= 8
        GROUP BY year, rounds
    """).fetchall()

    yearly_blake2f = defaultdict(Counter)
    blake2f_rounds = Counter()
    for year, rounds, cnt in blake2f_rows:
        yearly_blake2f[year][int(rounds)] += int(cnt)
        blake2f_rounds[int(rounds)] += int(cnt)

    # BLS MSM point counts by year
    bls_msm_rows = con.execute("""
        SELECT precompile_name, year,
            CASE
                WHEN precompile_name LIKE '%g1%'
                THEN input_byte_len // 128
                ELSE input_byte_len // 256
            END AS points,
            count(*) AS cnt
        FROM base
        WHERE precompile_name LIKE '%msm%'
        GROUP BY precompile_name, year, points
    """).fetchall()

    yearly_bls_msm = defaultdict(lambda: defaultdict(Counter))
    bls_msm_points = defaultdict(Counter)
    for pc, year, pts, cnt in bls_msm_rows:
        yearly_bls_msm[pc][year][int(pts)] += int(cnt)
        bls_msm_points[pc][int(pts)] += int(cnt)

    # Build input results
    inputs_result = {}
    for p in sorted(input_sizes):
        entry = build_input_entry(p, input_sizes[p], modexp_combos.get(p),
                                   pairing_pairs if p == 'ecpairing' else None,
                                   blake2f_rounds if p == 'blake2f' else None,
                                   bls_msm_points.get(p))

        by_year = {}
        for year in sorted(yearly_input_sizes[p].keys()):
            by_year[year] = build_input_entry(
                p, yearly_input_sizes[p][year],
                yearly_modexp.get(p, {}).get(year),
                yearly_pairing.get(year) if p == 'ecpairing' else None,
                yearly_blake2f.get(year) if p == 'blake2f' else None,
                yearly_bls_msm.get(p, {}).get(year),
            )
        entry['by_year'] = by_year
        inputs_result[p] = entry

    write_json({
        'block_range': [min_block, max_block],
        'precompiles': inputs_result,
    }, os.path.join(out_dir, 'inputs.json'))
    print(f'  ({time.time()-t0:.1f}s)', flush=True)

    elapsed = time.time() - t0
    print(f'\nDone! All JSON files written to {out_dir}  ({elapsed:.1f}s total)', flush=True)


if __name__ == '__main__':
    main()
