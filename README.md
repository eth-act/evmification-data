# evmification-data

Dataset and analysis of EVM precompile usage on Ethereum mainnet, covering blocks 2.4M–24.7M.

Useful for understanding precompile adoption patterns and informing EVM protocol changes.

- **Data**: [`precompile-usage/`](precompile-usage/) — parquet files ([download](https://s3-dcl1.ethquokkaops.io/evm-parquet/))
- **Dashboard**: [`dashboard/`](dashboard/) — interactive visualizations of usage, gas, and caller activity
- **Analysis**: [`analysis/`](analysis/) — DuckDB scripts to generate dashboard data

Proof of concept EVMified precompiles: [eth-act/evmification](https://github.com/eth-act/evmification/tree/main)
