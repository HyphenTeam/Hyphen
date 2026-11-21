# Limit Orders

This Rust contract settles fixed-price exchanges between two assets issued by the contract. Deployment credits both supplies to the deployer's Ed25519 account. The supply is fixed for the lifetime of each deployment. Asset IDs and balances belong to that contract address. Native HYP payments and balances in other contracts use separate ledgers.

A maker may have one open order. Placement deducts the entire offer from the maker's available balance. Any other signer can fill the order by paying the requested quantity of the opposite asset. Both transfers and removal of the order commit in one VM call. Only the maker can cancel and recover the offer. A monotonically increasing ID distinguishes successive orders at identical prices. A failed call preserves the order, balances and signer's next nonce.

## Binary ABI

Amounts and order IDs are unsigned 64-bit little-endian integers. An account is a raw 32-byte Ed25519 public key. The asset selector is one byte, either `00` or `01`. Amounts are in indivisible units. `terms` occupies 17 bytes in the order `sell_asset | offered_amount | requested_amount`. The stored order is `order_id | terms`, totaling 25 bytes.

| Entry point | Input bytes | Result |
| --- | --- | --- |
| Deployment constructor | `supply_0`, `supply_1` | Issues both positive supplies to the signer |
| `hyphen_execute` | `01`, asset, recipient, amount | Transfers a positive amount |
| `hyphen_execute` | `02`, terms | Escrows the offer and opens an order |
| `hyphen_execute` | `03`, maker, order | Fills the exact order returned by the query |
| `hyphen_execute` | `04`, order ID | Cancels the signer's open order |
| `hyphen_query` | `00` | Returns the two supplies in asset order |
| `hyphen_query` | `01`, asset, account | Returns the available balance |
| `hyphen_query` | `02`, maker | Returns the order, or zero bytes when none is open |

Run `scripts/test-contract-toolchains.ps1` with the Rust `wasm32-unknown-unknown` target and Clang's Wasm linker installed. The module is written to `target/contract-toolchains/limit-orders.wasm`. Pass the 16 constructor bytes to `hyphen-contract deploy` using `--input`. The live acceptance run uses separate signers and checks settlement again after reopening the node. [Contract RPC commands](../../wiki/Operations-Verification.md#third-party-contract-commands) · [Acceptance test](../../scripts/test-contract-rpc.py)
