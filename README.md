# ldk-node-sample
Sample lightning node command-line app built on top of
[Ldk Node](https://github.com/lightningdevkit/ldk-node)
(similar to
[ldk-sample](https://github.com/lightningdevkit/ldk-sample)
).


## Installation
```
git clone https://github.com/optout21/ldk-node-sample
```

## Usage
```
cd ldk-node-sample
cargo run [<datadir>] [--port <listening_port>] [--network <network>|--testnet|--mainnet] [--esplora <esplora_url>] [--log <log_level>]
```

`datadir` is a subfolder for keeping state, defaults to `datadir`

`listening_port`: defaults to 9735.

`network`: default is testnet, one of: testnet, mainnet.

`esplora_url`: The URL of the Esplora server to use as chain info. Sample values: 'https://blockstream.info/testnet/api', 'https://mempool.space/api'.

`log_level`: Logging level, one of: none, error, warn, info, debug, trace.

``

For the interactive commands, type `help`.


## License

Licensed under either:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
