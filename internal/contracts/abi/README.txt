Place your contract ABI JSON files here.

Example file names (must match config.yaml abi_path):
  - my_xdc_contract.json
  - my_redbelly_contract.json

The ABI JSON should be the standard Solidity compiler output, e.g.:
[
  {
    "anonymous": false,
    "inputs": [
      { "indexed": true,  "name": "from",  "type": "address" },
      { "indexed": true,  "name": "to",    "type": "address" },
      { "indexed": false, "name": "value", "type": "uint256" }
    ],
    "name": "Transfer",
    "type": "event"
  }
]
