# DegaTokenClaim

## Description

DegaTokenClaim is an application designed to manage the claiming of tokens on a decentralized platform. This tool allows users to claim their tokens securely and efficiently.

## Features

- Secure token claiming
- Intuitive user interface
- Support for multiple blockchain networks
- Transaction verification and tracking

## System Requirements

- Node.js v14.x or higher
- npm v6.x or higher
- Metamask or any other Ethereum-compatible wallet

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/DEGAorg/TGE-claim-contract.git
   cd TGE-claim-contract
   ```

2. Install the dependencies:
   ```sh
   npm install
   ```

## Environment Variables

Configuration variables are set via tasks in the `vars` scope and can be retrieved in the config using the `vars` object. This feature is useful for user-specific values or for data that shouldn't be included in the code repository.

1. Set the `PRIVATE_KEY` variable:

   ```sh
   npx hardhat vars set PRIVATE_KEY
   ✔ Enter value: ********************************
   ```

2. Set the `ETHERSCAN_API_KEY` variable:

   ```sh
   npx hardhat vars set ETHERSCAN_API_KEY
   ✔ Enter value: ********************************
   ```

## Usage

1. Start the development server:
   ```sh
   npx hardhat node
   ```

2. Deploy the smart contract:
   ```sh
   npx hardhat run scripts/deploy.js --network localhost
   ```

3. Run tests:
   ```sh
   npm run test
   npm run test:forge
   ```

4. Run coverage tests:
   ```sh
   npm run test:coverage
   ```

## Project Structure

- `contracts/` - Contains the Solidity smart contracts.
- `scripts/` - Contains the deployment scripts.
- `test/` - Contains the test scripts.
- `hardhat.config.ts` - Hardhat configuration file.
- `package.json` - Project dependencies and scripts.

## Dependencies

### Development Dependencies

- `@nomicfoundation/hardhat-chai-matchers`: ^2.0.0
- `@nomicfoundation/hardhat-ethers`: ^3.0.0
- `@nomicfoundation/hardhat-ignition`: ^0.15.0
- `@nomicfoundation/hardhat-ignition-ethers`: ^0.15.0
- `@nomicfoundation/hardhat-network-helpers`: ^1.0.0
- `@nomicfoundation/hardhat-toolbox`: ^5.0.0
- `@nomicfoundation/hardhat-verify`: ^2.0.0
- `@nomiclabs/hardhat-ethers`: ^2.2.3
- `@typechain/ethers-v6`: ^0.5.0
- `@typechain/hardhat`: ^9.0.0
- `@types/chai`: ^4.2.0
- `@types/mocha`: >=9.1.0
- `@types/node`: >=18.0.0
- `chai`: ^4.4.1
- `ethers`: ^6.13.1
- `hardhat`: ^2.22.5
- `hardhat-gas-reporter`: ^1.0.8
- `mocha`: ^10.4.0
- `solidity-coverage`: ^0.8.0
- `ts-node`: >=8.0.0
- `typechain`: ^8.3.0
- `typescript`: >=4.5.0

### Dependencies

- `@openzeppelin/contracts`: ^5.0.2

## Author

- DEGA ORG

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
