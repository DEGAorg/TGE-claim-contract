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

## Domain Separator

### What is the Domain Separator?

The domain separator is a unique identifier used in the EIP-712 standard for typed structured data hashing and signing. It ensures that the signed data is specific to a particular contract and chain, preventing replay attacks on different contracts or chains.

In the `DegaTokenClaim` contract, the domain separator is used to generate a digest of the claim data, which is then signed by the authorized signer. This signed digest is submitted by the user to claim their tokens.

### How to Use the Domain Separator from a UI with ethers.js

To interact with the `DegaTokenClaim` contract from a UI and generate the necessary signature, you can follow these steps:

1. **Import ethers.js**:
   ```javascript
   import { ethers } from "ethers";
   ```

2. **Set up the provider and signer**:
   ```javascript
   const provider = new ethers.providers.Web3Provider(window.ethereum);
   const signer = provider.getSigner();
   ```

3. **Define the contract ABI and address**:
   ```javascript
   const degaTokenClaimAbi = [ /* ABI array */ ];
   const degaTokenClaimAddress = "0xYourContractAddress";
   const degaTokenClaimContract = new ethers.Contract(degaTokenClaimAddress, degaTokenClaimAbi, signer);
   ```

4. **Define the domain and types for EIP-712**:
   ```javascript
   const domain = {
     name: "DegaTokenClaim",
     version: "1",
     verifyingContract: degaTokenClaimAddress
   };

   const types = {
     Claim: [
       { name: "user", type: "address" },
       { name: "amount", type: "uint256" },
       { name: "uid", type: "bytes32" }
     ]
   };
   ```

5. **Create the claim message**:
   ```javascript
   const userAddress = await signer.getAddress();
   const amount = ethers.utils.parseEther("100"); // Amount to claim
   const uid = ethers.utils.hexlify(ethers.utils.randomBytes(32)); // Unique UID

   const message = {
     user: userAddress,
     amount: amount,
     uid: uid
   };
   ```

6. **Sign the message**:
   ```javascript
   const signature = await signer._signTypedData(domain, types, message);
   ```

7. **Send the transaction to claim tokens**:
   ```javascript
   const tx = await degaTokenClaimContract.claimTokens(amount, uid, signature);
   await tx.wait();
   console.log("Tokens claimed successfully!");
   ```

### Example Usage

Here's a complete example of how you can integrate this into a UI using ethers.js:

```javascript
import { ethers } from "ethers";

async function claimTokens() {
  const provider = new ethers.providers.Web3Provider(window.ethereum);
  const signer = provider.getSigner();

  const degaTokenClaimAbi = [ /* ABI array */ ];
  const degaTokenClaimAddress = "0xYourContractAddress";
  const degaTokenClaimContract = new ethers.Contract(degaTokenClaimAddress, degaTokenClaimAbi, signer);

  const domain = {
    name: "DegaTokenClaim",
    version: "1",
    verifyingContract: degaTokenClaimAddress
  };

  const types = {
    Claim: [
      { name: "user", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "uid", type: "bytes32" }
    ]
  };

  const userAddress = await signer.getAddress();
  const amount = ethers.utils.parseEther("100"); // Amount to claim
  const uid = ethers.utils.hexlify(ethers.utils.randomBytes(32)); // Unique UID

  const message = {
    user: userAddress,
    amount: amount,
    uid: uid
  };

  const signature = await signer._signTypedData(domain, types, message);

  const tx = await degaTokenClaimContract.claimTokens(amount, uid, signature);
  await tx.wait();
  console.log("Tokens claimed successfully!");
}

claimTokens().catch(console.error);
```

This example shows how to create a UI that interacts with the `DegaTokenClaim` contract, allowing a user to claim tokens by generating a signed message using the EIP-712 standard.

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
