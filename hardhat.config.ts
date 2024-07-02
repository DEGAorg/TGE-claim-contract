import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import { vars } from "hardhat/config";
import type { NetworkUserConfig } from "hardhat/types";

const PRIVATE_KEY: string = vars.get("PRIVATE_KEY");
const ETHERSCAN_API_KEY = vars.get("ETHERSCAN_API_KEY");


const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    bnb_testnet: { 
      url: `https://bsc-testnet.public.blastapi.io`, 
      accounts: [PRIVATE_KEY], 
    }, 
    bnb_mainnet: { 
      url: `https://binance.llamarpc.com`, 
      accounts: [PRIVATE_KEY], 
    }, 
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
  },
  sourcify: {
    enabled: true
  }
};

export default config;
