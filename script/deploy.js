// This script deploys the DegaToken and DegaTokenClaim contracts.

const path = require("path");

async function main() {
  // Check for the Hardhat Network
  if (network.name === "hardhat") {
    console.warn(
      "You are trying to deploy a contract to the Hardhat Network, which " +
        "gets automatically created and destroyed every time. Use the Hardhat " +
        "option '--network localhost'"
    );
  }

  // Get the deployer account
  const [deployer] = await ethers.getSigners();
  const deployerAddress = await deployer.getAddress();
  console.log("Deploying the contracts with the account:", deployerAddress);

  console.log(
    "Account balance:",
    ethers.formatEther(await ethers.provider.getBalance(deployerAddress))
  );

  // DegaToken ERC20 Address
  const degaToken = "0x9f4Fb26B94125D2f1a1dFf28dd63596878f2f7F2";
  
  const adminAddress = "0xC5492384195bD95E73e2A1a7D0011bAb122F6C42";

// Deploy the DegaTokenClaim contract
const DegaTokenClaim = await ethers.getContractFactory("DegaTokenClaim");
console.log("Contract factory obtained");

try {
  const degaTokenClaim = await DegaTokenClaim.deploy(degaToken, adminAddress);
  console.log("Deploy transaction sent");
  await degaTokenClaim.waitForDeployment();
  console.log("DegaTokenClaim deployed to:", degaTokenClaim.address);

  // Verify the contracts on Etherscan
  await hre.run("verify:verify", {
    address: degaTokenClaim.address,
    constructorArguments: [degaToken, adminAddress],
  });

  console.log("\nContracts Verified");

  // Save the contract's artifacts and address in the frontend directory
  saveFrontendFiles(degaToken, degaTokenClaim);
} catch (error) {
  console.error("Error deploying the contract:", error);
}
}

/**
 * @notice Save the contract artifacts and addresses to the frontend directory.
 * @param {Object} degaToken The deployed DegaToken contract instance.
 * @param {Object} degaTokenClaim The deployed DegaTokenClaim contract instance.
 */
function saveFrontendFiles(degaToken, degaTokenClaim) {
  const fs = require("fs");
  const contractsDir = path.join(__dirname, "..", "frontend", "src", "contracts");

  if (!fs.existsSync(contractsDir)) {
    fs.mkdirSync(contractsDir);
  }

  fs.writeFileSync(
    path.join(contractsDir, "contract-address.json"),
    JSON.stringify({
      DegaToken: degaToken,
      DegaTokenClaim: degaTokenClaim.address
    }, undefined, 2)
  );

  const DegaTokenClaimArtifact = artifacts.readArtifactSync("DegaTokenClaim");

  fs.writeFileSync(
    path.join(contractsDir, "DegaTokenClaim.json"),
    JSON.stringify(DegaTokenClaimArtifact, null, 2)
  );
}

main()
 .then(() => process.exit(0))
 .catch((error) => {
    console.error(error);
    process.exit(1);
  });
