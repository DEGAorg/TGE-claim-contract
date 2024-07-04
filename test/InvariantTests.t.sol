// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.24;

// import "forge-std/Test.sol";
// import "../contracts/DegaTokenClaim.sol";
// import "../contracts/mock/DegaToken.sol";

// contract InvariantTests is Test {
//   DegaToken public degaToken;
//     DegaTokenClaim public degaTokenClaim;
//     address public admin;
//     address public authorizedSigner;
//     address public user;

//     function setUp() public {
//         admin = address(this);
//         authorizedSigner = address(0x1234);
//         user = address(0x5678);

//         degaToken = new DegaToken("$DEGA", "$DEGA");
//         degaToken.initialize(1_000_000 ether);
//         degaTokenClaim = new DegaTokenClaim(address(degaToken), admin);

//         degaToken.transfer(address(degaTokenClaim), 500_000 ether);
//         degaTokenClaim.setAuthorizedSigner(authorizedSigner);
//     }

//     function invariantTokenBalanceNonNegative() public {
//         assert(degaToken.balanceOf(address(degaTokenClaim)) >= 0);
//     }

//     function invariantUsedNoncesIntegrity(bytes32 nonce) public {
//         if (degaTokenClaim.usedNonces(nonce)) {
//             // Ensure no other operations have reset this nonce
//             assert(degaTokenClaim.usedNonces(nonce));
//         }
//     }

//     function invariantTotalSupplyConstant() public {
//         uint256 initialSupply = 1_000_000 ether;
//         uint256 totalSupply = degaToken.totalSupply();
//         assert(totalSupply == initialSupply);
//     }

//     function invariantContractBalanceAfterClaim() public {
//         uint256 initialBalance = degaToken.balanceOf(address(degaTokenClaim));
//         // Simulate a claim
//         uint256 amount = 100 ether;
//         bytes32 nonce = keccak256(abi.encodePacked(block.timestamp));
//         (uint8 v, bytes32 r, bytes32 s) = vm.sign((authorizedSigner), keccak256(abi.encodePacked(user, amount, nonce, block.chainid)));
//         bytes memory signature = abi.encodePacked(r, s, v);

//         vm.prank(user);
//         degaTokenClaim.claimTokens(amount, nonce, signature);

//         // Check the invariant
//         uint256 finalBalance = degaToken.balanceOf(address(degaTokenClaim));
//         assert(finalBalance == initialBalance - amount);
//     }
// }
