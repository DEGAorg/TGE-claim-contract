// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DegaTokenClaim} from "../contracts/DegaTokenClaim.sol";
import "../contracts/mock/DegaToken.sol";

import {Utilities} from "./Utilities.sol";

contract FuzzClaimTokensTest is Test {
    DegaToken public degaToken;
    DegaTokenClaim public degaTokenClaim;
    address public admin;
    address public authorizedSigner;
    uint256 public authorizedSignerPK;
    uint256 public jhonDoePK;
    address public user;

    Utilities internal utils;
    address payable[] internal users;

    bytes32 private constant CLAIM_TYPEHASH =
        keccak256("Claim(address user,uint256 amount,bytes32 nonce,uint256 chainId)");

    function setUp() public {
        utils = new Utilities();
        users = utils.createUsers(5);
        admin = users[0];
        (, authorizedSignerPK) = makeAddrAndKey("authorizedSigner");
        (, jhonDoePK) = makeAddrAndKey("JhonDoe");
        authorizedSigner = vm.addr(authorizedSignerPK);
        user = users[2];

        degaToken = new DegaToken("$DEGA", "$DEGA");
        degaTokenClaim = new DegaTokenClaim(address(degaToken), admin);

        degaToken.transfer(address(degaTokenClaim), 500_000 ether);
        vm.startPrank(admin);
        degaTokenClaim.setAuthorizedSigner(authorizedSigner);
        vm.stopPrank();
    }

    function _domainSeparatorV4() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("DegaTokenClaim")),
                keccak256(bytes("1")),
                block.chainid,
                address(degaTokenClaim)
            )
        );
    }

    function _hashTypedDataV4(bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }

    function testValidClaimTokens(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)));
        vm.assume(nonce != 0x0);

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                user,
                amount,
                nonce,
                block.chainid
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerPK, digest);
        bytes memory validSignature = abi.encodePacked(r, s, v);

        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        assertEq(degaToken.balanceOf(user), amount);
    }

     function testInvalidSignature(uint256 amount, bytes32 nonce) public {
       vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)));
        vm.assume(nonce != 0x0);

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                user,
                amount,
                nonce,
                block.chainid
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(jhonDoePK, digest); // Invalid signature
        bytes memory invalidSignature = abi.encodePacked(r, s, v); 

        vm.expectRevert("Invalid signature");
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, invalidSignature);
    }

    function testNonceReplayAttack(uint256 amount, bytes32 nonce) public {
      vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)));
        vm.assume(nonce != 0x0);

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                user,
                amount,
                nonce,
                block.chainid
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerPK, digest);
        bytes memory validSignature = abi.encodePacked(r, s, v);

        
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        
        // Claim twice using same signature 

        vm.expectRevert("Nonce already used");
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);

        vm.stopPrank();
    }

    function testClaimExceedingBalance(uint256 amount, bytes32 nonce) public {
        vm.assume(amount > degaToken.balanceOf(address(degaTokenClaim)));
        vm.assume(nonce != 0x0);

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                user,
                amount,
                nonce,
                block.chainid
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerPK, digest);
        bytes memory validSignature = abi.encodePacked(r, s, v);

        vm.expectRevert("Insufficient contract balance");
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        vm.stopPrank();
    }

}
