// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import {DegaTokenClaim} from "../contracts/DegaTokenClaim.sol";
import "../contracts/mock/DegaToken.sol";

import {Utilities} from "./Utilities.sol";

/**
 * @title FuzzClaimTokensTest
 * @dev Contract for fuzz testing the DegaTokenClaim contract.
 */
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

    event TokensClaimed(address indexed user, uint256 amount, bytes32 nonce);
    event SignerUpdated(address indexed newSigner);
    event AdminAdded(address indexed newAdmin);
    event AdminRemoved(address indexed admin);

    /**
     * @notice Sets up the initial state for each test.
     */
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

    /**
     * @dev Generates the EIP-712 domain separator for the DegaTokenClaim contract.
     * @return The domain separator.
     */
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

    /**
     * @dev Generates the EIP-712 hash for a given struct hash.
     * @param structHash The struct hash to be hashed.
     * @return The hashed data.
     */
    function _hashTypedDataV4(bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }

    /**
     * @dev Generates the digest for a claim.
     * @param userAddress The address of the user.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     * @return The claim digest.
     */
    function getDigest(address userAddress, uint256 amount, bytes32 nonce) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                userAddress,
                amount,
                nonce,
                block.chainid
            )
        );
        return _hashTypedDataV4(structHash);
    }

    /**
     * @dev Generates the signature for a given digest.
     * @param pk The private key used to sign the digest.
     * @param digest The digest to be signed.
     * @return The generated signature.
     */
    function getSignature(uint256 pk, bytes32 digest) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Tests the valid claiming of tokens.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testValidClaimTokens(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit TokensClaimed(user, amount, nonce);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        assertEq(degaToken.balanceOf(user), amount);
    }

    /**
     * @notice Tests valid token claims for multiple users.
     * @param randomUser The address of a random user.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testValidClaimTokensForMultipleUsers(address randomUser, uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);
        vm.assume(randomUser != address(0));

        bytes32 digest = getDigest(randomUser, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(randomUser);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        assertEq(degaToken.balanceOf(randomUser), amount);
    }

    /**
     * @notice Tests claiming tokens to the zero address.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testClaimZeroAddress(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(address(0x0), amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(address(0x0));
        vm.expectRevert();
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
    }

    /**
     * @notice Tests claiming tokens with an invalid signature.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testInvalidSignature(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory invalidSignature = getSignature(jhonDoePK, digest);

        vm.expectRevert("Invalid signature");
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, invalidSignature);
    }

    /**
     * @notice Tests the replay attack protection by using the same nonce twice.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testNonceReplayAttack(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);

        vm.expectRevert("Nonce already used");
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
    }

    /**
     * @notice Tests claiming tokens exceeding the contract balance.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testClaimExceedingBalance(uint256 amount, bytes32 nonce) public {
        vm.assume(amount > degaToken.balanceOf(address(degaTokenClaim)));
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.expectRevert("Insufficient contract balance");
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
    }

    /**
     * @notice Tests pausing and unpausing the contract.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testPauseAndUnpause(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        vm.startPrank(admin);
        degaTokenClaim.pause();
        vm.stopPrank();

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        bytes4 expectedSelector = Pausable.EnforcedPause.selector;
        vm.expectRevert(expectedSelector);
        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);

        vm.startPrank(admin);
        degaTokenClaim.unpause();
        vm.stopPrank();

        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        assertEq(degaToken.balanceOf(user), amount);
    }

    /**
     * @notice Tests changing the authorized signer.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testChangeAuthorizedSigner(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        address newSigner;
        uint256 newSignerPK;
        (, newSignerPK) = makeAddrAndKey("newSigner");
        newSigner = vm.addr(newSignerPK);

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit SignerUpdated(newSigner);
        degaTokenClaim.setAuthorizedSigner(newSigner);
        vm.stopPrank();

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(newSignerPK, digest);

        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
        assertEq(degaToken.balanceOf(user), amount);
    }

    /**
     * @notice Tests reusing a nonce by different users.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testInvalidNonceReuseByDifferentUser(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(user);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);

        address anotherUser = users[3];
        vm.prank(anotherUser);
        vm.expectRevert("Nonce already used");
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
    }

    /**
     * @notice Tests multiple users claiming different nonces.
     * @param amount1 The amount of tokens to claim for the first user.
     * @param amount2 The amount of tokens to claim for the second user.
     * @param nonce1 The unique nonce for the first user's claim.
     * @param nonce2 The unique nonce for the second user's claim.
     */
    function testMultipleUsersClaimingDifferentNonces(uint256 amount1, uint256 amount2, bytes32 nonce1, bytes32 nonce2) public {
        address user1 = users[2];
        address user2 = users[3];

        vm.assume(amount1 < degaToken.balanceOf(address(degaTokenClaim)) / 2 && amount1 > 0);
        vm.assume(amount2 < degaToken.balanceOf(address(degaTokenClaim)) / 2 && amount2 > 0);
        vm.assume(nonce1 != 0x0 && nonce2 != 0x0);
        vm.assume(user1 != user2);

        bytes32 digest1 = getDigest(user1, amount1, nonce1);
        bytes32 digest2 = getDigest(user2, amount2, nonce2);

        bytes memory validSignature1 = getSignature(authorizedSignerPK, digest1);
        bytes memory validSignature2 = getSignature(authorizedSignerPK, digest2);

        vm.prank(user1);
        degaTokenClaim.claimTokens(amount1, nonce1, validSignature1);
        assertEq(degaToken.balanceOf(user1), amount1);

        vm.prank(user2);
        degaTokenClaim.claimTokens(amount2, nonce2, validSignature2);
        assertEq(degaToken.balanceOf(user2), amount2);
    }

    /**
     * @notice Tests claiming tokens with a zero amount.
     * @param nonce The unique nonce for the claim.
     */
    function testClaimWithZeroAmount(bytes32 nonce) public {
        uint256 amount = 0;
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(user);
        vm.expectRevert("Amount must be greater than zero");
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
    }

    /**
     * @notice Tests adding and removing an admin.
     * @param newAdmin The address of the new admin.
     */
    function testAddAndRemoveAdmin(address newAdmin) public {
        vm.assume(newAdmin != address(0));
        vm.assume(newAdmin != admin);

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit AdminAdded(newAdmin);
        degaTokenClaim.addAdmin(newAdmin);
        vm.stopPrank();

        assertTrue(degaTokenClaim.hasRole(degaTokenClaim.ADMIN_ROLE(), newAdmin));

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit AdminRemoved(newAdmin);
        degaTokenClaim.removeAdmin(newAdmin);
        vm.stopPrank();

        assertFalse(degaTokenClaim.hasRole(degaTokenClaim.ADMIN_ROLE(), newAdmin));
    }

    /**
     * @notice Tests that claiming tokens emits the appropriate events.
     * @param amount The amount of tokens to claim.
     * @param nonce The unique nonce for the claim.
     */
    function testClaimEmitEvents(uint256 amount, bytes32 nonce) public {
        vm.assume(amount < degaToken.balanceOf(address(degaTokenClaim)) && amount > 0);
        vm.assume(nonce != 0x0);

        bytes32 digest = getDigest(user, amount, nonce);
        bytes memory validSignature = getSignature(authorizedSignerPK, digest);

        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit TokensClaimed(user, amount, nonce);
        degaTokenClaim.claimTokens(amount, nonce, validSignature);
    }

    /**
     * @notice Tests that only an admin can set the authorized signer.
     * @param nonAdmin The address of a non-admin user.
     * @param newSigner The address of the new authorized signer.
     */
    function testOnlyAdminCanSetAuthorizedSigner(address nonAdmin, address newSigner) public {
        vm.assume(nonAdmin != admin);
        vm.assume(newSigner != address(0));

        vm.expectRevert();
        vm.prank(nonAdmin);
        degaTokenClaim.setAuthorizedSigner(newSigner);

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit SignerUpdated(newSigner);
        degaTokenClaim.setAuthorizedSigner(newSigner);
        vm.stopPrank();
    }

    /**
     * @notice Tests that only an admin can pause and unpause the contract.
     * @param nonAdmin The address of a non-admin user.
     */
    function testOnlyAdminCanPauseAndUnpause(address nonAdmin) public {
        vm.assume(nonAdmin != admin);

        vm.prank(nonAdmin);
        vm.expectRevert();
        degaTokenClaim.pause();

        vm.startPrank(admin);
        degaTokenClaim.pause();
        vm.stopPrank();

        vm.prank(nonAdmin);
        vm.expectRevert();
        degaTokenClaim.unpause();

        vm.startPrank(admin);
        degaTokenClaim.unpause();
        vm.stopPrank();
    }
}
