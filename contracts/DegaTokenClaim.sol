// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title DegaTokenClaim
 * @dev Contract to manage the claim of DEGA tokens using an authorized signature mechanism. 
 * This contract allows users to claim DEGA tokens by providing a valid signature from an authorized signer.
 * The contract includes the following features:
 * - Admin role management to set and update authorized signers.
 * - Signature-based token claiming process to ensure secure and authorized distribution of tokens.
 * - Nonce management to prevent replay attacks.
 * - Pausable functionality to handle emergency situations, allowing admins to pause and unpause the contract.
 *
 * The contract makes use of the following OpenZeppelin libraries:
 * - AccessControl for role-based access management.
 * - Pausable for pausing and unpausing the contract.
 * - EIP712 for structured data hashing and signing.
 * - ECDSA for Elliptic Curve Digital Signature Algorithm operations.
 */
contract DegaTokenClaim is AccessControlDefaultAdminRules, Pausable, EIP712 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    IERC20 public degaToken;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // Mapping to store used uids for each address
    mapping(address => mapping(bytes32 => bool)) private usedUids;

    /// Address authorized to sign the claims
    address public authorizedSigner;

    bytes32 private constant CLAIM_TYPEHASH =
        keccak256("Claim(address user,uint256 amount,bytes32 uid)");

    /**
     * @dev Emitted when tokens are claimed.
     * @param user The address of the user claiming the tokens.
     * @param amount The amount of tokens claimed.
     * @param uid The uid used for the claim.
     */
    event TokensClaimed(address indexed user, uint256 amount, bytes32 uid);

    /**
     * @dev Emitted when the authorized signer is updated.
     * @param newSigner The address of the new authorized signer.
     */
    event SignerUpdated(address indexed newSigner);

    /**
     * @dev Emitted when a new admin is added.
     * @param newAdmin The address of the new admin.
     */
    event AdminAdded(address indexed newAdmin);

    /**
     * @dev Emitted when an admin is removed.
     * @param admin The address of the removed admin.
     */
    event AdminRemoved(address indexed admin);

    /**
     * @dev Constructor for the DegaTokenClaim contract.
     * @param _tokenAddress The address of the DEGA token contract.
     * @param _initialAdmin The address of the initial admin.
     */
    constructor(address _tokenAddress, address _initialAdmin) 
    AccessControlDefaultAdminRules(2, _initialAdmin) 
    EIP712("DegaTokenClaim", "1") {
        degaToken = IERC20(_tokenAddress);
    }

    /**
     * @notice Set the authorized signer.
     * @dev Only callable by accounts with the ADMIN_ROLE.
     * @param _signer The address of the new authorized signer.
     */
    function setAuthorizedSigner(address _signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        authorizedSigner = _signer;
        emit SignerUpdated(_signer);
    }

    /**
     * @notice Claim tokens with a valid signature.
     * @param _amount The amount of tokens to claim.
     * @param _uid The unique identifier to prevent replay attacks.
     * @param _signature The signature from the authorized signer.
     */
    function claimTokens(uint256 _amount, bytes32 _uid, bytes calldata _signature) external whenNotPaused {
        require(authorizedSigner != address(0), "Invalid Authorized Signer Address");
        
        // Ensure the uid has not been used by this sender
        require(!usedUids[msg.sender][_uid], "UID has already been used");

        require(_amount > 0, "Amount must be greater than zero");
        require(degaToken.balanceOf(address(this)) >= _amount, "Insufficient contract balance");
        
        bytes32 structHash = keccak256(abi.encode(
            CLAIM_TYPEHASH,
            msg.sender,
            _amount,
            _uid
        ));

        bytes32 digest = _hashTypedDataV4(structHash);
        
        address signer = ECDSA.recover(digest, _signature);

        require(signer == authorizedSigner, "Invalid signature");

        usedUids[msg.sender][_uid] = true;
        require(degaToken.transfer(msg.sender, _amount), "Token transfer failed");

        emit TokensClaimed(msg.sender, _amount, _uid);
    }

    /**
     * @notice Add a new admin.
     * @dev Only callable by accounts with the DEFAULT_ADMIN_ROLE.
     * @param _admin The address of the new admin.
     */
    function addAdmin(address _admin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(ADMIN_ROLE, _admin);
        emit AdminAdded(_admin);
    }

    /**
     * @notice Remove an admin.
     * @dev Only callable by accounts with the DEFAULT_ADMIN_ROLE.
     * @param _admin The address of the admin to remove.
     */
    function removeAdmin(address _admin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(ADMIN_ROLE, _admin);
        emit AdminRemoved(_admin);
    }

    /**
     * @notice Pause the contract.
     * @dev Only callable by accounts with the ADMIN_ROLE.
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
        emit Paused(msg.sender);
    }

    /**
     * @notice Unpause the contract.
     * @dev Only callable by accounts with the ADMIN_ROLE.
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
        emit Unpaused(msg.sender);
    }
}
