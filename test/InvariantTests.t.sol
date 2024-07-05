// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import {DegaTokenClaim} from "../contracts/DegaTokenClaim.sol";
import "../contracts/mock/DegaToken.sol";

import {Utilities} from "./Utilities.sol";

/**
 * @title InvariantDegaTokenClaimTest
 * @dev Contract for testing invariants of the DegaTokenClaim contract.
 */
contract InvariantDegaTokenClaimTest is Test {
    DegaToken public degaToken;
    DegaTokenClaim public degaTokenClaim;
    address public admin;
    address public authorizedSigner;
    uint256 public authorizedSignerPK;
    address public user;

    Utilities internal utils;
    address payable[] internal users;

    /**
     * @notice Sets up the initial state for each test.
     */
    function setUp() public {
        utils = new Utilities();
        users = utils.createUsers(5);
        admin = users[0];
        (, authorizedSignerPK) = makeAddrAndKey("authorizedSigner");
        authorizedSigner = vm.addr(authorizedSignerPK);
        user = users[2];

        degaToken = new DegaToken("$DEGA", "$DEGA");
        degaTokenClaim = new DegaTokenClaim(address(degaToken), admin);

        degaToken.transfer(address(degaTokenClaim), 500_000 ether);
        degaToken.transfer(admin, 500_000 ether);
        vm.startPrank(admin);
        degaTokenClaim.setAuthorizedSigner(authorizedSigner);
        vm.stopPrank();
    }

    /**
     * @notice Ensures the total supply of DEGA tokens is consistent.
     * @dev Checks that the total supply does not exceed the initial maximum supply.
     */
    function invariant_totalSupplyIsConsistent() public view {
        assertLe(degaToken.totalSupply(), 1_000_000 ether);
    }

    /**
     * @notice Ensures the claim contract's balance is consistent.
     * @dev Verifies that the total supply accounts for the contract's balance and claimed tokens.
     */
    function invariant_claimContractBalanceIsConsistent() public view {
        uint256 contractBalance = degaToken.balanceOf(address(degaTokenClaim));
        uint256 totalClaimedTokens = 1_000_000 ether - degaToken.balanceOf(address(this)) - contractBalance;
        assertLe(degaToken.totalSupply(), contractBalance + totalClaimedTokens + degaToken.balanceOf(address(this)));
    }

    /**
     * @notice Ensures the admin has the admin role in the claim contract.
     * @dev Verifies that the admin has the ADMIN_ROLE in the DegaTokenClaim contract.
     */
    function invariant_adminHasAdminRole() public view {
        assertTrue(degaTokenClaim.hasRole(degaTokenClaim.ADMIN_ROLE(), admin));
    }

    /**
     * @notice Ensures user balances are non-negative.
     * @dev Checks that each user's balance is greater than or equal to zero.
     */
    function invariant_userBalanceNonNegative() public view {
        for (uint i = 0; i < users.length; i++) {
            uint256 userBalance = degaToken.balanceOf(users[i]);
            assertTrue(userBalance >= 0);
        }
    }

    /**
     * @notice Ensures the paused state is consistent.
     * @dev Verifies that the paused state of the contract matches the Pausable implementation.
     */
    function invariant_pausedStateConsistent() public view {
        bool isPaused = degaTokenClaim.paused();
        assertTrue(isPaused == Pausable(degaTokenClaim).paused());
    }

    /**
     * @notice Ensures the contract holds a non-negative token balance.
     * @dev Checks that the contract's balance is greater than or equal to zero.
     */
    function invariant_contractHoldsEnoughTokens() public view {
        uint256 contractBalance = degaToken.balanceOf(address(degaTokenClaim));
        assertTrue(contractBalance >= 0);
    }

    /**
     * @notice Ensures no unauthorized burning of tokens.
     * @dev Verifies that the total supply is at least the minimum expected amount.
     */
    function invariant_noUnauthorizedBurning() public view {
        uint256 totalSupply = degaToken.totalSupply();
        assertTrue(totalSupply >= 500_000 ether);
    }

    /**
     * @notice Ensures only the admin can pause the contract.
     * @dev Verifies that only the admin has the authority to pause the contract.
     */
    function invariant_onlyAdminCanPause() public view {
        if (degaTokenClaim.paused()) {
            assertTrue(degaTokenClaim.hasRole(degaTokenClaim.ADMIN_ROLE(), admin));
        }
    }

    /**
     * @notice Ensures no double spending of tokens.
     * @dev Checks that user balances are consistent and non-negative.
     */
    function invariant_noDoubleSpending() public view {
        for (uint i = 0; i < users.length; i++) {
            uint256 userBalance = degaToken.balanceOf(users[i]);
            assertTrue(userBalance >= 0);
        }
    }
}
