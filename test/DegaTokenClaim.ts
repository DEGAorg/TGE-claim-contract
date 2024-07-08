// SPDX-License-Identifier: MIT
/**
 * @title DegaTokenClaim Contract Test Suite
 * @notice This suite tests the DegaTokenClaim smart contract using Hardhat and Chai.
 */

import { expect } from "chai";
import { Signer, ZeroAddress } from "ethers";
import { ethers } from "hardhat";

describe("DegaTokenClaim", () => {
  let degaTokenClaim: any;
  let degaToken: any;
  let admin: any;
  let user: any;
  let authorizedSigner: Signer;

  /**
   * @notice Before each test, deploy the DegaToken and DegaTokenClaim contracts, and set up the initial state.
   */
  beforeEach(async () => {
    [admin, user, authorizedSigner] = await ethers.getSigners();

    degaToken = await ethers.deployContract("DegaToken", ["$DEGA", "$DEGA"]);

    degaTokenClaim = await ethers.deployContract("DegaTokenClaim", [
      await degaToken.getAddress(),
      admin.address,
    ]);

    await degaToken.transfer(
      await degaTokenClaim.getAddress(),
      ethers.parseEther("500000")
    );
  });

  /**
   * @notice Test suite for the constructor of DegaTokenClaim.
   */
  describe("constructor", () => {
    it("sets the DEGA token address", async () => {
      expect(await degaTokenClaim.degaToken()).to.equal(
        await degaToken.getAddress()
      );
    });

    it("sets the initial admin", async () => {
      const isAdmin = await degaTokenClaim.hasRole(
        await degaTokenClaim.ADMIN_ROLE(),
        admin.address
      );
      expect(isAdmin).to.be.true;
    });
  });

  /**
   * @notice Test suite for the setAuthorizedSigner function of DegaTokenClaim.
   */
  describe("setAuthorizedSigner", () => {
    it("sets the authorized signer", async () => {
      await degaTokenClaim
        .connect(admin)
        .setAuthorizedSigner(await authorizedSigner.getAddress());
      expect(await degaTokenClaim.authorizedSigner()).to.equal(
        await authorizedSigner.getAddress()
      );
    });

    it("emits the SignerUpdated event", async () => {
      await expect(
        degaTokenClaim
          .connect(admin)
          .setAuthorizedSigner(await authorizedSigner.getAddress())
      )
        .to.emit(degaTokenClaim, "SignerUpdated")
        .withArgs(await authorizedSigner.getAddress());
    });

    it("reverts if not called by an admin", async () => {
      await expect(
        degaTokenClaim
          .connect(user)
          .setAuthorizedSigner(await authorizedSigner.getAddress())
      ).to.be.revertedWithCustomError(
        degaTokenClaim,
        "AccessControlUnauthorizedAccount"
      );
    });
  });

  /**
   * @notice Test suite for the claimTokens function of DegaTokenClaim.
   */
  describe("claimTokens", () => {
    let uid: any;
    let amount: any;
    let extraAmount: any;
    let signature: any;

    beforeEach(async () => {
      await degaTokenClaim
        .connect(admin)
        .setAuthorizedSigner(await authorizedSigner.getAddress());

      uid = ethers.hexlify(ethers.randomBytes(32));
      amount = ethers.parseEther("100").toString();
      extraAmount = ethers.parseEther("500001").toString();
      const chainId = (await ethers.provider.getNetwork()).chainId;

      const domain = {
        name: "DegaTokenClaim",
        version: "1",
        chainId,
        verifyingContract: await degaTokenClaim.getAddress(),
      };

      const types = {
        Claim: [
          { name: "user", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "uid", type: "bytes32" },
        ],
      };

      const value = {
        user: user.address,
        amount,
        uid,
      };

      signature = await authorizedSigner.signTypedData(domain, types, value);
    });

    it("transfers tokens to the user", async () => {
      await degaTokenClaim.connect(user).claimTokens(amount, uid, signature);
      expect(await degaToken.balanceOf(user.address)).to.equal(amount);
    });

    it("reverts if authorizedSigner is zero address", async () => {
      await degaTokenClaim.connect(admin).setAuthorizedSigner(ZeroAddress);
      await expect(
        degaTokenClaim.connect(user).claimTokens(amount, uid, signature)
      ).to.be.revertedWith("Invalid Authorized Signer Address");
    });

    it("reverts if exceeding balance", async () => {
      const chainId = (await ethers.provider.getNetwork()).chainId;
      uid = ethers.hexlify(ethers.randomBytes(32));

      const domain = {
        name: "DegaTokenClaim",
        version: "1",
        chainId,
        verifyingContract: await degaTokenClaim.getAddress(),
      };

      const types = {
        Claim: [
          { name: "user", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "uid", type: "bytes32" },
        ],
      };

      const value = {
        user: user.address,
        amount: extraAmount,
        uid,
      };

      signature = await authorizedSigner.signTypedData(domain, types, value);

      await expect(
        degaTokenClaim.connect(user).claimTokens(extraAmount, uid, signature)
      ).to.be.revertedWith("Insufficient contract balance");
    });

    it("emits the TokensClaimed event", async () => {
      await expect(
        degaTokenClaim.connect(user).claimTokens(amount, uid, signature)
      )
        .to.emit(degaTokenClaim, "TokensClaimed")
        .withArgs(user.address, amount, uid);
    });

    it("reverts if the uid is already used", async () => {
      await degaTokenClaim.connect(user).claimTokens(amount, uid, signature);
      await expect(
        degaTokenClaim.connect(user).claimTokens(amount, uid, signature)
      ).to.be.revertedWith("UID has already been used");
    });

    it("reverts if the signature is invalid", async () => {
      signature = ethers.randomBytes(0);
      await expect(
        degaTokenClaim.connect(user).claimTokens(amount, uid, signature)
      ).to.be.revertedWithCustomError(degaTokenClaim, "ECDSAInvalidSignatureLength");
    });
  });

  /**
   * @notice Test suite for the addAdmin function of DegaTokenClaim.
   */
  describe("addAdmin", () => {
    it("adds a new admin", async () => {
      await degaTokenClaim.connect(admin).addAdmin(user.address);
      expect(
        await degaTokenClaim.hasRole(
          await degaTokenClaim.ADMIN_ROLE(),
          user.address
        )
      ).to.be.true;
    });

    it("emits the AdminAdded event", async () => {
      await expect(degaTokenClaim.connect(admin).addAdmin(user.address))
        .to.emit(degaTokenClaim, "AdminAdded")
        .withArgs(user.address);
    });

    it("reverts if not called by the default admin", async () => {
      await expect(
        degaTokenClaim.connect(user).addAdmin(user.address)
      ).to.be.revertedWithCustomError(
        degaTokenClaim,
        "AccessControlUnauthorizedAccount"
      );
    });
  });

  /**
   * @notice Test suite for the removeAdmin function of DegaTokenClaim.
   */
  describe("removeAdmin", () => {
    it("removes an admin", async () => {
      await degaTokenClaim.connect(admin).addAdmin(user.address);
      await degaTokenClaim.connect(admin).removeAdmin(user.address);
      expect(
        await degaTokenClaim.hasRole(
          await degaTokenClaim.ADMIN_ROLE(),
          user.address
        )
      ).to.be.false;
    });

    it("emits the AdminRemoved event", async () => {
      await degaTokenClaim.connect(admin).addAdmin(user.address);
      await expect(degaTokenClaim.connect(admin).removeAdmin(user.address))
        .to.emit(degaTokenClaim, "AdminRemoved")
        .withArgs(user.address);
    });

    it("reverts if not called by the default admin", async () => {
      await expect(
        degaTokenClaim.connect(user).removeAdmin(user.address)
      ).to.be.revertedWithCustomError(
        degaTokenClaim,
        "AccessControlUnauthorizedAccount"
      );
    });
  });
});
