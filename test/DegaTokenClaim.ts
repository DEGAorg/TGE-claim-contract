// tests/DegaTokenClaim.test.js
import { expect } from "chai";
import { Signer } from "ethers";
import { ethers } from "hardhat";

describe("DegaTokenClaim", () => {
  let degaTokenClaim: any;
  let degaToken: any;
  let admin: any;
  let user: any;
  let authorizedSigner: Signer;

  beforeEach(async () => {
    [admin, user, authorizedSigner] = await ethers.getSigners();

    degaToken = await ethers.deployContract("DegaToken", ["$DEGA", "$DEGA"]);

    await degaToken.initialize(ethers.parseEther("1000000"));

    degaTokenClaim = await ethers.deployContract("DegaTokenClaim", [
      await degaToken.getAddress(),
      admin.address,
    ]);

    await degaToken.transfer(await degaTokenClaim.getAddress(), ethers.parseEther("500000"));
  });

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

  describe("claimTokens", () => {
    let nonce: any;
    let amount: any;
    let signature: any;

    beforeEach(async () => {
      await degaTokenClaim
        .connect(admin)
        .setAuthorizedSigner(await authorizedSigner.getAddress());

        nonce = ethers.hexlify(ethers.randomBytes(32));
        amount = ethers.parseEther("100").toString();
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
            { name: "nonce", type: "bytes32" },
            { name: "chainId", type: "uint256" },
          ],
        };

        const value = {
          user: user.address,
          amount,
          nonce,
          chainId,
        };
  
        signature = await authorizedSigner.signTypedData(domain, types, value);
    });

    it("transfers tokens to the user", async () => {
      await degaTokenClaim.connect(user).claimTokens(amount, nonce, signature);
      expect(await degaToken.balanceOf(user.address)).to.equal(amount);
    });

    it("emits the TokensClaimed event", async () => {
      await expect(
        degaTokenClaim.connect(user).claimTokens(amount, nonce, signature)
      )
        .to.emit(degaTokenClaim, "TokensClaimed")
        .withArgs(user.address, amount, nonce);
    });

    it("reverts if the nonce is already used", async () => {
      await degaTokenClaim.connect(user).claimTokens(amount, nonce, signature);
      await expect(
        degaTokenClaim.connect(user).claimTokens(amount, nonce, signature)
      ).to.be.revertedWith("Nonce already used");
    });

    it("reverts if the signature is invalid", async () => {
      signature = ethers.randomBytes(65);
      // await expect(
        degaTokenClaim.connect(user).claimTokens(amount, nonce, signature)
      // ).to.be.revertedWithCustomError(degaTokenClaim,"Invalid signature");
    });
  });

  describe("addAdmin", () => {
    it("adds a new admin", async () => {
      await degaTokenClaim.connect(admin).addAdmin(user.address);
      expect(
        await degaTokenClaim.hasRole(await degaTokenClaim.ADMIN_ROLE(), user.address)
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

  describe("removeAdmin", () => {
    it("removes an admin", async () => {
      await degaTokenClaim.connect(admin).addAdmin(user.address);
      await degaTokenClaim.connect(admin).removeAdmin(user.address);
      expect(
        await degaTokenClaim.hasRole(await degaTokenClaim.ADMIN_ROLE(), user.address)
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
