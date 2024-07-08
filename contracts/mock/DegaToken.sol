// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract DegaToken is ERC20, ERC20Burnable {
    bool public mockFail = false;
    constructor(string memory name, string memory symbol)
        ERC20(name, symbol)
    {
         _mint(msg.sender, 1000000000000000 * 10 **18);
    }

    function transfer(address to, uint256 value) override public returns (bool) {
        require(!mockFail, "Mock fail is enabled");
        require(to != address(0), "ERC20: transfer to the zero address");
        _transfer(_msgSender(), to, value);
        return true;
    }

    function setMockFail(bool _mockFail) public {
        mockFail = _mockFail;
    }
}