// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract WrappedToken is ERC20 {
    address public bridge;
    bool public initialized;

    string private tokenName;
    string private tokenSymbol;
    uint8 private tokenDecimals;

    error NotBridge();
    error AlreadyInitialized();
    error ZeroAddress();

    modifier onlyBridge() {
        if (msg.sender != bridge) revert NotBridge();
        _;
    }

    constructor() ERC20("WrappedToken", "WTOKEN") {}

    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address bridge_
    ) external {
        if (initialized) revert AlreadyInitialized();
        if (bridge_ == address(0)) revert ZeroAddress();
        initialized = true;
        tokenName = name_;
        tokenSymbol = symbol_;
        tokenDecimals = decimals_;
        bridge = bridge_;
    }

    function name() public view override returns (string memory) {
        return tokenName;
    }

    function symbol() public view override returns (string memory) {
        return tokenSymbol;
    }

    function decimals() public view override returns (uint8) {
        return tokenDecimals;
    }

    function mint(address to, uint256 amount) external onlyBridge {
        _mint(to, amount);
    }

    function burnFrom(address from, uint256 amount) external onlyBridge {
        _burn(from, amount);
    }
}
