// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "../@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "../@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {AccessControl} from "../@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title Custom ERC20 Token
 * @notice Minimal ERC20 token with mint and burn functionality.
 * @author NU Blockchain Technologies
 */
contract CustomToken is ERC20, ERC20Permit, AccessControl {
    /**
     * @notice Role for minting tokens.
     */
    bytes32 public constant MINTER_ADMIN_ROLE = keccak256("MINTER_ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /**
     * @notice Custom decimals for the token.
     */
    uint8 private _customDecimals;

    /**
     * @notice Event emitted when tokens are burned.
     * @param from The address that burned the tokens.
     * @param amount The amount of tokens burned.
     */
    event TokensBurned(address indexed from, uint256 amount);

    /**
     * @notice Initializes the contract with the provided token name, symbol, admin, and decimals.
     * @param _name The name of the token.
     * @param _symbol The symbol of the token.
     * @param _admin The address of the admin.
     * @param _decimals The number of decimals for the token.
     */
    constructor(
        string memory _name,
        string memory _symbol,
        address _admin,
        uint8 _decimals
    ) ERC20(_name, _symbol) ERC20Permit(_name) {
        _customDecimals = _decimals;
        _setRoleAdmin(MINTER_ROLE, MINTER_ADMIN_ROLE);
        _grantRole(MINTER_ADMIN_ROLE, _admin);
    }

    /**
     * @notice Returns the number of decimals used by the token.
     * @return The number of decimals.
     */
    function decimals() public view override returns (uint8) {
        return _customDecimals;
    }

    /**
     * @notice Mints a specified amount of tokens to a specified address.
     * @param to The address to which the tokens will be minted.
     * @param amount The amount of tokens to mint.
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /**
     * @notice Burns a specified amount of tokens from the caller's balance.
     * @param amount The amount of tokens to burn.
     */
    function burn(uint256 amount) public virtual {
        _burn(_msgSender(), amount);
        emit TokensBurned(_msgSender(), amount);
    }

    /**
     * @notice Burns a specified amount of tokens from a specified address.
     * @dev The caller must have been approved to spend at least `amount` tokens on behalf of `account`.
     * @param account The address to burn tokens from.
     * @param amount The amount of tokens to burn.
     */
    function burnFrom(address account, uint256 amount) public virtual {
        _spendAllowance(account, _msgSender(), amount);
        _burn(account, amount);
        emit TokensBurned(account, amount);
    }
}
