// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "../@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "../@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20Permit} from "../@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessageHashUtils} from "../@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "../@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title ICustomToken
 * @notice Minimal interface for CustomToken that only exposes the functions we need
 * @author NU Blockchain Technologies
 */
interface ICustomToken is IERC20, IERC20Permit {
    /**
     * @notice Burns a specified amount of tokens from the caller's balance.
     * @param amount The amount of tokens to burn.
     */
    function burn(uint256 amount) external;
}

/**
 * @title Withdrawal Contract
 * @notice Handles secure token withdrawals with AML verification and permit functionality.
 * @dev This contract provides a secure way to withdraw tokens from the contract
 @author NU Blockchain Technologies
 */
contract Withdrawal is Initializable, AccessControlUpgradeable {
    using SafeERC20 for ICustomToken;

    // --- Constants ---

    /// @notice Role for burning locked tokens.
    bytes32 public constant BURN_ADMIN_ROLE = keccak256("BURN_ADMIN_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");

    // --- State Variables ---

    /// @notice The token being withdrawn and burned withdrawn from this contract.
    ICustomToken public shareToken;
    /// @notice The address of the payment token, used for logging purposes.
    address public paymentToken;
    /// @notice The address of the trusted signer for AML (Anti-Money Laundering) checks.
    address public amlSigner;
    /// @notice A mapping to prevent the reuse of AML signatures.
    mapping(bytes32 => bool) public usedSignatures;

    // --- Errors ---

    error InvalidAddress(string); // dev: Address cannot be zero
    error AmountMustBeGreaterThanZero(); // dev: Amount must be greater than zero
    error InsufficientBalance(); // dev: Contract does not have enough tokens to burn
    error AmlSignatureExpired(); // dev: AML signature has expired
    error AmlSignatureAlreadyUsed(); // dev: AML signature has already been used
    error InvalidAmlSignature(); // dev: The AML signature is invalid
    error InvalidAmlSigner(); // dev: The AML signer is invalid
    error InvalidMintTransactionHash(); // dev: The mint transaction hash is invalid

    // --- Events ---

    /**
     * @notice Emitted when a user withdraws tokens.
     * @param shareTokenAddress The address of the withdrawal token.
     * @param paymentTokenAddress The address of the payment token.
     * @param amlSignerAddress The address of the AML signer.
     */
    event WithdrawalInitialized(address shareTokenAddress, address paymentTokenAddress, address amlSignerAddress);

    /**
     * @notice Emitted when a user withdraws tokens.
     * @param user The address of the user who initiated the withdrawal.
     * @param amount The amount of tokens withdrawn.
     * @param shareToken The address of the shared token associated with the withdrawal.
     * @param paymentToken The address of the payment token associated with the withdrawal.
     */
    event Withdraw(address indexed user, uint256 amount, address shareToken, address paymentToken);

    // --- Initializer ---

    /**
     * @notice Initializes the contract with the provided token addresses and AML signer.
     * @dev Can only be called once during contract deployment.
     * @param _shareTokenAddress The address of the token that can be withdrawn.
     * @param _paymentTokenAddress The address of the payment token for logging purposes.
     * @param _amlSignerAddress The address of the trusted AML signer.
     * @param burnAdminAddress The address of the user who can manage the burn role.
     */
    function initialize(
        address _shareTokenAddress,
        address _paymentTokenAddress,
        address _amlSignerAddress,
        address burnAdminAddress
    ) external initializer {
        __AccessControl_init();

        if (_shareTokenAddress == address(0)) revert InvalidAddress("Invalid withdrawal token");
        if (_paymentTokenAddress == address(0)) revert InvalidAddress("Invalid payment token");
        if (_amlSignerAddress == address(0)) revert InvalidAddress("Invalid AML signer");

        shareToken = ICustomToken(_shareTokenAddress);
        paymentToken = _paymentTokenAddress;
        amlSigner = _amlSignerAddress;

        _setRoleAdmin(BURN_ROLE, BURN_ADMIN_ROLE);
        _grantRole(BURN_ADMIN_ROLE, burnAdminAddress);

        emit WithdrawalInitialized(_shareTokenAddress, _paymentTokenAddress, _amlSignerAddress);
    }

    // --- Public Functions ---

    /**
     * @notice Allows a user to withdraw tokens after passing an AML check.
     * @dev The function verifies the AML signature and deadline before processing the withdrawal.
     * @param _amount The amount of tokens to withdraw.
     * @param _amlSignature The signature from the AML signer.
     * @param _amlDeadline The expiration timestamp for the AML signature.
     */
    function withdraw(uint256 _amount, bytes calldata _amlSignature, uint256 _amlDeadline) external {
        if (_amount == 0) revert AmountMustBeGreaterThanZero();

        bytes32 messageHash = _getMessageHash(_amount, _amlDeadline);
        _verifyAML(messageHash, _amlSignature, _amlDeadline);

        _doWithdraw(_amount);
    }

    /**
     * @notice Allows a user to withdraw tokens using a permit, avoiding the need for a separate approval transaction.
     * @dev Combines permit functionality with AML checks for gas-efficient withdrawals.
     * @param _amount The amount of tokens to withdraw.
     * @param _amlSignature The signature from the AML signer.
     * @param _amlDeadline The expiration timestamp for the AML signature.
     * @param _permitDeadline The expiration timestamp for the permit signature.
     * @param _v The recovery byte of the permit signature.
     * @param _r First 32 bytes of the permit signature.
     * @param _s Second 32 bytes of the permit signature.
     */
    function withdrawWithPermit(
        uint256 _amount,
        bytes calldata _amlSignature,
        uint256 _amlDeadline,
        uint256 _permitDeadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external {
        if (_amount == 0) revert AmountMustBeGreaterThanZero();

        bytes32 messageHash = _getMessageHash(_amount, _amlDeadline);
        _verifyAML(messageHash, _amlSignature, _amlDeadline);

        shareToken.permit(msg.sender, address(this), _amount, _permitDeadline, _v, _r, _s);

        _doWithdraw(_amount);
    }

    // --- Private Helper Functions ---

    /**
     * @notice Handles the withdrawal logic by transferring tokens from the sender to this contract.
     * @param _amount The amount of tokens to withdraw.
     */
    function _doWithdraw(uint256 _amount) private {
        shareToken.safeTransferFrom(msg.sender, address(this), _amount);

        emit Withdraw(msg.sender, _amount, address(shareToken), paymentToken);
    }

    /**
     * @notice Emitted when tokens are burned from the contract.
     * @param amount The amount of tokens burned.
     * @param shareToken The shared token address.
     * @param burner The address that initiated the burn.
     * @param mintTransactionHash The hash of the mint transaction.
     */
    event TokensBurned(uint256 amount, address shareToken, address burner, string indexed mintTransactionHash);

    /**
     * @notice Burns a specified amount of tokens held by this contract.
     * @dev Only callable by addresses with the BURN_ROLE. This function is part of the
     * manual burn/mint model to maintain token supply across different chains.
     * @param amount The amount of tokens to burn. Must be greater than zero and not exceed
     * the contract's token balance.
     * @param mintTransactionHash The hash of the mint transaction.
     * @custom:requirements
     * - Caller must have BURN_ROLE
     * - `amount` must be greater than zero
     * - `mintTransactionHash` must not be empty
     * - Contract must have sufficient token balance
     */
    function burn(uint256 amount, string calldata mintTransactionHash) external onlyRole(BURN_ROLE) {
        if (amount == 0) revert AmountMustBeGreaterThanZero();
        if (bytes(mintTransactionHash).length == 0) revert InvalidMintTransactionHash();

        // Ensure the contract has enough tokens to burn
        uint256 contractBalance = shareToken.balanceOf(address(this));
        if (amount > contractBalance) revert InsufficientBalance();

        // Burn the tokens using the CustomToken's burnAuthorized function
        shareToken.burn(amount);

        emit TokensBurned(amount, address(shareToken), msg.sender, mintTransactionHash);
    }

    /**
     * @notice Internal function to verify the AML signature.
     * @dev This function is called by the public deposit and depositWithPermit functions.
     * @param messageHash The hash of the message to verify.
     * @param _signature The signature to verify.
     * @param _deadline The expiration timestamp for the signature.
     */
    function _verifyAML(bytes32 messageHash, bytes calldata _signature, uint256 _deadline) private {
        if (block.timestamp > _deadline) revert AmlSignatureExpired();
        if (usedSignatures[messageHash]) revert AmlSignatureAlreadyUsed();

        bytes32 ethSignedHash = MessageHashUtils.toTypedDataHash(_getDomainSeparator(), messageHash);
        address recoveredSigner = ECDSA.recover(ethSignedHash, _signature);

        if (recoveredSigner == address(0)) revert InvalidAmlSignature();
        if (recoveredSigner != amlSigner) revert InvalidAmlSigner();

        usedSignatures[messageHash] = true;
    }

    /**
     * @notice Returns the domain separator for the current chain.
     */
    function _getDomainSeparator() private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("Withdrawal"),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }

    /**
     * @notice Calculates the hash of the struct using abi.encode (standard EIP-712).
     */
    function _getMessageHash(uint256 _amount, uint256 _deadline) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("Withdraw(address sender,uint256 amount,uint256 deadline)"),
                    msg.sender,
                    _amount,
                    _deadline
                )
            );
    }
}
