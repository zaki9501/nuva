// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "../../@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC4626Upgradeable} from "../../@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import {ERC20Upgradeable} from "../../@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {ERC20PermitUpgradeable} from "../../@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {Ownable2StepUpgradeable} from "../../@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "../../@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "../../@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "../../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "../../@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ECDSA} from "../../@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "../../@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title NuvaVault
 * @notice A professional-grade ERC4626 vault implementation.
 * @dev Features UUPS upgradeability, inflation attack protection via offsets, pausable operations, and multi-step ownership.
 * @author Nuva Finance
 */
contract NuvaVault is
    Initializable,
    ERC4626Upgradeable,
    ERC20PermitUpgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable
{
    // --- Custom Errors ---
    /// @notice Thrown when the provided asset address is invalid (zero address).
    error InvalidAsset();
    /// @notice Thrown when a caller is not authorized.
    error Unauthorized();
    error InvalidAmlSigner();
    error AmlSignatureExpired();
    error AmlSignatureAlreadyUsed();
    error InvalidAmlSignature();
    error AmlDeadlineTooLong();

    uint256 public constant MAX_DEADLINE = 24 hours;

    // --- State Variables ---
    mapping(address => bool) public authorizedCallers;

    /// @notice The address authorized to sign AML approvals.
    address public amlSigner;
    /// @notice Mapping to track used AML signatures to prevent replay attacks.
    mapping(bytes32 => bool) public usedSignatures;

    /**
     * @notice EIP-712 typehash for deposit authorization.
     */
    bytes32 private constant DEPOSIT_TYPEHASH =
        keccak256(
            "Deposit(address sender,uint256 assets,address receiver,uint256 deadline)"
        );

    /**
     * @notice EIP-712 typehash for redeem authorization.
     */
    bytes32 private constant REDEEM_TYPEHASH =
        keccak256(
            "Redeem(address sender,uint256 shares,address receiver,address owner,uint256 deadline)"
        );

    // --- Events ---
    event AuthorizedCallerAdded(address indexed caller);
    event AuthorizedCallerRemoved(address indexed caller);
    event AmlSignerUpdated(address oldSigner, address newSigner);

    // --- Modifiers ---
    modifier onlyAuthorized() {
        if (!authorizedCallers[msg.sender]) revert Unauthorized();
        _;
    }

    modifier onlyOwnerOrAuthorized() {
        if (owner() != msg.sender && !authorizedCallers[msg.sender])
            revert Unauthorized();
        _;
    }

    /**
     * @custom:oz-upgrades-unsafe-allow constructor
     * @notice Constructor to disable initializers for the logic contract.
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Do not allow the owner to renounce ownership outside of the two step process.
     */
    function renounceOwnership() public pure override {
        revert("Ownership renouncement disabled");
    }

    /**
     * @notice Initializes the vault with asset and naming information.
     * @param _asset The underlying asset of the vault.
     * @param _name The name of the vault token.
     * @param _symbol The symbol of the vault token.
     * @param _initialOwner The address of the initial contract owner.
     */
    function initialize(
        address _asset,
        string memory _name,
        string memory _symbol,
        address _initialOwner,
        address _amlSigner
    ) public initializer {
        if (_asset == address(0)) revert InvalidAsset();
        if (_amlSigner == address(0)) revert InvalidAmlSigner();

        __ERC20_init(_name, _symbol);
        __ERC4626_init(IERC20(_asset));
        __ERC20Permit_init(_name);
        __Ownable_init_unchained(_initialOwner);
        __Ownable2Step_init_unchained();
        __UUPSUpgradeable_init();
        __Pausable_init();

        amlSigner = _amlSigner;
    }

    // --- Admin Functions ---

    /**
     * @notice Pauses vault operations (deposits, mints, withdrawals, redemptions).
     * @notice ERC20 transfers are intentionally permitted during pause to preserve secondary market access.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpauses vault operations.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Adds an authorized caller.
     * @param caller The address to authorize.
     */
    function addAuthorizedCaller(
        address caller
    ) external onlyOwnerOrAuthorized {
        authorizedCallers[caller] = true;
        emit AuthorizedCallerAdded(caller);
    }

    /**
     * @notice Removes an authorized caller.
     * @param caller The address to remove from authorization.
     */
    function removeAuthorizedCaller(
        address caller
    ) external onlyOwnerOrAuthorized {
        authorizedCallers[caller] = false;
        emit AuthorizedCallerRemoved(caller);
    }

    /**
     * @notice Authorizes a contract upgrade. Only callable by the owner.
     * @param newImplementation The address of the new implementation.
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // --- Overrides ---

    /**
     * @notice Deposits assets into the vault. Protected by whenNotPaused and onlyAuthorized.
     * @param assets Amount of assets to deposit.
     * @param receiver Address to receive the shares.
     * @return shares Amount of shares minted.
     */
    function deposit(
        uint256 assets,
        address receiver
    ) public override whenNotPaused onlyAuthorized returns (uint256 shares) {
        return super.deposit(assets, receiver);
    }

    /**
     * @notice Mints shares from the vault. Protected by whenNotPaused and onlyAuthorized.
     * @param shares Amount of shares to mint.
     * @param receiver Address to receive the shares.
     * @return assets Amount of assets deposited.
     */
    function mint(
        uint256 shares,
        address receiver
    ) public override whenNotPaused onlyAuthorized returns (uint256 assets) {
        return super.mint(shares, receiver);
    }

    /**
     * @notice Withdraws assets from the vault. Protected by whenNotPaused and onlyAuthorized.
     * @param assets Amount of assets to withdraw.
     * @param receiver Address to receive the assets.
     * @param owner Address of the owner of the shares.
     * @return shares Amount of shares burned.
     */
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override whenNotPaused onlyAuthorized returns (uint256 shares) {
        return super.withdraw(assets, receiver, owner);
    }

    /**
     * @notice Redeems shares from the vault. Protected by whenNotPaused and onlyAuthorized.
     * @param shares Amount of shares to redeem.
     * @param receiver Address to receive the assets.
     * @param owner Address of the owner of the shares.
     * @return assets Amount of assets withdrawn.
     */
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public override whenNotPaused onlyAuthorized returns (uint256 assets) {
        return super.redeem(shares, receiver, owner);
    }

    /**
     * @notice Returns the maximum amount of the underlying asset that can be deposited.
     * @param receiver The receiver of the deposit.
     * @return The maximum amount of assets. Returns 0 if paused.
     */
    function maxDeposit(
        address receiver
    ) public view override returns (uint256) {
        if (paused()) {
            return 0;
        }
        return super.maxDeposit(receiver);
    }

    /**
     * @notice Returns the maximum amount of shares that can be minted.
     * @param receiver The receiver of the mint.
     * @return The maximum amount of shares. Returns 0 if paused.
     */
    function maxMint(address receiver) public view override returns (uint256) {
        if (paused()) {
            return 0;
        }
        return super.maxMint(receiver);
    }

    /**
     * @notice Returns the maximum amount of the underlying asset that can be withdrawn.
     * @param owner The owner of the shares.
     * @return The maximum amount of assets. Returns 0 if paused.
     */
    function maxWithdraw(address owner) public view override returns (uint256) {
        if (paused()) {
            return 0;
        }
        return super.maxWithdraw(owner);
    }

    /**
     * @notice Returns the maximum amount of shares that can be redeemed.
     * @param owner The owner of the shares.
     * @return The maximum amount of shares. Returns 0 if paused.
     */
    function maxRedeem(address owner) public view override returns (uint256) {
        if (paused()) {
            return 0;
        }
        return super.maxRedeem(owner);
    }

    /**
     * @notice Updates the authorized AML signer.
     * @param _newAmlSigner The address of the new AML signer.
     */
    function setAmlSigner(address _newAmlSigner) external onlyOwner {
        if (_newAmlSigner == address(0)) revert InvalidAmlSigner();
        emit AmlSignerUpdated(amlSigner, _newAmlSigner);
        amlSigner = _newAmlSigner;
    }

    /**
     * @notice UX-focused deposit including AML and Permit.
     * @param assets Amount of assets to deposit.
     * @param receiver Address to receive the shares.
     * @param amlSignature The AML signature from the authorized signer.
     * @param amlDeadline The expiration timestamp of the AML signature.
     * @param permitDeadline The expiration timestamp of the ERC20 permit.
     * @param v V component of the permit signature.
     * @param r R component of the permit signature.
     * @param s S component of the permit signature.
     * @return shares Amount of Nuva shares minted.
     */
    function depositWithPermit(
        uint256 assets,
        address receiver,
        bytes calldata amlSignature,
        uint256 amlDeadline,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused returns (uint256 shares) {
        bytes32 messageHash = _getMessageHash(assets, receiver, amlDeadline);
        _verifyAML(messageHash, amlSignature, amlDeadline);

        try
            IERC20Permit(asset()).permit(
                msg.sender,
                address(this),
                assets,
                permitDeadline,
                v,
                r,
                s
            )
        {
            // Permit successful
        } catch {
            // Permit failed or not supported, proceeding with existing allowance
        }

        return super.deposit(assets, receiver);
    }

    /**
     * @notice UX-focused redeem including AML and Permit.
     * @param shares Amount of shares to redeem.
     * @param receiver Address to receive the assets.
     * @param owner Address of the owner of the shares.
     * @param amlSignature The AML signature from the authorized signer.
     * @param amlDeadline The expiration timestamp of the AML signature.
     * @param permitDeadline The expiration timestamp of the ERC20 permit.
     * @param v V component of the permit signature.
     * @param r R component of the permit signature.
     * @param s S component of the permit signature.
     * @return assets Amount of assets withdrawn.
     */
    function redeemWithPermit(
        uint256 shares,
        address receiver,
        address owner,
        bytes calldata amlSignature,
        uint256 amlDeadline,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused returns (uint256 assets) {
        bytes32 messageHash = _getRedeemMessageHash(shares, receiver, owner, amlDeadline);
        _verifyAML(messageHash, amlSignature, amlDeadline);

        if (msg.sender != owner) {
            try
                IERC20Permit(address(this)).permit(
                    owner,
                    msg.sender,
                    shares,
                    permitDeadline,
                    v,
                    r,
                    s
                )
            {
                // Permit successful
            } catch {
                // Permit failed or not supported, proceeding with existing allowance
            }
        }

        return super.redeem(shares, receiver, owner);
    }

    /**
     * @dev Verifies the provided AML signature.
     * @param _messageHash The hash of the deposit data.
     * @param _signature The AML signature.
     * @param _deadline The signature expiration timestamp.
     */
    function _verifyAML(
        bytes32 _messageHash,
        bytes calldata _signature,
        uint256 _deadline
    ) private {
        if (block.timestamp > _deadline) revert AmlSignatureExpired();
        if (_deadline > block.timestamp + MAX_DEADLINE)
            revert AmlDeadlineTooLong();
        if (usedSignatures[_messageHash]) revert AmlSignatureAlreadyUsed();

        bytes32 ethSignedHash = MessageHashUtils.toTypedDataHash(
            _getDomainSeparator(),
            _messageHash
        );
        address recoveredSigner = ECDSA.recover(ethSignedHash, _signature);

        if (recoveredSigner != amlSigner) revert InvalidAmlSignature();
        usedSignatures[_messageHash] = true;
    }

    /**
     * @dev Constructs the message hash for AML verification.
     * @param _assets Deposit amount.
     * @param _receiver Receiver of shares.
     * @param _deadline Signature deadline.
     * @return messageHash The computed EIP-712 message hash.
     */
    function _getMessageHash(
        uint256 _assets,
        address _receiver,
        uint256 _deadline
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DEPOSIT_TYPEHASH,
                    msg.sender,
                    _assets,
                    _receiver,
                    _deadline
                )
            );
    }

    /**
     * @dev Constructs the message hash for AML verification.
     * @param _shares Redeem amount.
     * @param _receiver Receiver of assets.
     * @param _owner Owner of shares.
     * @param _deadline Signature deadline.
     * @return messageHash The computed EIP-712 message hash.
     */
    function _getRedeemMessageHash(
        uint256 _shares,
        address _receiver,
        address _owner,
        uint256 _deadline
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    REDEEM_TYPEHASH,
                    msg.sender,
                    _shares,
                    _receiver,
                    _owner,
                    _deadline
                )
            );
    }

    /**
     * @dev Returns the EIP-712 domain separator.
     * @return separator The domain separator hash.
     */
    function _getDomainSeparator() private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    ),
                    keccak256(bytes("NuvaVault")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(this)
                )
            );
    }

    /**
     * @notice Returns the decimals offset used to protect against inflation attacks.
     * @return The number of virtual decimals to add.
     */
    function _decimalsOffset() internal pure override returns (uint8) {
        return 12;
    }

    /**
     * @notice Returns the number of decimals used to get its user representation.
     * @return The number of decimals.
     */
    function decimals()
        public
        view
        virtual
        override(ERC4626Upgradeable, ERC20Upgradeable)
        returns (uint8)
    {
        return super.decimals();
    }

    // --- Upgrade Safety ---
    /// @dev Storage gap for future expansion.
    uint256[48] private __gap;
}
