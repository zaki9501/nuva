// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "../../@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "../../@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "../../@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {AccessControlUpgradeable} from "../../@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "../../@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "../../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "../../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "../../@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC4626} from "../../@openzeppelin/contracts/interfaces/IERC4626.sol";
import {ECDSA} from "../../@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "../../@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Clones} from "../../@openzeppelin/contracts/proxy/Clones.sol";

/**
 * @title INuvaVault
 * @notice Interface for NuvaVault specific operations.
 */
interface INuvaVault is IERC4626 {
    function addAuthorizedCaller(address caller) external;

    function removeAuthorizedCaller(address caller) external;
}

/**
 * @title IRedemptionProxy
 * @notice Interface for the disposable RedemptionProxy clones.
 */
interface IRedemptionProxy {
    /**
     * @notice Initializes the proxy clone.
     * @param _assetVault Address of the underlying asset vault.
     * @param _stakingVault Address of the staking vault.
     * @param _nuvaVault Address of the Nuva vault.
     * @param _user Address of the user receiving the redeemed assets.
     */
    function initialize(
        address _assetVault,
        address _stakingVault,
        address _nuvaVault,
        address _user
    ) external;

    /**
     * @notice Triggers the multi-hop redemption process.
     * @param _amountNuvaShares The amount of Nuva shares to redeem.
     * @param _minAssetsOut Minimum amount of asset shares required to proceed.
     */
    function triggerRedeem(
        uint256 _amountNuvaShares,
        uint256 _minAssetsOut
    ) external;

    /**
     * @notice Sweeps the redeemed assets back to the user.
     * @param _amount The amount of assets to sweep.
     * @return sweptAmount The actual amount swept.
     */
    function sweep(uint256 _amount) external returns (uint256 sweptAmount);
}

/**
 * @title DedicatedVaultRouter
 * @notice UX-focused router for multi-hop vault deposits and asynchronous redemptions.
 * @dev Supports AML signature verification, ERC20 Permit, and automated staking flows.
 * @author Nuva Finance
 */
contract DedicatedVaultRouter is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    // --- Roles ---
    /// @notice Role authorized to sweep redemptions.
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    // --- State Variables ---
    /// @notice The first hop vault in the multi-hop deposit flow.
    IERC4626 public assetVault;
    /// @notice The underlying base asset (e.g. USDC).
    IERC20 public asset;
    /// @notice The second hop vault (staking wrapper).
    IERC4626 public stakingVault;
    /// @notice The asset required for the stakingVault.
    IERC20 public stakingAsset;
    /// @notice The final hop vault (Nuva).
    IERC4626 public nuvaVault;
    /// @notice The asset required for the nuvaVault.
    IERC20 public nuvaAsset;
    /// @notice The address authorized to sign AML approvals.
    address public amlSigner;

    /// @notice The master copy implementation for RedemptionProxy clones.
    address public redemptionProxyImplementation;
    /// @notice Mapping from a RedemptionProxy clone to the user who owns it.
    mapping(address => address) public redemptionProxyToUser;
    /// @notice Mapping from a RedemptionProxy clone to its creation timestamp.
    mapping(address => uint256) public redemptionProxyToTimestamp;

    /// @notice Mapping to track used AML signatures to prevent replay attacks.
    mapping(bytes32 => bool) public usedSignatures;

    // --- Events ---
    /**
     * @notice Emitted when a multi-hop deposit is completed.
     * @param sender The address of the user who performed the deposit.
     * @param receiver The address of the user who receives the deposit.
     * @param assets The amount of underlying assets deposited.
     * @param shares The amount of AssetVault shares minted.
     * @param stakingShares The amount of StakingVault shares minted.
     * @param nuvaShares The amount of Nuva shares minted.
     */
    event Deposited(
        address indexed sender,
        address indexed receiver,
        uint256 assets,
        uint256 shares,
        uint256 stakingShares,
        uint256 nuvaShares
    );
    /**
     * @notice Emitted when the AML signer address is updated.
     * @param oldSigner The previous AML signer address.
     * @param newSigner The new AML signer address.
     */
    event AmlSignerUpdated(address oldSigner, address newSigner);
    /**
     * @notice Emitted when the RedemptionProxy implementation is updated.
     * @param oldImplementation The previous implementation address.
     * @param newImplementation The new implementation address.
     */
    event RedemptionProxyImplementationUpdated(
        address oldImplementation,
        address newImplementation
    );
    /**
     * @notice Emitted when a new redemption is requested.
     * @param user The address of the user requesting redemption.
     * @param redemptionProxy The address of the deployed proxy clone.
     * @param amount The Nuva token amount that is being redeemed.
     */
    event RedemptionRequested(
        address indexed user,
        address redemptionProxy,
        uint256 amount
    );
    /**
     * @notice Emitted when redemptions are swept back to users.
     * @param redemptionProxies The addresses of the deployed proxy clones.
     * @param users The array of user addresses (from proxy addresses).
     * @param totalSweptAmount The total amount of assets swept.
     */
    event RedemptionsSwept(
        address[] redemptionProxies,
        address[] users,
        uint256[] amounts,
        uint256 totalSweptAmount
    );

    // --- Custom Errors ---
    error InvalidVault();
    error InvalidAmount();
    error InvalidAddress();
    error InvalidAmlSigner();
    error AmlSignatureExpired();
    error AmlSignatureAlreadyUsed();
    error InvalidAmlSignature();
    error FundsStuck(uint256 amount);
    error SlippageExceeded(uint256 minShares, uint256 actualShares);
    error InvalidRedemptionProxyImplementation();
    error ArrayLengthMismatch();
    error AmlDeadlineTooLong();
    error TimeoutNotReached();
    error Unauthorized();

    uint256 public constant MAX_DEADLINE = 24 hours;

    /**
     * @notice EIP-712 typehash for deposit authorization.
     */
    bytes32 private constant DEPOSIT_TYPEHASH =
        keccak256(
            "Deposit(address sender,uint256 amount,address receiver,uint256 deadline)"
        );

    /**
     * @notice EIP-712 typehash for redemption authorization.
     */
    bytes32 private constant REDEEM_TYPEHASH =
        keccak256(
            "Redeem(address sender,uint256 amountNuvaShares,uint256 deadline)"
        );

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
     * @notice Initializes the router with vault and owner information.
     * @param _assetVault The address of the asset vault (hop 1).
     * @param _stakingVault The address of the staking vault (hop 2).
     * @param _nuvaVault The address of the Nuva vault (hop 3).
     * @param _amlSigner The address authorized for AML signatures.
     * @param _initialOwner The address of the initial contract owner.
     */
    function initialize(
        address _assetVault,
        address _stakingVault,
        address _nuvaVault,
        address _amlSigner,
        address _initialOwner
    ) public initializer {
        __Ownable_init_unchained(_initialOwner);
        __Ownable2Step_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __ReentrancyGuard_init_unchained();

        _grantRole(KEEPER_ROLE, _initialOwner);

        if (
            _assetVault == address(0) ||
            _stakingVault == address(0) ||
            _nuvaVault == address(0)
        ) revert InvalidVault();
        if (_amlSigner == address(0)) revert InvalidAmlSigner();

        assetVault = IERC4626(_assetVault);
        asset = IERC20(assetVault.asset());

        stakingVault = IERC4626(_stakingVault);
        stakingAsset = IERC20(stakingVault.asset());

        nuvaVault = IERC4626(_nuvaVault);
        nuvaAsset = IERC20(nuvaVault.asset());

        amlSigner = _amlSigner;
    }

    // --- Admin Functions ---

    /**
     * @notice Grants the KEEPER_ROLE to a specified address.
     * @param _keeper The address to be granted the KEEPER_ROLE.
     */
    function addKeeper(address _keeper) external onlyOwner {
        _grantRole(KEEPER_ROLE, _keeper);
    }

    /**
     * @notice Revokes the KEEPER_ROLE from a specified address.
     * @param _keeper The address to have the KEEPER_ROLE revoked.
     */
    function removeKeeper(address _keeper) external onlyOwner {
        _revokeRole(KEEPER_ROLE, _keeper);
    }

    /**
     * @notice Performs a standard deposit including AML verification and multi-hop vault staking.
     * @param _amount The amount of underlying asset to deposit.
     * @param _receiver The address to receive the final Nuva shares.
     * @param _minVaultSharesOut Minimum shares expected from the first hop.
     * @param _minStakingVaultSharesOut Minimum shares expected from the second hop.
     * @param _minNuvaVaultSharesOut Minimum shares expected from the third hop.
     * @param _amlSignature The AML signature from the authorized signer.
     * @param _amlDeadline The expiration timestamp of the AML signature.
     * @return nuvaShares The amount of Nuva shares minted.
     */
    function deposit(
        uint256 _amount,
        address _receiver,
        uint256 _minVaultSharesOut,
        uint256 _minStakingVaultSharesOut,
        uint256 _minNuvaVaultSharesOut,
        bytes calldata _amlSignature,
        uint256 _amlDeadline
    ) external nonReentrant returns (uint256 nuvaShares) {
        bytes32 messageHash = _getMessageHash(_amount, _receiver, _amlDeadline);
        _verifyAML(messageHash, _amlSignature, _amlDeadline);

        return
            _doDeposit(
                _amount,
                _receiver,
                _minVaultSharesOut,
                _minStakingVaultSharesOut,
                _minNuvaVaultSharesOut
            );
    }

    /**
     * @notice UX-focused deposit including AML, Permit, and Auto-Staking.
     * @param _amount The amount of underlying asset to deposit.
     * @param _receiver The address to receive the final Nuva shares.
     * @param _minVaultSharesOut Minimum shares expected from the first hop.
     * @param _minStakingVaultSharesOut Minimum shares expected from the second hop.
     * @param _minNuvaVaultSharesOut Minimum shares expected from the third hop.
     * @param _amlSignature The AML signature from the authorized signer.
     * @param _amlDeadline The expiration timestamp of the AML signature.
     * @param _permitDeadline The expiration timestamp of the ERC20 permit.
     * @param _v V component of the permit signature.
     * @param _r R component of the permit signature.
     * @param _s S component of the permit signature.
     * @return nuvaShares The amount of Nuva shares minted.
     */
    function depositWithPermit(
        uint256 _amount,
        address _receiver,
        uint256 _minVaultSharesOut,
        uint256 _minStakingVaultSharesOut,
        uint256 _minNuvaVaultSharesOut,
        bytes calldata _amlSignature,
        uint256 _amlDeadline,
        uint256 _permitDeadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external nonReentrant returns (uint256 nuvaShares) {
        bytes32 messageHash = _getMessageHash(_amount, _receiver, _amlDeadline);
        _verifyAML(messageHash, _amlSignature, _amlDeadline);

        try
            IERC20Permit(address(asset)).permit(
                msg.sender,
                address(this),
                _amount,
                _permitDeadline,
                _v,
                _r,
                _s
            )
        {
            // Permit successful
        } catch {
            // Permit failed or not supported, proceeding with existing allowance
        }

        return
            _doDeposit(
                _amount,
                _receiver,
                _minVaultSharesOut,
                _minStakingVaultSharesOut,
                _minNuvaVaultSharesOut
            );
    }

    /**
     * @notice Internal helper to execute the multi-hop deposit logic.
     * @param _amount Amount to deposit.
     * @param _receiver Receiver of the shares.
     * @param _minVaultSharesOut Min shares from AssetVault.
     * @param _minStakingVaultSharesOut Min shares from StakingVault.
     * @param _minNuvaVaultSharesOut Min shares from NuvaVault.
     * @return nuvaShares Amount of Nuva shares minted.
     */
    function _doDeposit(
        uint256 _amount,
        address _receiver,
        uint256 _minVaultSharesOut,
        uint256 _minStakingVaultSharesOut,
        uint256 _minNuvaVaultSharesOut
    ) internal returns (uint256 nuvaShares) {
        if (_amount == 0) revert InvalidAmount();
        if (_receiver == address(0)) revert InvalidAddress();

        uint256 assetBalBefore = asset.balanceOf(address(this));
        uint256 stakingAssetBalBefore = stakingAsset.balanceOf(address(this));
        uint256 nuvaAssetBalBefore = nuvaAsset.balanceOf(address(this));

        // 1. Asset Vault Hop
        asset.safeTransferFrom(msg.sender, address(this), _amount);
        uint256 receivedAmount = asset.balanceOf(address(this)) -
            assetBalBefore;
        asset.forceApprove(address(assetVault), receivedAmount);
        uint256 vaultShares = assetVault.deposit(receivedAmount, address(this));

        if (vaultShares < _minVaultSharesOut)
            revert SlippageExceeded(_minVaultSharesOut, vaultShares);
        if (asset.balanceOf(address(this)) > assetBalBefore)
            revert FundsStuck(1);

        // 2. Staking Vault Hop
        stakingAsset.forceApprove(address(stakingVault), vaultShares);
        uint256 stakingShares = stakingVault.deposit(
            vaultShares,
            address(this)
        );

        if (stakingShares < _minStakingVaultSharesOut)
            revert SlippageExceeded(_minStakingVaultSharesOut, stakingShares);
        if (stakingAsset.balanceOf(address(this)) > stakingAssetBalBefore)
            revert FundsStuck(2);

        // 3. Nuva Vault Hop
        nuvaAsset.forceApprove(address(nuvaVault), stakingShares);
        nuvaShares = nuvaVault.deposit(stakingShares, _receiver);

        if (nuvaShares < _minNuvaVaultSharesOut)
            revert SlippageExceeded(_minNuvaVaultSharesOut, nuvaShares);
        if (nuvaAsset.balanceOf(address(this)) > nuvaAssetBalBefore)
            revert FundsStuck(3);

        emit Deposited(
            msg.sender,
            _receiver,
            _amount,
            vaultShares,
            stakingShares,
            nuvaShares
        );
    }

    // --- Redemption Functions ---

    /**
     * @notice Initiates an asynchronous redemption by deploying a RedemptionProxy clone.
     * @param _amountNuvaShares The amount of Nuva shares to redeem.
     * @param _minAssetsOut Minimum amount of asset shares required to proceed.
     * @param _amlSignature The AML signature from the authorized signer.
     * @param _amlDeadline The expiration timestamp of the AML signature.
     */
    function requestRedeem(
        uint256 _amountNuvaShares,
        uint256 _minAssetsOut,
        bytes calldata _amlSignature,
        uint256 _amlDeadline
    ) external nonReentrant {
        bytes32 messageHash = _getRedeemMessageHash(
            _amountNuvaShares,
            _amlDeadline
        );
        _verifyAML(messageHash, _amlSignature, _amlDeadline);

        _doRequestRedeem(_amountNuvaShares, _minAssetsOut);
    }

    /**
     * @notice Initiates an asynchronous redemption using ERC20 permit for vault shares.
     * @param _amountNuvaShares The amount of Nuva shares to redeem.
     * @param _minAssetsOut Minimum amount of asset shares required to proceed.
     * @param _amlSignature The AML signature from the authorized signer.
     * @param _amlDeadline The expiration timestamp of the AML signature.
     * @param _permitDeadline The expiration timestamp of the permit.
     * @param _v V component of the permit signature.
     * @param _r R component of the permit signature.
     * @param _s S component of the permit signature.
     */
    function requestRedeemWithPermit(
        uint256 _amountNuvaShares,
        uint256 _minAssetsOut,
        bytes calldata _amlSignature,
        uint256 _amlDeadline,
        uint256 _permitDeadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external nonReentrant {
        bytes32 messageHash = _getRedeemMessageHash(
            _amountNuvaShares,
            _amlDeadline
        );
        _verifyAML(messageHash, _amlSignature, _amlDeadline);

        try
            IERC20Permit(address(nuvaVault)).permit(
                msg.sender,
                address(this),
                _amountNuvaShares,
                _permitDeadline,
                _v,
                _r,
                _s
            )
        {
            // Permit successful
        } catch {
            // Permit failed or not supported
        }

        _doRequestRedeem(_amountNuvaShares, _minAssetsOut);
    }

    /**
     * @notice Internal helper to execute the redemption request logic.
     * @param _amountNuvaShares Amount of Nuva shares to redeem.
     * @param _minAssetsOut Minimum amount of asset shares required to proceed.
     */
    function _doRequestRedeem(
        uint256 _amountNuvaShares,
        uint256 _minAssetsOut
    ) internal {
        if (_amountNuvaShares == 0) revert InvalidAmount();
        if (redemptionProxyImplementation == address(0))
            revert InvalidRedemptionProxyImplementation();

        uint256 balBefore = nuvaVault.balanceOf(address(this));

        // Deploy a minimal proxy clone of RedemptionProxy
        address redemptionProxyAddress = Clones.clone(
            redemptionProxyImplementation
        );
        IRedemptionProxy redemptionProxy = IRedemptionProxy(
            redemptionProxyAddress
        );

        // Initialize the clone
        redemptionProxy.initialize(
            address(assetVault),
            address(stakingVault),
            address(nuvaVault),
            msg.sender
        );

        // Transfer nuvaVault shares from user to the RedemptionProxy clone
        IERC20(address(nuvaVault)).safeTransferFrom(
            msg.sender,
            address(this),
            _amountNuvaShares
        );
        IERC20(address(nuvaVault)).forceApprove(
            redemptionProxyAddress,
            _amountNuvaShares
        );
        INuvaVault(address(nuvaVault)).addAuthorizedCaller(
            redemptionProxyAddress
        );
        redemptionProxy.triggerRedeem(_amountNuvaShares, _minAssetsOut);

        if (nuvaVault.balanceOf(address(this)) > balBefore)
            revert FundsStuck(1);

        redemptionProxyToUser[redemptionProxyAddress] = msg.sender;
        redemptionProxyToTimestamp[redemptionProxyAddress] = block.timestamp;
        emit RedemptionRequested(
            msg.sender,
            redemptionProxyAddress,
            _amountNuvaShares
        );
    }

    /**
     * @notice Sweeps underlying assets from multiple RedemptionProxy clones back to users.
     * @param _proxyAddresses Array of proxy addresses to sweep from.
     * @param _amounts Array of amounts to sweep for each proxy.
     */
    function sweepRedemptions(
        address[] calldata _proxyAddresses,
        uint256[] calldata _amounts
    ) external nonReentrant onlyRole(KEEPER_ROLE) {
        if (redemptionProxyImplementation == address(0))
            revert InvalidRedemptionProxyImplementation();
        if (_proxyAddresses.length != _amounts.length)
            revert ArrayLengthMismatch();

        uint256 totalSwept = 0;
        uint256 length = _proxyAddresses.length;
        address[] memory users = new address[](length);

        for (uint256 i = 0; i < length; ++i) {
            address proxyAddress = _proxyAddresses[i];
            uint256 amountToSweep = _amounts[i];
            address user = redemptionProxyToUser[proxyAddress];
            users[i] = user;

            if (user != address(0) && amountToSweep > 0) {
                IRedemptionProxy redemptionProxy = IRedemptionProxy(
                    proxyAddress
                );
                totalSwept += redemptionProxy.sweep(amountToSweep);
            }

            // Only delete mapping when the proxy has been fully drained
            if (IERC20(asset).balanceOf(proxyAddress) == 0) {
                delete redemptionProxyToUser[proxyAddress];
                delete redemptionProxyToTimestamp[proxyAddress];
                INuvaVault(address(nuvaVault)).removeAuthorizedCaller(
                    proxyAddress
                );
            }
        }
        emit RedemptionsSwept(_proxyAddresses, users, _amounts, totalSwept);
    }

    /**
     * @notice Sweeps underlying assets from a single RedemptionProxy clone back to the user after a 7 day timeout.
     * @param _proxyAddress Address of the proxy to sweep from.
     */
    function sweepUserRedemption(address _proxyAddress) external nonReentrant {
        address user = redemptionProxyToUser[_proxyAddress];
        if (user != msg.sender) revert Unauthorized();
        if (
            block.timestamp < redemptionProxyToTimestamp[_proxyAddress] + 7 days
        ) revert TimeoutNotReached();

        uint256 amountToSweep = IERC20(asset).balanceOf(_proxyAddress);
        if (amountToSweep == 0) revert InvalidAmount();

        IRedemptionProxy redemptionProxy = IRedemptionProxy(_proxyAddress);
        uint256 sweptAmount = redemptionProxy.sweep(amountToSweep);

        delete redemptionProxyToUser[_proxyAddress];
        delete redemptionProxyToTimestamp[_proxyAddress];
        INuvaVault(address(nuvaVault)).removeAuthorizedCaller(_proxyAddress);

        address[] memory proxies = new address[](1);
        proxies[0] = _proxyAddress;
        address[] memory users = new address[](1);
        users[0] = msg.sender;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amountToSweep;

        emit RedemptionsSwept(proxies, users, amounts, sweptAmount);
    }

    // --- Admin Functions ---

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
     * @notice Sets the master copy implementation for RedemptionProxy clones.
     * @param _newImplementation The address of the new implementation.
     */
    function setRedemptionProxyImplementation(
        address _newImplementation
    ) external onlyOwner {
        if (_newImplementation == address(0))
            revert InvalidRedemptionProxyImplementation();
        emit RedemptionProxyImplementationUpdated(
            redemptionProxyImplementation,
            _newImplementation
        );
        redemptionProxyImplementation = _newImplementation;
    }

    // --- Internal Helpers ---

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
     * @param _amount Deposit amount.
     * @param _receiver Receiver of shares.
     * @param _deadline Signature deadline.
     * @return messageHash The computed EIP-712 message hash.
     */
    function _getMessageHash(
        uint256 _amount,
        address _receiver,
        uint256 _deadline
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DEPOSIT_TYPEHASH,
                    msg.sender,
                    _amount,
                    _receiver,
                    _deadline
                )
            );
    }

    /**
     * @dev Constructs the message hash for redemption AML verification.
     * @param _amountNuvaShares Amount of Nuva shares to redeem.
     * @param _deadline Signature deadline.
     * @return messageHash The computed EIP-712 message hash.
     */
    function _getRedeemMessageHash(
        uint256 _amountNuvaShares,
        uint256 _deadline
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    REDEEM_TYPEHASH,
                    msg.sender,
                    _amountNuvaShares,
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
                    keccak256(bytes("DedicatedVaultRouter")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(this)
                )
            );
    }

    // --- Upgrade Safety ---
    // 10 slots: assetVault, asset, stakingVault, stakingAsset, nuvaVault, nuvaAsset, amlSigner, redemptionProxyImplementation, redemptionProxyToUser, usedSignatures
    // reentrancyStatus slot is namespaced
    uint256[40] private __gap;

    /**
     * @dev Authorizes a contract upgrade. Only callable by the owner.
     * @param newImplementation Address of the new implementation.
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {
        // Upgrade authorized
    }
}
