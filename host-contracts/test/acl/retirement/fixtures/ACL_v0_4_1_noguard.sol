// SPDX-License-Identifier: BSD-3-Clause-Clear
// TEST FIXTURE: an ACL source, verbatim except for the edits listed below. Do not edit by hand.
// Source: the ACL v0.4.1 backport with the upgrade guard removed (not a release; the U3 hazard test only)
// Source git blob: 57bc6f5c8195f12d793f7fe3d367ada20c0d4c43
// Edits (mechanical, nothing else changed):
//   - 1 import path(s) "./shared/ -> "../../../../contracts/shared/
//   - 1 import path(s) "./interfaces/ -> "../../../../contracts/interfaces/
//   - 1 import path(s) "./ACLEvents.sol" -> "../../../../contracts/ACLEvents.sol"
//   - 1 import path(s) "../addresses/ -> "../../../../addresses/
//   - _authorizeUpgrade body emptied (pre-Level-0 shape), guard removed
pragma solidity ^0.8.24;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {MulticallUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol";
import {UUPSUpgradeableEmptyProxy} from "../../../../contracts/shared/UUPSUpgradeableEmptyProxy.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {fhevmExecutorAdd, pauserSetAdd} from "../../../../addresses/FHEVMHostAddresses.sol";
import {IPauserSet} from "../../../../contracts/interfaces/IPauserSet.sol";

import {ACLEvents} from "../../../../contracts/ACLEvents.sol";

/**
 * @title ACL.
 * @notice The ACL (Access Control List) is a permission management system designed to control who can access, compute on,
 * or decrypt encrypted values in fhEVM. By defining and enforcing these permissions, the ACL ensures that encrypted data remains
 * secure while still being usable within authorized contexts.
 */
/// @custom:security-contact https://github.com/zama-ai/fhevm/blob/main/SECURITY.md
contract ACL is
    UUPSUpgradeableEmptyProxy,
    Ownable2StepUpgradeable,
    PausableUpgradeable,
    ACLEvents,
    MulticallUpgradeable
{
    /**
     * @notice Returned if an account is already in the deny list.
     * @param account The address of the account that is already blocked.
     */
    error AccountAlreadyBlocked(address account);

    /**
     * @notice Returned if an account that is already retired calls `retireAccount()`.
     * @param account The address of the account that is already retired.
     */
    error AccountAlreadyRetired(address account);

    /**
     * @notice Returned if an account is not in the deny list.
     * @param account The address of the account that is not blocked.
     */
    error AccountNotBlocked(address account);

    /**
     * @notice Returned if a delegation or revoke has already been done in a same block.
     * @param delegator The address of the account that delegates access to its handles.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to delegate access to.
     * @param blockNumber The block number.
     */
    error AlreadyDelegatedOrRevokedInSameBlock(
        address delegator,
        address delegate,
        address contractAddress,
        uint256 blockNumber
    );

    /**
     * @notice Returned if the delegate address is the same as the contract address.
     * @param contractAddress The contract address to delegate access to.
     */
    error DelegateCannotBeContractAddress(address contractAddress);

    /**
     * @notice Returned if the delegate address is the wildcard contract address.
     * @param delegate The address of the delegate.
     */
    error DelegateCannotBeWildcard(address delegate);

    /**
     * @notice Returned if the requested expiration date was already set to same expiration for (delegate,contractAddress).
     * @param delegator The address of the account that delegates access to its handles.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to delegate access to.
     * @param expirationDate The UNIX timestamp when the user decryption delegation expires.
     */
    error ExpirationDateAlreadySetToSameValue(
        address delegator,
        address delegate,
        address contractAddress,
        uint256 expirationDate
    );

    /// @notice Returned if the requested expiration date for user decryption delegation is in the past.
    error ExpirationDateInThePast();

    /// @notice Returned if the handlesList array is empty.
    error HandlesListIsEmpty();

    /**
     * @notice Returned if the the delegate contract is not already delegate for sender & delegator addresses.
     * @param delegator The address of the account that delegates access to its handles.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to delegate access to.
     */
    error NotDelegatedYet(address delegator, address delegate, address contractAddress);

    /// @notice Returned if the sender address is not allowed to pause the contract.
    error NotPauser(address sender);

    /**
     * @notice Returned if the sender address is the same as the contract address.
     * @param contractAddress The contract address to delegate access to.
     */
    error SenderCannotBeContractAddress(address contractAddress);

    /**
     * @notice Returned if the sender address is the same as the delegate address.
     * @param delegate The address of the account that receives the delegation.
     */
    error SenderCannotBeDelegate(address delegate);

    /**
     * @notice Returned if the sender address is not allowed for allow operations.
     * @param sender The address of the account that is not allowed.
     */
    error SenderNotAllowed(address sender);

    /**
     * @notice Returned if the sender address is in the deny list.
     * @param sender The address of the account that is denied.
     */
    error SenderDenied(address sender);

    /**
     * @notice Returned if a retired account calls a grant path: `allow`, `allowForDecryption`, `allowTransient`
     *         (outside the FHEVMExecutor branch) or `delegateForUserDecryption`.
     * @param sender The address of the retired account.
     */
    error SenderRetired(address sender);

    /**
     * @notice Returned if an upgrade targets an implementation that does not declare the Decryption Authority
     *         Lifecycle Core interface through ERC-165, or that reports another retirement storage location.
     * @param newImplementation The address of the rejected implementation.
     */
    error UpgradeDropsRetirement(address newImplementation);

    /**
     * @notice Struct that represents a delegation.
     * @dev The `delegationCounter` is incremented at each delegation or revocation
     *      to allow off-chain clients to track changes.
     */
    struct UserDecryptionDelegation {
        /// @notice The UNIX timestamp when the user decryption delegation expires.
        uint64 expirationDate;
        /// @notice The last block number when a delegation or revocation happened.
        uint64 lastBlockDelegateOrRevoke;
        /// @notice Counter that tracks the order of each delegation or revocation.
        uint64 delegationCounter;
    }

    /// @custom:storage-location erc7201:fhevm.storage.ACL
    struct ACLStorage {
        mapping(bytes32 handle => mapping(address account => bool isAllowed)) persistedAllowedPairs;
        mapping(bytes32 handle => bool isAllowedForDecryption) allowedForDecryption;
        // prettier-ignore
        mapping(address account =>
            mapping(address delegate => mapping(address contractAddress => UserDecryptionDelegation delegation)))
                userDecryptionDelegations;
        mapping(address account => bool isDenied) denyList;
    }

    /**
     * @notice Retirement state, kept in its own ERC-7201 namespace so that it survives any release that keeps
     *         the namespace (see `_authorizeUpgrade`).
     * @dev Append-only: later lifecycle extensions add their fields here, in the same namespace.
     */
    /// @custom:storage-location erc7201:fhevm.storage.ACLRetirement
    struct ACLRetirementStorage {
        mapping(address account => bool isRetired) retired;
    }

    /// @notice Name of the contract.
    string private constant CONTRACT_NAME = "ACL";

    /// @notice Major version of the contract.
    uint256 private constant MAJOR_VERSION = 0;

    /// @notice Minor version of the contract.
    uint256 private constant MINOR_VERSION = 4;

    /// @notice Patch version of the contract.
    uint256 private constant PATCH_VERSION = 1;

    /// @notice FHEVMExecutor address.
    address private constant FHEVM_EXECUTOR_ADDRESS = fhevmExecutorAdd;

    /// @notice PauserSet contract.
    IPauserSet private constant PAUSER_SET = IPauserSet(pauserSetAdd);

    /**
     * @notice Sentinel address for user-decryption delegation that applies to every app contract.
     * @dev `type(uint160).max` (EIP-55: 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF). No contract can be deployed here.
     *      Pass as `contractAddress` in `delegateForUserDecryption` / `revokeDelegationForUserDecryption` to grant or
     *      revoke blanket delegation. This is a high-trust grant: SDKs should warn users explicitly.
     */
    address public constant WILDCARD_DELEGATION_ADDRESS = address(type(uint160).max);

    /// Constant used for making sure the version number used in the `reinitializer` modifier is
    /// identical between `initializeFromEmptyProxy` and the `reinitializeVX` method
    uint64 private constant REINITIALIZER_VERSION = 6;

    /// keccak256(abi.encode(uint256(keccak256("fhevm.storage.ACL")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ACL_STORAGE_LOCATION = 0xa688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00;

    /// keccak256(abi.encode(uint256(keccak256("fhevm.storage.ACLRetirement")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ACL_RETIREMENT_STORAGE_LOCATION =
        0xe6ae1005b480da47ced1ed3eb5869a54ca87c5d592369277249f4148c0e86200;

    /// @notice ERC-165 interface id of ERC-165 itself, `supportsInterface(bytes4)`.
    bytes4 private constant ERC165_INTERFACE_ID = 0x01ffc9a7;

    /// @notice ERC-165 interface id of the Decryption Authority Lifecycle Core:
    ///         `retireAccount()` (0xe7142996) XOR `isAccountRetired(address)` (0xb279091e).
    bytes4 private constant DAL_CORE_INTERFACE_ID = 0x556d2088;

    /// @notice Selector of `retirementStorageLocation()`, read from a new implementation by `_authorizeUpgrade`.
    bytes4 private constant RETIREMENT_STORAGE_LOCATION_SELECTOR = 0xc89c7ccd;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice  Initializes the contract.
     */
    /// @custom:oz-upgrades-validate-as-initializer
    function initializeFromEmptyProxy() public virtual onlyFromEmptyProxy reinitializer(REINITIALIZER_VERSION) {
        __Ownable_init(owner());
        __Pausable_init();
    }

    /**
     * @notice Re-initializes the contract from V4 (ACL v0.4.0). Retirement state needs no initialization.
     */
    /// @custom:oz-upgrades-unsafe-allow missing-initializer-call
    /// @custom:oz-upgrades-validate-as-initializer
    function reinitializeV5() public virtual reinitializer(REINITIALIZER_VERSION) {}

    /**
     * @notice Allows the use of `handle` for the address `account`.
     * @dev The caller must not be in the deny list and must be allowed to use `handle` for allow() to succeed. If not, allow() reverts.
     *      A retired caller is never allowed and reverts with `SenderRetired`. A grant to a retired `account` is
     *      accepted and inert: no view ever answers true for a retired account.
     * @param handle Handle.
     * @param account Address of the account.
     */
    function allow(bytes32 handle, address account) public virtual whenNotPaused {
        if (isAccountDenied(msg.sender)) {
            revert SenderDenied(msg.sender);
        }
        if (!isAllowed(handle, msg.sender)) {
            if (_retired().retired[msg.sender]) {
                revert SenderRetired(msg.sender);
            }
            revert SenderNotAllowed(msg.sender);
        }
        ACLStorage storage $ = _getACLStorage();
        $.persistedAllowedPairs[handle][account] = true;
        emit Allowed(msg.sender, account, handle);
    }

    /**
     * @notice Allows a list of handles to be decrypted.
     * @dev The caller must not be in the deny list and must be allowed to use `handlesList[i]` for allowForDecryption() to succeed.
     *      If not, allowForDecryption() reverts. A retired caller reverts with `SenderRetired`.
     * @param handlesList List of handles.
     */
    function allowForDecryption(bytes32[] memory handlesList) public virtual whenNotPaused {
        uint256 lenHandlesList = handlesList.length;
        if (lenHandlesList == 0) {
            revert HandlesListIsEmpty();
        }

        if (isAccountDenied(msg.sender)) {
            revert SenderDenied(msg.sender);
        }

        ACLStorage storage $ = _getACLStorage();
        for (uint256 k = 0; k < lenHandlesList; k++) {
            bytes32 handle = handlesList[k];
            if (!isAllowed(handle, msg.sender)) {
                if (_retired().retired[msg.sender]) {
                    revert SenderRetired(msg.sender);
                }
                revert SenderNotAllowed(msg.sender);
            }
            $.allowedForDecryption[handle] = true;
        }
        emit AllowedForDecryption(msg.sender, handlesList);
    }

    /**
     * @notice Allows the use of `handle` by address `account` for this transaction.
     * @dev The caller must not be in the deny list and must be allowed to use `handle` for allowTransient() to succeed.
     *      If not, allowTransient() reverts. The Coprocessor contract can always `allowTransient`,
     *      contrarily to `allow`. Any other retired caller reverts with `SenderRetired`.
     * @param handle Handle.
     * @param account Address of the account.
     */
    function allowTransient(bytes32 handle, address account) public virtual whenNotPaused {
        if (msg.sender != FHEVM_EXECUTOR_ADDRESS) {
            if (isAccountDenied(msg.sender)) {
                revert SenderDenied(msg.sender);
            }

            if (!isAllowed(handle, msg.sender)) {
                if (_retired().retired[msg.sender]) {
                    revert SenderRetired(msg.sender);
                }
                revert SenderNotAllowed(msg.sender);
            }
        }

        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            tstore(key, 1)
            let length := tload(0)
            let lengthPlusOne := add(length, 1)
            tstore(lengthPlusOne, key)
            tstore(0, lengthPlusOne)
        }
    }

    /**
     * @notice Delegates an account the access to handles for user decryption, for instance, in the context of account
     * abstraction for issuing user decryption requests from a smart contract account.
     * @dev A retired caller reverts with `SenderRetired`. Delegating to a retired delegate, or for a retired contract,
     *      is accepted and inert: the delegated view answers false for every retired party.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to delegate access to, or `WILDCARD_DELEGATION_ADDRESS` for delegation across
     *        all contracts (until expiry). Mixing wildcard with per-contract delegations is allowed and can be useful,
     *        for example when different expiries are desired, although it is often unnecessary.
     * @param expirationDate The UNIX timestamp when the user decryption delegation expires.
     */
    function delegateForUserDecryption(
        address delegate,
        address contractAddress,
        uint64 expirationDate
    ) public virtual whenNotPaused {
        if (_retired().retired[msg.sender]) {
            revert SenderRetired(msg.sender);
        }
        ACLStorage storage $ = _getACLStorage();
        UserDecryptionDelegation storage userDecryptionDelegation = $.userDecryptionDelegations[msg.sender][delegate][
            contractAddress
        ];
        uint256 blockNumber = block.number;

        if (userDecryptionDelegation.lastBlockDelegateOrRevoke == blockNumber) {
            revert AlreadyDelegatedOrRevokedInSameBlock(msg.sender, delegate, contractAddress, blockNumber);
        }

        if (contractAddress == msg.sender) {
            revert SenderCannotBeContractAddress(contractAddress);
        }
        if (delegate == msg.sender) {
            revert SenderCannotBeDelegate(delegate);
        }
        if (delegate == WILDCARD_DELEGATION_ADDRESS) {
            revert DelegateCannotBeWildcard(delegate);
        }
        if (delegate == contractAddress) {
            revert DelegateCannotBeContractAddress(contractAddress);
        }
        if (expirationDate <= block.timestamp) {
            revert ExpirationDateInThePast();
        }

        uint64 oldExpirationDate = userDecryptionDelegation.expirationDate;
        uint64 newExpirationDate = expirationDate;
        if (oldExpirationDate == newExpirationDate) {
            revert ExpirationDateAlreadySetToSameValue(msg.sender, delegate, contractAddress, oldExpirationDate);
        }

        // Set the last block where the delegation happened.
        userDecryptionDelegation.lastBlockDelegateOrRevoke = uint64(blockNumber);

        // Set the delegation expiration date.
        userDecryptionDelegation.expirationDate = newExpirationDate;

        emit DelegatedForUserDecryption(
            msg.sender,
            delegate,
            contractAddress,
            ++userDecryptionDelegation.delegationCounter,
            oldExpirationDate,
            newExpirationDate
        );
    }

    /**
     * @notice Revokes the access to handles for user decryption delegated to an account.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to revoke access to, or `WILDCARD_DELEGATION_ADDRESS` to revoke the
     *        wildcard delegation across all contracts.
     */
    function revokeDelegationForUserDecryption(address delegate, address contractAddress) public virtual whenNotPaused {
        ACLStorage storage $ = _getACLStorage();
        UserDecryptionDelegation storage userDecryptionDelegation = $.userDecryptionDelegations[msg.sender][delegate][
            contractAddress
        ];
        uint256 blockNumber = block.number;

        if (userDecryptionDelegation.lastBlockDelegateOrRevoke == blockNumber) {
            revert AlreadyDelegatedOrRevokedInSameBlock(msg.sender, delegate, contractAddress, blockNumber);
        }

        // Set the last block where the revocation happened.
        userDecryptionDelegation.lastBlockDelegateOrRevoke = uint64(blockNumber);

        uint64 oldExpirationDate = userDecryptionDelegation.expirationDate;
        if (oldExpirationDate == 0) {
            revert NotDelegatedYet(msg.sender, delegate, contractAddress);
        }

        // Reset the delegation expiration date.
        userDecryptionDelegation.expirationDate = 0;

        emit RevokedDelegationForUserDecryption(
            msg.sender,
            delegate,
            contractAddress,
            ++userDecryptionDelegation.delegationCounter,
            oldExpirationDate
        );
    }

    /**
     * @notice Retires the caller's authority over its decryption rights (revocable access).
     * @dev One-way: no function clears it. Not gated by pause or by the deny list, and callable by contracts.
     *      Effective immediately: every authorization view answers false for the caller in every role (user,
     *      delegator, delegate, contract), except operand checks made by the FHEVMExecutor, and every grant path
     *      reverts for the caller. To keep access from a new account, batch the grants first:
     *      `multicall([allow(h_i, newAccount)..., retireAccount()])`.
     *      Limits: it is pre-emptive, not a clawback (whatever was already shared or decrypted stays exposed); it
     *      restricts oracle access only (the account still acts on-chain); it is as final as this chain's governance.
     */
    function retireAccount() public virtual {
        ACLRetirementStorage storage $ = _retired();
        if ($.retired[msg.sender]) {
            revert AccountAlreadyRetired(msg.sender);
        }
        $.retired[msg.sender] = true;
        emit AccountRetired(msg.sender, address(0));
    }

    /**
     * @dev Triggers stopped state.
     * Only a pauser address can pause.
     * The contract must not be paused.
     */
    function pause() external virtual {
        if (!PAUSER_SET.isPauser(msg.sender)) {
            revert NotPauser(msg.sender);
        }
        _pause();
    }

    /**
     * @dev Returns to normal state.
     * Only owner can unpause.
     * The contract must be paused.
     */
    function unpause() external virtual onlyOwner {
        _unpause();
    }

    /**
     * @notice Get the expiration date of a delegation for user decryption.
     * @param delegator The address of the account that delegates access to its handles.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to delegate access to.
     * @return expirationDate The UNIX timestamp when the user decryption delegation expires (0 means delegation is inactive).
     *         Returns 0 if the delegator, the delegate or the contract is retired.
     */
    function getUserDecryptionDelegationExpirationDate(
        address delegator,
        address delegate,
        address contractAddress
    ) public view virtual returns (uint64) {
        ACLRetirementStorage storage $r = _retired();
        if ($r.retired[delegator] || $r.retired[delegate] || $r.retired[contractAddress]) {
            return 0;
        }
        ACLStorage storage $ = _getACLStorage();
        UserDecryptionDelegation storage userDecryptionDelegation = $.userDecryptionDelegations[delegator][delegate][
            contractAddress
        ];
        return userDecryptionDelegation.expirationDate;
    }

    /**
     * @notice Checks whether the account is allowed to use the handle in the
     * same transaction (transient).
     * @param handle Handle.
     * @param account Address of the account.
     * @return isAllowedTransient Whether the account can access transiently the handle.
     */
    function allowedTransient(bytes32 handle, address account) public view virtual returns (bool) {
        bool isAllowedTransient;
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            isAllowedTransient := tload(key)
        }
        return isAllowedTransient;
    }

    /**
     * @notice Getter function for the FHEVMExecutor contract address.
     * @return fhevmExecutorAddress Address of the FHEVMExecutor.
     */
    function getFHEVMExecutorAddress() public view virtual returns (address) {
        return FHEVM_EXECUTOR_ADDRESS;
    }

    /**
     * @notice Getter function for the PauserSet contract address.
     * @return pauserSetAddress Address of the PauserSet contract.
     */
    function getPauserSetAddress() public view virtual returns (address) {
        return address(PAUSER_SET);
    }

    /**
     * @notice Returns whether the account is allowed to use the `handle`, either due to
     * allowTransient() or allow().
     * @dev Returns false for a retired `account` whenever the caller is not the FHEVMExecutor. The executor exemption
     *      exists for exactly one evaluation: authorizing an operand's use as input to a computation the executor
     *      performs for its caller, whose outputs it grants only transiently and only to that caller. Every grant,
     *      publication, delegation, deputy check and off-chain verifier reads this view with another caller, so the
     *      exemption is never an export route. The executor path reads the raw persisted mapping and never the
     *      retirement slot.
     * @param handle Handle.
     * @param account Address of the account.
     * @return isAllowed Whether the account can access the handle.
     */
    function isAllowed(bytes32 handle, address account) public view virtual returns (bool) {
        if (msg.sender != FHEVM_EXECUTOR_ADDRESS && _retired().retired[account]) {
            return false;
        }
        return allowedTransient(handle, account) || _getACLStorage().persistedAllowedPairs[handle][account];
    }

    /**
     * @notice Checks whether a handle is allowed for decryption.
     * @param handle Handle.
     * @return isAllowed Whether the handle is allowed for decryption.
     */
    function isAllowedForDecryption(bytes32 handle) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return $.allowedForDecryption[handle];
    }

    /**
     * @notice Returns whether an account is delegated to access the handle for user decryption.
     * @dev Succeeds when the delegator and `contractAddress` are both persistently allowed on the handle, and either
     *      a non-expired delegation exists for `(delegator, delegate, contractAddress)` or for
     *      `(delegator, delegate, WILDCARD_DELEGATION_ADDRESS)`. Wildcard does not bypass `allow`; it only avoids per-contract
     *      delegation entries. Returns false if the delegator, the delegate or the contract is retired.
     * @param delegator The address of the account that delegates access to its handles.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The app contract associated with the handle for this check.
     * @param handle The handle to check for delegated user decryption.
     * @return isDelegatedForUserDecryption Whether the handle can be accessed for delegated user decryption.
     */
    function isHandleDelegatedForUserDecryption(
        address delegator,
        address delegate,
        address contractAddress,
        bytes32 handle
    ) public view virtual returns (bool) {
        ACLRetirementStorage storage $r = _retired();
        if ($r.retired[delegator] || $r.retired[delegate] || $r.retired[contractAddress]) {
            return false;
        }
        ACLStorage storage $ = _getACLStorage();
        if (!$.persistedAllowedPairs[handle][delegator] || !$.persistedAllowedPairs[handle][contractAddress]) {
            return false;
        }
        return
            _isUserDecryptionDelegationActive($, delegator, delegate, WILDCARD_DELEGATION_ADDRESS) ||
            _isUserDecryptionDelegationActive($, delegator, delegate, contractAddress);
    }

    /**
     * @notice Returns `true` if address `a` is allowed to use `c` and `false` otherwise.
     * @dev Returns false for a retired `account`, whoever the caller is.
     * @param handle Handle.
     * @param account Address of the account.
     * @return isAllowed Whether the account can access the handle.
     */
    function persistAllowed(bytes32 handle, address account) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return $.persistedAllowedPairs[handle][account] && !_retired().retired[account];
    }

    /**
     * @notice Returns `true` if `account` is deny-listed and `false` otherwise.
     * @param account Address of the account.
     * @return isAccountDenied Whether the account is on the deny list.
     */
    function isAccountDenied(address account) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return $.denyList[account];
    }

    /**
     * @notice Returns `true` if `account` has retired its decryption authority through `retireAccount()`.
     * @param account Address of the account.
     * @return isAccountRetired Whether the account is retired.
     */
    function isAccountRetired(address account) public view virtual returns (bool) {
        return _retired().retired[account];
    }

    /**
     * @notice Adds `account` to the deny list
     * @param account Address of the account.
     */
    function blockAccount(address account) public virtual onlyOwner {
        ACLStorage storage $ = _getACLStorage();
        if ($.denyList[account]) {
            revert AccountAlreadyBlocked(account);
        }
        $.denyList[account] = true;
        emit BlockedAccount(account);
    }

    /**
     * @notice Removes `account` from the deny list
     * @param account Address of the account.
     */
    function unblockAccount(address account) public virtual onlyOwner {
        ACLStorage storage $ = _getACLStorage();
        if (!$.denyList[account]) {
            revert AccountNotBlocked(account);
        }
        $.denyList[account] = false;
        emit UnblockedAccount(account);
    }

    /**
     * @notice Returns wether specified account is in the set of pausers.
     * @param account The address of the account.
     */
    function isPauser(address account) external view virtual returns (bool) {
        return PAUSER_SET.isPauser(account);
    }

    /**
     * @dev This function removes the transient allowances, which could be useful for integration with
     * Account Abstraction when bundling several UserOps calling the FHEVMExecutor Coprocessor.
     */
    function cleanTransientStorage() external virtual {
        assembly {
            let length := tload(0)
            tstore(0, 0)
            let lengthPlusOne := add(length, 1)
            for {
                let i := 1
            } lt(i, lengthPlusOne) {
                i := add(i, 1)
            } {
                let handle := tload(i)
                tstore(i, 0)
                tstore(handle, 0)
            }
        }
    }

    /**
     * @notice Getter for the name and version of the contract.
     * @return string Name and the version of the contract.
     */
    function getVersion() external pure virtual returns (string memory) {
        return
            string(
                abi.encodePacked(
                    CONTRACT_NAME,
                    " v",
                    Strings.toString(MAJOR_VERSION),
                    ".",
                    Strings.toString(MINOR_VERSION),
                    ".",
                    Strings.toString(PATCH_VERSION)
                )
            );
    }

    /**
     * @notice ERC-165 interface detection.
     * @dev True for ERC-165 itself (0x01ffc9a7) and for the Decryption Authority Lifecycle Core (0x556d2088).
     * @param interfaceId The interface identifier.
     * @return supported Whether the interface is supported.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == ERC165_INTERFACE_ID || interfaceId == DAL_CORE_INTERFACE_ID;
    }

    /**
     * @notice Returns the ERC-7201 location of the retirement state, `erc7201:fhevm.storage.ACLRetirement`.
     * @dev `_authorizeUpgrade` requires every new implementation to report this same location.
     * @return location The storage location.
     */
    function retirementStorageLocation() public pure virtual returns (bytes32) {
        return ACL_RETIREMENT_STORAGE_LOCATION;
    }

    /**
     * @dev Should revert when `msg.sender` is not authorized to upgrade the contract.
     *      Also reverts with `UpgradeDropsRetirement` unless the new implementation (a) reports ERC-165 support for
     *      the Decryption Authority Lifecycle Core and (b) reports the same retirement storage location. Both checks
     *      run in the current implementation, before the switch. They stop accidental downgrades and namespace drift,
     *      not an implementation that lies about either answer.
     */
    function _authorizeUpgrade(address _newImplementation) internal virtual override onlyOwner {}

    /// @dev Looks up `userDecryptionDelegations[delegator][delegate][contractAddress]`.
    /// @param contractAddress App contract from the decryption request, or `WILDCARD_DELEGATION_ADDRESS` for the wildcard row.
    function _isUserDecryptionDelegationActive(
        ACLStorage storage $,
        address delegator,
        address delegate,
        address contractAddress
    ) private view returns (bool) {
        return $.userDecryptionDelegations[delegator][delegate][contractAddress].expirationDate > block.timestamp;
    }

    /**
     * @dev Returns the ACL storage location.
     */
    function _getACLStorage() internal pure returns (ACLStorage storage $) {
        assembly {
            $.slot := ACL_STORAGE_LOCATION
        }
    }

    /**
     * @dev Returns the ACL retirement storage location.
     */
    function _retired() internal pure returns (ACLRetirementStorage storage $) {
        assembly {
            $.slot := ACL_RETIREMENT_STORAGE_LOCATION
        }
    }
}
