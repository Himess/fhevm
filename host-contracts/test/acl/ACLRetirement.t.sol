// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ACL} from "../../contracts/ACL.sol";
import {ACLEvents} from "../../contracts/ACLEvents.sol";
import {PauserSet} from "../../contracts/immutable/PauserSet.sol";
import {EmptyUUPSProxyACL} from "../../contracts/emptyProxyACL/EmptyUUPSProxyACL.sol";
import {DeployableERC1967Proxy, HostContractsDeployerTestUtils} from "../../fhevm-foundry/HostContractsDeployerTestUtils.sol";
import {aclAdd, fhevmExecutorAdd, pauserSetAdd, confidentialBridgeAdd} from "../../addresses/FHEVMHostAddresses.sol";
import {ACL as ACL_v0_7_0} from "./retirement/fixtures/ACL_v0_7_0.sol";
import {RetirementTestAccount} from "./retirement/RetirementMocks.sol";

/**
 * @title ACLRetirementTest
 * @notice Account retirement tests for the ACL: views per role, typed errors and lifecycle edges, and a
 *         differential fuzz showing that accounts that never retire behave as before.
 */
contract ACLRetirementTest is HostContractsDeployerTestUtils {
    ACL internal acl;
    PauserSet internal pauserSet;

    address internal constant owner = address(456);
    address internal constant pauser = address(789);

    /// keccak256(abi.encode(uint256(keccak256("fhevm.storage.ACLRetirement")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant RETIREMENT_LOCATION = 0xe6ae1005b480da47ced1ed3eb5869a54ca87c5d592369277249f4148c0e86200;
    bytes4 internal constant CORE_INTERFACE_ID = 0x556d2088;

    address internal user = makeAddr("user");
    address internal other = makeAddr("other");
    address internal delegator = makeAddr("delegator");
    address internal delegate = makeAddr("delegate");
    address internal newAccount = makeAddr("newAccount");
    address internal app;
    address internal app2;

    bytes32 internal h1 = keccak256("handle-1");
    bytes32 internal h2 = keccak256("handle-2");

    function setUp() public {
        _deployACL(owner);
        acl = ACL(aclAdd);
        _deployPauserSet();
        pauserSet = PauserSet(pauserSetAdd);
        vm.prank(owner);
        pauserSet.addPauser(pauser);
        app = address(new RetirementTestAccount());
        app2 = address(new RetirementTestAccount());
    }

    /// @dev Zama's grant sequence (acl.t.sol `_allowHandle`): executor transient grant, persist, clean.
    function _allowHandle(bytes32 handle, address account) internal {
        vm.prank(fhevmExecutorAdd);
        acl.allowTransient(handle, account);
        vm.prank(account);
        acl.allow(handle, account);
        acl.cleanTransientStorage();
    }

    function _retire(address account) internal {
        vm.prank(account);
        acl.retireAccount();
    }

    function _retiredSlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, RETIREMENT_LOCATION));
    }

    /// @dev Sets up delegator -> delegate on `app` (per contract) and on the wildcard, with both handles allowed to
    ///      the delegator, `app` and `app2`.
    function _setUpDelegation() internal returns (uint64 expiry) {
        expiry = uint64(block.timestamp + 1 days);
        _allowHandle(h1, delegator);
        _allowHandle(h1, app);
        _allowHandle(h2, delegator);
        _allowHandle(h2, app2);
        vm.prank(delegator);
        acl.delegateForUserDecryption(delegate, app, expiry);
        vm.roll(block.number + 1);
        address wildcard = acl.WILDCARD_DELEGATION_ADDRESS();
        vm.prank(delegator);
        acl.delegateForUserDecryption(delegate, wildcard, expiry + 1);
        assertTrue(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app, h1));
        assertTrue(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app2, h2));
        assertTrue(acl.isDelegatedForUserDecryption(delegator, delegate, app));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, app), expiry);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Views per role
    ////////////////////////////////////////////////////////////////////////////

    /// @dev A retired user is denied by isAllowed for every caller except the FHEVMExecutor, and by persistAllowed.
    function test_RetiredUser_ViewsAnswerFalse(address caller) public {
        vm.assume(caller != fhevmExecutorAdd);
        _allowHandle(h1, user);
        assertTrue(acl.isAllowed(h1, user));
        assertTrue(acl.persistAllowed(h1, user));

        _retire(user);

        assertTrue(acl.isAccountRetired(user));
        vm.prank(caller);
        assertFalse(acl.isAllowed(h1, user));
        vm.prank(caller);
        assertFalse(acl.persistAllowed(h1, user));
        // Engine exemption: the executor still reads the raw persisted pair for operand checks.
        vm.prank(fhevmExecutorAdd);
        assertTrue(acl.isAllowed(h1, user));
        // persistAllowed has no exemption.
        vm.prank(fhevmExecutorAdd);
        assertFalse(acl.persistAllowed(h1, user));
    }

    /// @dev Transient grants are covered too: the raw getter stays raw (R14), the gated view does not.
    function test_RetiredUser_TransientGrantIsRawOnly() public {
        _retire(user);
        vm.prank(fhevmExecutorAdd);
        acl.allowTransient(h1, user);
        assertTrue(acl.allowedTransient(h1, user), "allowedTransient is the raw primitive");
        assertFalse(acl.isAllowed(h1, user), "non-executor callers see false");
        vm.prank(fhevmExecutorAdd);
        assertTrue(acl.isAllowed(h1, user), "executor operand check still passes");
    }

    /// @dev Retirement is per account: a never-retired holder of the same handle is unaffected.
    function test_RetiredUser_OthersUnaffected() public {
        _allowHandle(h1, user);
        _allowHandle(h1, other);
        _retire(user);
        assertTrue(acl.isAllowed(h1, other));
        assertTrue(acl.persistAllowed(h1, other));
        assertFalse(acl.isAccountRetired(other));
    }

    /// @dev A retired delegator: both delegated views answer false and the getter returns 0, per contract and wildcard.
    function test_RetiredDelegator_DelegatedViewsFalse() public {
        _setUpDelegation();
        _retire(delegator);
        assertFalse(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app, h1));
        assertFalse(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app2, h2));
        assertFalse(acl.isDelegatedForUserDecryption(delegator, delegate, app));
        assertFalse(acl.isDelegatedForUserDecryption(delegator, delegate, app2));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, app), 0);
        assertEq(
            acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, acl.WILDCARD_DELEGATION_ADDRESS()),
            0
        );
    }

    /// @dev A retired delegate stops every delegation it holds, from every delegator.
    function test_RetiredDelegate_AllItsDelegationsStop() public {
        _setUpDelegation();
        address delegator2 = makeAddr("delegator2");
        _allowHandle(h1, delegator2);
        vm.prank(delegator2);
        acl.delegateForUserDecryption(delegate, app, uint64(block.timestamp + 1 days));
        assertTrue(acl.isHandleDelegatedForUserDecryption(delegator2, delegate, app, h1));

        _retire(delegate);

        assertFalse(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app, h1));
        assertFalse(acl.isHandleDelegatedForUserDecryption(delegator2, delegate, app, h1));
        assertFalse(acl.isDelegatedForUserDecryption(delegator, delegate, app));
        assertFalse(acl.isDelegatedForUserDecryption(delegator2, delegate, app));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, app), 0);
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator2, delegate, app), 0);
    }

    /// @dev A retired contract (it retires itself): direct views, both delegated views and the getter all refuse it.
    ///      Delegations for other contracts, including through the same wildcard row, are unaffected.
    function test_RetiredContract_DirectAndDelegatedViewsFalse() public {
        uint64 expiry = _setUpDelegation();
        RetirementTestAccount(payable(app)).execute(address(acl), 0, abi.encodeCall(ACL.retireAccount, ()));
        assertTrue(acl.isAccountRetired(app));

        // Direct path (connector: isAllowed(h, contract); SDK and mock: persistAllowed(h, contract)).
        assertFalse(acl.isAllowed(h1, app));
        assertFalse(acl.persistAllowed(h1, app));
        // Delegated path: the contract role is gated too.
        assertFalse(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app, h1));
        assertFalse(acl.isDelegatedForUserDecryption(delegator, delegate, app));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, app), 0);
        // The wildcard row itself is not a retired party; other contracts still pass through it.
        assertEq(
            acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, acl.WILDCARD_DELEGATION_ADDRESS()),
            expiry + 1
        );
        assertTrue(acl.isHandleDelegatedForUserDecryption(delegator, delegate, app2, h2));
        assertTrue(acl.isDelegatedForUserDecryption(delegator, delegate, app2));
    }

    /// @dev Inbound `allow` to a retired account is accepted (no revert, event emitted, raw pair written) and inert.
    function test_InboundAllowToRetiredAccepted_AndInert() public {
        _allowHandle(h1, other);
        _retire(user);

        vm.expectEmit(address(acl));
        emit ACLEvents.Allowed(other, user, h1);
        vm.prank(other);
        acl.allow(h1, user);

        assertFalse(acl.persistAllowed(h1, user));
        assertFalse(acl.isAllowed(h1, user));
        // The raw pair is written: the executor-path read (the only one that ignores retirement) sees it.
        vm.prank(fhevmExecutorAdd);
        assertTrue(acl.isAllowed(h1, user));
    }

    /// @dev Inbound transient grants (executor) and delegations to a retired delegate or for a retired contract are
    ///      accepted and inert.
    function test_InboundTransientAndDelegationsToRetiredAccepted_AndInert() public {
        _allowHandle(h1, delegator);
        _allowHandle(h1, app);
        _retire(delegate);
        RetirementTestAccount(payable(app)).execute(address(acl), 0, abi.encodeCall(ACL.retireAccount, ()));

        vm.prank(fhevmExecutorAdd);
        acl.allowTransient(h2, delegate);
        assertFalse(acl.isAllowed(h2, delegate));

        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.prank(delegator);
        acl.delegateForUserDecryption(delegate, app2, expiry);
        assertFalse(acl.isDelegatedForUserDecryption(delegator, delegate, app2));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, app2), 0);

        address freshDelegate = makeAddr("freshDelegate");
        vm.roll(block.number + 1);
        vm.prank(delegator);
        acl.delegateForUserDecryption(freshDelegate, app, expiry);
        assertFalse(acl.isHandleDelegatedForUserDecryption(delegator, freshDelegate, app, h1));
        assertFalse(acl.isDelegatedForUserDecryption(delegator, freshDelegate, app));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, freshDelegate, app), 0);
    }

    /// @dev R9: public decryption is unchanged and retirement never un-publishes.
    function test_PublicDecryptionUnchanged() public {
        _allowHandle(h1, user);
        bytes32[] memory list = new bytes32[](1);
        list[0] = h1;
        vm.prank(user);
        acl.allowForDecryption(list);
        _retire(user);
        assertTrue(acl.isAllowedForDecryption(h1));
    }

    ////////////////////////////////////////////////////////////////////////////
    // Typed errors, ERC-165, lifecycle edges
    ////////////////////////////////////////////////////////////////////////////

    function test_RetireAccount_SetsBitInNamespaceAndEmits(address account) public {
        vm.assume(account != address(0));
        assertEq(vm.load(address(acl), _retiredSlot(account)), bytes32(0));
        vm.expectEmit(true, true, true, true, address(acl));
        emit ACLEvents.AccountRetired(account, address(0));
        vm.prank(account);
        acl.retireAccount();
        assertTrue(acl.isAccountRetired(account));
        assertEq(vm.load(address(acl), _retiredSlot(account)), bytes32(uint256(1)));
    }

    function test_SecondRetirementReverts_NoSecondEvent() public {
        _retire(user);
        vm.recordLogs();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.AccountAlreadyRetired.selector, user));
        acl.retireAccount();
        assertEq(vm.getRecordedLogs().length, 0);
        assertTrue(acl.isAccountRetired(user));
    }

    function test_TypedErrors_GrantPathsRevertSenderRetired() public {
        _allowHandle(h1, user);
        _retire(user);
        bytes32[] memory list = new bytes32[](1);
        list[0] = h1;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, user));
        acl.allow(h1, newAccount);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, user));
        acl.allowForDecryption(list);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, user));
        acl.allowTransient(h1, newAccount);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, user));
        acl.delegateForUserDecryption(delegate, app, uint64(block.timestamp + 1 days));
    }

    /// @dev The typed error replaces SenderNotAllowed only in the failure branch: unallowed never-retired senders
    ///      keep the existing error, deny-list and pause checks keep their precedence.
    function test_TypedErrors_PrecedenceUnchanged() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderNotAllowed.selector, user));
        acl.allow(h1, newAccount);

        _allowHandle(h1, user);
        _retire(user);
        vm.prank(owner);
        acl.blockAccount(user);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderDenied.selector, user));
        acl.allow(h1, newAccount);

        vm.prank(pauser);
        acl.pause();
        vm.prank(user);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        acl.allow(h1, newAccount);
        vm.prank(user);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        acl.delegateForUserDecryption(delegate, app, uint64(block.timestamp + 1 days));
    }

    /// @dev Delegating to a retired delegate or for a retired contract does not revert (R8); only a retired caller does.
    function test_DelegateToRetiredDoesNotRevert() public {
        _retire(delegate);
        vm.prank(delegator);
        acl.delegateForUserDecryption(delegate, app, uint64(block.timestamp + 1 days));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(delegator, delegate, app), 0);
    }

    function test_ERC165() public view {
        assertTrue(acl.supportsInterface(0x01ffc9a7));
        assertTrue(acl.supportsInterface(CORE_INTERFACE_ID));
        assertFalse(acl.supportsInterface(0xffffffff));
        assertFalse(acl.supportsInterface(0x00000000));
        // The Core id is retireAccount() XOR isAccountRetired(address).
        assertEq(ACL.retireAccount.selector, bytes4(0xe7142996));
        assertEq(ACL.isAccountRetired.selector, bytes4(0xb279091e));
        assertEq(ACL.retireAccount.selector ^ ACL.isAccountRetired.selector, CORE_INTERFACE_ID);
        assertEq(ACL.supportsInterface.selector, bytes4(0x01ffc9a7));
        assertEq(ACL.retirementStorageLocation.selector, bytes4(0xc89c7ccd));
    }

    function test_ERC165_FuzzUnknownIds(bytes4 id) public view {
        vm.assume(id != 0x01ffc9a7 && id != CORE_INTERFACE_ID);
        assertFalse(acl.supportsInterface(id));
    }

    function test_RetirementStorageLocationIsERC7201() public view {
        bytes32 expected = keccak256(abi.encode(uint256(keccak256("fhevm.storage.ACLRetirement")) - 1)) &
            ~bytes32(uint256(0xff));
        assertEq(expected, RETIREMENT_LOCATION);
        assertEq(acl.retirementStorageLocation(), RETIREMENT_LOCATION);
        // Distinct from the existing ACL namespace.
        assertTrue(RETIREMENT_LOCATION != 0xa688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00);
    }

    function test_RetirementWorksWhilePaused() public {
        vm.prank(pauser);
        acl.pause();
        _retire(user);
        assertTrue(acl.isAccountRetired(user));
    }

    function test_RetirementWorksWhileDenyListed() public {
        vm.prank(owner);
        acl.blockAccount(user);
        _retire(user);
        assertTrue(acl.isAccountRetired(user));
        assertTrue(acl.isAccountDenied(user));
    }

    /// @dev R3: a contract retires itself.
    function test_ContractCanRetireItself() public {
        RetirementTestAccount(payable(app)).execute(address(acl), 0, abi.encodeCall(ACL.retireAccount, ()));
        assertTrue(acl.isAccountRetired(app));
    }

    /// @dev R2: nothing the owner or a pauser can do clears the bit.
    function test_RetirementIsOneWay() public {
        _retire(user);
        vm.startPrank(owner);
        acl.blockAccount(user);
        acl.unblockAccount(user);
        vm.stopPrank();
        vm.prank(pauser);
        acl.pause();
        vm.prank(owner);
        acl.unpause();
        assertTrue(acl.isAccountRetired(user));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.AccountAlreadyRetired.selector, user));
        acl.retireAccount();
    }

    function _carryCalls(bool retireLast) internal view returns (bytes[] memory calls) {
        calls = new bytes[](3);
        if (retireLast) {
            calls[0] = abi.encodeCall(ACL.allow, (h1, newAccount));
            calls[1] = abi.encodeCall(ACL.allow, (h2, newAccount));
            calls[2] = abi.encodeCall(ACL.retireAccount, ());
        } else {
            calls[0] = abi.encodeCall(ACL.retireAccount, ());
            calls[1] = abi.encodeCall(ACL.allow, (h1, newAccount));
            calls[2] = abi.encodeCall(ACL.allow, (h2, newAccount));
        }
    }

    /// @dev Carry: grants first, then retire, in one caller-preserving multicall (R13). Atomic.
    function test_CarryMulticall_GrantsThenRetire() public {
        _allowHandle(h1, user);
        _allowHandle(h2, user);
        vm.expectEmit(address(acl));
        emit ACLEvents.Allowed(user, newAccount, h1);
        vm.expectEmit(address(acl));
        emit ACLEvents.Allowed(user, newAccount, h2);
        vm.expectEmit(address(acl));
        emit ACLEvents.AccountRetired(user, address(0));
        vm.prank(user);
        acl.multicall(_carryCalls(true));

        assertTrue(acl.isAccountRetired(user));
        assertTrue(acl.persistAllowed(h1, newAccount));
        assertTrue(acl.persistAllowed(h2, newAccount));
        assertFalse(acl.persistAllowed(h1, user));
    }

    /// @dev The reverse order reverts with SenderRetired and rolls back the retirement too (atomic).
    function test_CarryMulticall_ReverseOrderReverts() public {
        _allowHandle(h1, user);
        _allowHandle(h2, user);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, user));
        acl.multicall(_carryCalls(false));
        assertFalse(acl.isAccountRetired(user));
        assertFalse(acl.persistAllowed(h1, newAccount));
        assertTrue(acl.persistAllowed(h1, user));
    }

    /// @dev Carry while paused reverts (allow is pause-gated) and changes nothing; retiring alone still works.
    function test_CarryDuringPauseReverts() public {
        _allowHandle(h1, user);
        _allowHandle(h2, user);
        vm.prank(pauser);
        acl.pause();
        vm.prank(user);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        acl.multicall(_carryCalls(true));
        assertFalse(acl.isAccountRetired(user));
        assertFalse(acl.persistAllowed(h1, newAccount));

        vm.prank(owner);
        acl.unpause();
        vm.prank(user);
        acl.multicall(_carryCalls(true));
        assertTrue(acl.isAccountRetired(user));
        assertTrue(acl.persistAllowed(h1, newAccount));
    }

    /// @dev Unchanged surfaces stay callable by a retired account: revocation (also while paused on main) and
    ///      signature invalidation.
    function test_RetiredAccountCanStillRevokeAndInvalidate() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.prank(delegator);
        acl.delegateForUserDecryption(delegate, app, expiry);
        _retire(delegator);
        vm.roll(block.number + 1);
        vm.prank(pauser);
        acl.pause();
        vm.prank(delegator);
        acl.revokeDelegationForUserDecryption(delegate, app);
        vm.prank(owner);
        acl.unpause();
        vm.warp(block.timestamp + 10);
        vm.prank(delegator);
        acl.invalidateDecryptionSignaturesBefore(0);
        assertEq(acl.decryptionSignatureInvalidatedBefore(delegator), block.timestamp);
    }

    /// @dev Retirement and the deny list are independent state.
    function test_RetirementAndDenyListIndependent() public {
        _retire(user);
        assertFalse(acl.isAccountDenied(user));
        vm.prank(owner);
        acl.blockAccount(other);
        assertFalse(acl.isAccountRetired(other));
    }

    /// @dev Since v0.8.0 the guard refuses EmptyUUPSProxyACL (no escape hatch to a Core-less implementation).
    function test_GuardRefusesEmptyProxyImplementation() public {
        address empty = address(new EmptyUUPSProxyACL());
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, empty));
        acl.upgradeToAndCall(empty, "");
    }

    /// @dev Ownership is checked first: a non-owner gets the existing Ownable error, not the guard's.
    function test_GuardRunsAfterOwnerCheck(address notOwner) public {
        vm.assume(notOwner != owner);
        address empty = address(new EmptyUUPSProxyACL());
        vm.prank(notOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notOwner));
        acl.upgradeToAndCall(empty, "");
    }

    ////////////////////////////////////////////////////////////////////////////
    // Differential, accounts that never retire: v0.8.0 answers exactly as v0.7.0
    ////////////////////////////////////////////////////////////////////////////

    function _deployStandaloneProxy(address implementation) internal returns (ACL proxied) {
        address emptyImplementation = address(new EmptyUUPSProxyACL());
        DeployableERC1967Proxy proxy = new DeployableERC1967Proxy(
            emptyImplementation,
            abi.encodeCall(EmptyUUPSProxyACL.initialize, (owner))
        );
        vm.prank(owner);
        EmptyUUPSProxyACL(address(proxy)).upgradeToAndCall(
            implementation,
            abi.encodeWithSignature("initializeFromEmptyProxy()")
        );
        proxied = ACL(address(proxy));
    }

    function _applyOp(ACL target, uint8 op, address a, address b, address c, bytes32 h, uint64 t) internal {
        op = op % 6;
        if (op == 0) {
            vm.prank(fhevmExecutorAdd);
            target.allowTransient(h, a);
            vm.prank(a);
            try target.allow(h, b) {} catch {}
        } else if (op == 1) {
            vm.prank(a);
            try target.delegateForUserDecryption(b, c, t) {} catch {}
        } else if (op == 2) {
            vm.prank(a);
            try target.revokeDelegationForUserDecryption(b, c) {} catch {}
        } else if (op == 3) {
            bytes32[] memory list = new bytes32[](1);
            list[0] = h;
            vm.prank(a);
            try target.allowForDecryption(list) {} catch {}
        } else if (op == 4) {
            vm.prank(a);
            try target.allow(h, b) {} catch {}
        } else {
            target.cleanTransientStorage();
        }
    }

    function _assertSameViews(ACL a, ACL b, address x, address y, address z, bytes32 h) internal {
        address[3] memory callers = [x, fhevmExecutorAdd, address(this)];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.prank(callers[i]);
            bool va = a.isAllowed(h, y);
            vm.prank(callers[i]);
            bool vb = b.isAllowed(h, y);
            assertEq(va, vb, "isAllowed");
        }
        assertEq(a.persistAllowed(h, y), b.persistAllowed(h, y), "persistAllowed");
        assertEq(a.allowedTransient(h, y), b.allowedTransient(h, y), "allowedTransient");
        assertEq(a.isAllowedForDecryption(h), b.isAllowedForDecryption(h), "isAllowedForDecryption");
        assertEq(
            a.isHandleDelegatedForUserDecryption(x, y, z, h),
            b.isHandleDelegatedForUserDecryption(x, y, z, h),
            "isHandleDelegatedForUserDecryption"
        );
        assertEq(a.isDelegatedForUserDecryption(x, y, z), b.isDelegatedForUserDecryption(x, y, z), "isDelegated");
        assertEq(
            a.getUserDecryptionDelegationExpirationDate(x, y, z),
            b.getUserDecryptionDelegationExpirationDate(x, y, z),
            "expiry"
        );
    }

    /// forge-config: default.fuzz.runs = 512
    /// @dev Same random operation sequence on a v0.7.0 proxy (fixture) and a v0.8.0 proxy, never-retired accounts
    ///      only: every view answers identically, for every caller kind.
    function test_Differential_NeverRetiredMatchesV070(
        uint8[6] memory ops,
        address[3] memory actors,
        bytes32 handle,
        uint32 dt
    ) public {
        for (uint256 i = 0; i < 3; i++) {
            vm.assume(actors[i] != fhevmExecutorAdd && actors[i] != confidentialBridgeAdd && actors[i] != address(0));
        }
        ACL base = _deployStandaloneProxy(address(new ACL_v0_7_0()));
        ACL next = _deployStandaloneProxy(address(new ACL()));
        uint64 t = uint64(block.timestamp) + 1 + uint64(dt);
        for (uint256 i = 0; i < ops.length; i++) {
            vm.roll(block.number + 1);
            address a = actors[i % 3];
            address b = actors[(i + 1) % 3];
            address c = actors[(i + 2) % 3];
            _applyOp(base, ops[i], a, b, c, handle, t);
            _applyOp(next, ops[i], a, b, c, handle, t);
            for (uint256 j = 0; j < 3; j++) {
                _assertSameViews(base, next, actors[j], actors[(j + 1) % 3], actors[(j + 2) % 3], handle);
            }
        }
    }
}
