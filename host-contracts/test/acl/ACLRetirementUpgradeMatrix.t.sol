// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ACL} from "../../contracts/ACL.sol";
import {EmptyUUPSProxyACL} from "../../contracts/emptyProxyACL/EmptyUUPSProxyACL.sol";
import {HostContractsDeployerTestUtils} from "../../fhevm-foundry/HostContractsDeployerTestUtils.sol";
import {aclAdd, fhevmExecutorAdd} from "../../addresses/FHEVMHostAddresses.sol";
import {ACLUpgradedExample} from "../../examples/ACLUpgradedExample.sol";
import {ACL as ACL_v0_4_0} from "./retirement/fixtures/ACL_v0_4_0.sol";
import {ACL as ACL_v0_4_1} from "./retirement/fixtures/ACL_v0_4_1.sol";
import {ACL as ACL_v0_4_1_noguard} from "./retirement/fixtures/ACL_v0_4_1_noguard.sol";
import {ACL as ACL_v0_5_0} from "./retirement/fixtures/ACL_v0_5_0.sol";
import {ACL as ACL_v0_7_0} from "./retirement/fixtures/ACL_v0_7_0.sol";
import {ACL as ACL_v0_8_0_drift} from "./retirement/fixtures/ACL_v0_8_0_drift.sol";
import {ACLLocationOnlyNoCore, ACLCoreOtherLocation, RetirementTestAccount} from "./retirement/RetirementMocks.sol";

/// @notice U7: a lying implementation. ACL v0.7.0 code (no retirement enforcement) that answers the guard's two
///         questions exactly like a Core release.
contract ACLLyingV070 is ACL_v0_7_0 {
    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }

    function retirementStorageLocation() external pure returns (bytes32) {
        return 0xe6ae1005b480da47ced1ed3eb5869a54ca87c5d592369277249f4148c0e86200;
    }
}

/**
 * @title ACLRetirementUpgradeMatrixTest
 * @notice Upgrade matrix U1-U7 (and U0, the main production path), with the empty-proxy deploy flow
 *         (EmptyUUPSProxyACL behind an ERC1967 proxy at `aclAdd`, then `upgradeToAndCall(impl, initializer)`) and
 *         Zama's upgrade call (`upgradeToAndCall(newImpl, reinitializeV{N-1}())`, tasks/upgradeContracts.ts).
 *         Older releases are verbatim fixtures (test/acl/retirement/fixtures, provenance in each header).
 */
contract ACLRetirementUpgradeMatrixTest is HostContractsDeployerTestUtils {
    address internal constant owner = address(456);

    bytes32 internal constant ACL_LOCATION = 0xa688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00;
    bytes32 internal constant RETIREMENT_LOCATION = 0xe6ae1005b480da47ced1ed3eb5869a54ca87c5d592369277249f4148c0e86200;
    /// OZ Initializable namespace (`_initialized` lives in its low 64 bits).
    bytes32 internal constant INITIALIZABLE_STORAGE =
        0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    ACL internal acl = ACL(aclAdd);

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal denied = makeAddr("denied");
    address internal retiredUser = makeAddr("retiredUser");
    address internal retiredDelegator = makeAddr("retiredDelegator");
    address internal app;
    address internal retiredApp;

    bytes32 internal h1 = keccak256("matrix-handle-1");
    bytes32 internal h2 = keccak256("matrix-handle-2");
    uint64 internal expiry;

    function setUp() public {
        _deployPauserSet();
        app = address(new RetirementTestAccount());
        retiredApp = address(new RetirementTestAccount());
        expiry = uint64(block.timestamp + 30 days);
    }

    ////////////////////////////////////////////////////////////////////////////
    // helpers
    ////////////////////////////////////////////////////////////////////////////

    /// @dev Zama's `_deployACL`, with the implementation chosen by the test.
    function _deployProxyWith(address implementation) internal {
        address emptyProxyImplementation = address(new EmptyUUPSProxyACL());
        deployCodeTo(
            "fhevm-foundry/HostContractsDeployerTestUtils.sol:DeployableERC1967Proxy",
            abi.encode(emptyProxyImplementation, abi.encodeCall(EmptyUUPSProxyACL.initialize, (owner))),
            aclAdd
        );
        vm.prank(owner);
        EmptyUUPSProxyACL(aclAdd).upgradeToAndCall(
            implementation,
            abi.encodeWithSignature("initializeFromEmptyProxy()")
        );
    }

    function _upgradeCall(address implementation, string memory reinitializer) internal pure returns (bytes memory) {
        return
            abi.encodeCall(
                UUPSUpgradeable.upgradeToAndCall,
                (implementation, bytes(reinitializer).length == 0 ? bytes("") : abi.encodeWithSignature(reinitializer))
            );
    }

    function _upgrade(address implementation, string memory reinitializer) internal {
        vm.prank(owner);
        (bool ok, bytes memory err) = aclAdd.call(_upgradeCall(implementation, reinitializer));
        if (!ok) {
            assembly {
                revert(add(err, 32), mload(err))
            }
        }
    }

    function _expectUpgradeRevert(address implementation, string memory reinitializer, bytes memory expected) internal {
        address before = _implementation();
        vm.prank(owner);
        (bool ok, bytes memory err) = aclAdd.call(_upgradeCall(implementation, reinitializer));
        assertFalse(ok, "upgrade must revert");
        assertEq(err, expected);
        assertEq(_implementation(), before, "implementation unchanged");
    }

    function _implementation() internal view returns (address) {
        return address(uint160(uint256(vm.load(aclAdd, IMPLEMENTATION_SLOT))));
    }

    function _initializedVersion() internal view returns (uint64) {
        return uint64(uint256(vm.load(aclAdd, INITIALIZABLE_STORAGE)));
    }

    function _retiredSlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, RETIREMENT_LOCATION));
    }

    function _pairSlot(bytes32 handle, address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, keccak256(abi.encode(handle, uint256(ACL_LOCATION)))));
    }

    function _denySlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, uint256(ACL_LOCATION) + 3));
    }

    function _allowHandle(bytes32 handle, address account) internal {
        vm.prank(fhevmExecutorAdd);
        acl.allowTransient(handle, account);
        vm.prank(account);
        acl.allow(handle, account);
        acl.cleanTransientStorage();
    }

    /// @dev State every release can hold: persisted pairs, a delegation, a public handle, a deny-list entry.
    function _seedState() internal {
        _allowHandle(h1, alice);
        _allowHandle(h1, app);
        _allowHandle(h1, retiredUser);
        _allowHandle(h1, retiredDelegator);
        _allowHandle(h1, retiredApp);
        _allowHandle(h2, carol);
        vm.prank(alice);
        acl.delegateForUserDecryption(bob, app, expiry);
        vm.prank(retiredDelegator);
        acl.delegateForUserDecryption(bob, app, expiry);
        vm.prank(alice);
        acl.delegateForUserDecryption(carol, retiredApp, expiry);
        bytes32[] memory list = new bytes32[](1);
        list[0] = h2;
        vm.prank(carol);
        acl.allowForDecryption(list);
        vm.prank(owner);
        acl.blockAccount(denied);
    }

    /// @dev Retire a user, a delegator and a contract (the contract retires itself) on a Core release.
    function _retireThree() internal {
        vm.prank(retiredUser);
        acl.retireAccount();
        vm.prank(retiredDelegator);
        acl.retireAccount();
        RetirementTestAccount(payable(retiredApp)).execute(aclAdd, 0, abi.encodeCall(ACL.retireAccount, ()));
    }

    /// @dev Never-retired state is intact (works on every release).
    function _assertBaseStatePreserved() internal view {
        assertTrue(acl.persistAllowed(h1, alice));
        assertTrue(acl.persistAllowed(h1, app));
        assertTrue(acl.isAllowed(h1, alice));
        assertTrue(acl.isHandleDelegatedForUserDecryption(alice, bob, app, h1));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(alice, bob, app), expiry);
        assertTrue(acl.isAllowedForDecryption(h2));
        assertTrue(acl.isAccountDenied(denied));
        assertEq(acl.owner(), owner);
        // Raw layout of fhevm.storage.ACL: the same slots hold the same values.
        assertEq(vm.load(aclAdd, _pairSlot(h1, alice)), bytes32(uint256(1)));
        assertEq(vm.load(aclAdd, _denySlot(denied)), bytes32(uint256(1)));
    }

    /// @dev Retirement bits and enforcement for the three retired parties, on a Core release.
    function _assertEnforced() internal {
        assertTrue(acl.isAccountRetired(retiredUser));
        assertTrue(acl.isAccountRetired(retiredDelegator));
        assertTrue(acl.isAccountRetired(retiredApp));
        assertEq(vm.load(aclAdd, _retiredSlot(retiredUser)), bytes32(uint256(1)));
        assertFalse(acl.isAllowed(h1, retiredUser));
        assertFalse(acl.persistAllowed(h1, retiredUser));
        assertFalse(acl.persistAllowed(h1, retiredApp));
        assertFalse(acl.isHandleDelegatedForUserDecryption(retiredDelegator, bob, app, h1));
        assertFalse(acl.isHandleDelegatedForUserDecryption(alice, carol, retiredApp, h1));
        assertEq(acl.getUserDecryptionDelegationExpirationDate(retiredDelegator, bob, app), 0);
        vm.prank(fhevmExecutorAdd);
        assertTrue(acl.isAllowed(h1, retiredUser), "engine exemption intact");
        vm.prank(retiredUser);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, retiredUser));
        acl.allow(h1, carol);
    }

    ////////////////////////////////////////////////////////////////////////////
    // U0: main production path, v0.7.0 -> v0.8.0
    ////////////////////////////////////////////////////////////////////////////

    function test_U0_v070_to_v080_StatePreserved_CoreActive() public {
        _deployProxyWith(address(new ACL_v0_7_0()));
        assertEq(acl.getVersion(), "ACL v0.7.0");
        _seedState();
        vm.warp(block.timestamp + 100);
        vm.prank(alice);
        acl.invalidateDecryptionSignaturesBefore(0);
        uint256 invalidatedBefore = acl.decryptionSignatureInvalidatedBefore(alice);

        // The first Core upgrade is authorized by v0.7.0's empty _authorizeUpgrade.
        _upgrade(address(new ACL()), "reinitializeV8()");

        assertEq(acl.getVersion(), "ACL v0.8.0");
        assertEq(_initializedVersion(), 9);
        _assertBaseStatePreserved();
        assertEq(acl.decryptionSignatureInvalidatedBefore(alice), invalidatedBefore);
        assertFalse(acl.isAccountRetired(retiredUser), "no retirement state before the first retire");
        _retireThree();
        _assertEnforced();
        // From now on the guard is live: no rollback to the Core-less predecessor.
        address v070 = address(new ACL_v0_7_0());
        _expectUpgradeRevert(v070, "", abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, v070));
    }

    /// @dev Zama's pattern (fhevmExecutor.t.sol test_reinitializeV7SucceedsOnUpgradePath): reinitializeV8 lands on
    ///      exactly 9 from the previous release's version 8, and a second call reverts.
    function test_reinitializeV8SucceedsOnUpgradePath() public {
        _deployProxyWith(address(new ACL_v0_7_0()));
        assertEq(_initializedVersion(), 8);
        _upgrade(address(new ACL()), "");
        ACL(aclAdd).reinitializeV8();
        assertEq(_initializedVersion(), 9);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        ACL(aclAdd).reinitializeV8();
    }

    ////////////////////////////////////////////////////////////////////////////
    // U1: v0.4.0 -> v0.4.1 (storage layout; also checked with OZ upgrades-core's validateUpgrade)
    ////////////////////////////////////////////////////////////////////////////

    function test_U1_v040_to_v041_LayoutAndStatePreserved() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        assertEq(acl.getVersion(), "ACL v0.4.0");
        assertEq(_initializedVersion(), 5);
        _seedState();

        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");

        assertEq(acl.getVersion(), "ACL v0.4.1");
        assertEq(_initializedVersion(), 6);
        _assertBaseStatePreserved();
        assertEq(vm.load(aclAdd, _retiredSlot(retiredUser)), bytes32(0), "retirement namespace starts empty");
        _retireThree();
        _assertEnforced();
    }

    ////////////////////////////////////////////////////////////////////////////
    // U2: v0.4.1 -> v0.8.0, bits and enforcement preserved
    ////////////////////////////////////////////////////////////////////////////

    function test_U2_v041_to_v080_BitsAndEnforcementPreserved() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        _retireThree();
        _assertEnforced();

        // Guard in v0.4.1 accepts v0.8.0 (declares Core, same location); reinitializer 6 -> 9.
        _upgrade(address(new ACL()), "reinitializeV8()");

        assertEq(acl.getVersion(), "ACL v0.8.0");
        assertEq(_initializedVersion(), 9);
        _assertBaseStatePreserved();
        _assertEnforced();
        assertFalse(acl.isDelegatedForUserDecryption(retiredDelegator, bob, app), "new main-only view gated too");
        assertTrue(acl.isDelegatedForUserDecryption(alice, bob, app));
    }

    ////////////////////////////////////////////////////////////////////////////
    // U3: guard-less v0.4.1 -> v0.7.0 succeeds and enforcement lapses (hazard demo)
    ////////////////////////////////////////////////////////////////////////////

    function test_U3_GuardlessV041_to_v070_EnforcementLapses() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1_noguard()), "reinitializeV5()");
        _retireThree();
        _assertEnforced();

        _upgrade(address(new ACL_v0_7_0()), "reinitializeV7()");

        assertEq(acl.getVersion(), "ACL v0.7.0");
        // The bits are still in storage ...
        assertEq(vm.load(aclAdd, _retiredSlot(retiredUser)), bytes32(uint256(1)));
        assertEq(vm.load(aclAdd, _retiredSlot(retiredApp)), bytes32(uint256(1)));
        // ... but nothing reads them: every gated view answers true again, the retired key can grant again.
        assertTrue(acl.isAllowed(h1, retiredUser));
        assertTrue(acl.persistAllowed(h1, retiredUser));
        assertTrue(acl.persistAllowed(h1, retiredApp));
        assertTrue(acl.isHandleDelegatedForUserDecryption(retiredDelegator, bob, app, h1));
        assertTrue(acl.isHandleDelegatedForUserDecryption(alice, carol, retiredApp, h1));
        vm.prank(retiredUser);
        acl.allow(h1, carol);
        assertTrue(acl.persistAllowed(h1, carol));
        (bool ok, ) = aclAdd.staticcall(abi.encodeCall(ACL.isAccountRetired, (retiredUser)));
        assertFalse(ok, "v0.7.0 has no retirement view");
    }

    ////////////////////////////////////////////////////////////////////////////
    // U4: v0.4.1 -> v0.7.0 reverts UpgradeDropsRetirement
    ////////////////////////////////////////////////////////////////////////////

    function test_U4_v041_to_v070_RevertsUpgradeDropsRetirement() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        _retireThree();

        address v070 = address(new ACL_v0_7_0());
        _expectUpgradeRevert(
            v070,
            "reinitializeV7()",
            abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, v070)
        );
        _expectUpgradeRevert(v070, "", abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, v070));

        assertEq(acl.getVersion(), "ACL v0.4.1");
        _assertBaseStatePreserved();
        _assertEnforced();
    }

    ////////////////////////////////////////////////////////////////////////////
    // U4b: a Core-declaring implementation with another namespace reverts (and why the check is needed)
    ////////////////////////////////////////////////////////////////////////////

    function test_U4b_CoreDeclaringOtherNamespace_Reverts() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        _retireThree();

        // Storage-level drift: v0.8.0 code with the retirement state in fhevm.storage.ACLRetirementDrift.
        address drift = address(new ACL_v0_8_0_drift());
        assertTrue(ACL(drift).supportsInterface(0x556d2088), "the drifted release declares Core");
        _expectUpgradeRevert(
            drift,
            "reinitializeV8()",
            abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, drift)
        );
        // Report-level drift: declares Core, reports another location.
        address other = address(new ACLCoreOtherLocation());
        _expectUpgradeRevert(
            other,
            "reinitializeV8()",
            abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, other)
        );

        // The same from v0.8.0.
        _upgrade(address(new ACL()), "reinitializeV8()");
        drift = address(new ACL_v0_8_0_drift());
        _expectUpgradeRevert(drift, "", abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, drift));
        _assertEnforced();
    }

    /// @dev Why ERC-165 alone is not enough: without the guard, the drifted Core release silently resets every
    ///      retirement (it reads an empty namespace).
    function test_U4b_WithoutLocationCheckDriftResetsRetirements() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1_noguard()), "reinitializeV5()");
        _retireThree();
        _upgrade(address(new ACL_v0_8_0_drift()), "reinitializeV8()");
        assertFalse(acl.isAccountRetired(retiredUser), "retirement reset");
        assertTrue(acl.isAllowed(h1, retiredUser));
        assertEq(vm.load(aclAdd, _retiredSlot(retiredUser)), bytes32(uint256(1)), "old bits orphaned in storage");
    }

    ////////////////////////////////////////////////////////////////////////////
    // U4c: the location getter without Core reverts; Core-less targets revert (no escape hatch)
    ////////////////////////////////////////////////////////////////////////////

    function test_U4c_LocationWithoutCore_Reverts() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        address locationOnly = address(new ACLLocationOnlyNoCore());
        _expectUpgradeRevert(
            locationOnly,
            "reinitializeV8()",
            abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, locationOnly)
        );
        // Rollback to the Core-less predecessor and to the empty proxy are refused too.
        address v040 = address(new ACL_v0_4_0());
        _expectUpgradeRevert(v040, "", abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, v040));
        address empty = address(new EmptyUUPSProxyACL());
        _expectUpgradeRevert(empty, "", abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, empty));
        // An EOA or a codeless address is refused (staticcall succeeds with empty return data).
        _expectUpgradeRevert(carol, "", abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, carol));
    }

    ////////////////////////////////////////////////////////////////////////////
    // U5: v0.4.1 -> v0.5.0
    ////////////////////////////////////////////////////////////////////////////

    /// @dev A reinitializer collision would revert InvalidInitialization. With the guard in v0.4.1, `_authorizeUpgrade` runs first
    ///      (OZ UUPSUpgradeable.upgradeToAndCall), so the observed revert is UpgradeDropsRetirement. The
    ///      reinitializer collision (both take 6) is shown on the guard-less build: InvalidInitialization.
    function test_U5_v041_to_v050_GuardFiresFirst_CollisionBehindIt() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        address v050 = address(new ACL_v0_5_0());
        _expectUpgradeRevert(
            v050,
            "reinitializeV5()",
            abi.encodeWithSelector(ACL.UpgradeDropsRetirement.selector, v050)
        );
    }

    function test_U5_v041_to_v050_ReinitializerCollision() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _upgrade(address(new ACL_v0_4_1_noguard()), "reinitializeV5()");
        assertEq(_initializedVersion(), 6);
        address v050 = address(new ACL_v0_5_0());
        _expectUpgradeRevert(
            v050,
            "reinitializeV5()",
            abi.encodeWithSelector(Initializable.InvalidInitialization.selector)
        );
    }

    ////////////////////////////////////////////////////////////////////////////
    // U7: a lying implementation passes the guard (asserted residual)
    ////////////////////////////////////////////////////////////////////////////

    function test_U7_LyingImplementationPassesGuard_AssertedResidual() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        _upgrade(address(new ACL()), "reinitializeV8()");
        _retireThree();
        _assertEnforced();

        // The guard only asks; it cannot check the answers against the code. Residual: canary and pinning (L3).
        _upgrade(address(new ACLLyingV070()), "");
        assertTrue(acl.isAllowed(h1, retiredUser), "residual: enforcement lapses under a lying implementation");
        assertTrue(acl.isHandleDelegatedForUserDecryption(retiredDelegator, bob, app, h1));
        assertEq(vm.load(aclAdd, _retiredSlot(retiredUser)), bytes32(uint256(1)));
    }

    function test_U7_LyingImplementationFromV041_AssertedResidual() public {
        _deployProxyWith(address(new ACL_v0_4_0()));
        _seedState();
        _upgrade(address(new ACL_v0_4_1()), "reinitializeV5()");
        _retireThree();
        _upgrade(address(new ACLLyingV070()), "reinitializeV7()");
        assertTrue(acl.persistAllowed(h1, retiredUser), "residual: enforcement lapses under a lying implementation");
    }

    ////////////////////////////////////////////////////////////////////////////
    // Guard does not block legitimate Core successors
    ////////////////////////////////////////////////////////////////////////////

    function test_GuardAcceptsCoreSuccessors() public {
        _deployProxyWith(address(new ACL()));
        _seedState();
        _retireThree();
        // Same release redeployed, and Zama's own upgrade example (inherits ACL, hence Core).
        _upgrade(address(new ACL()), "");
        _upgrade(address(new ACLUpgradedExample()), "");
        _assertBaseStatePreserved();
        _assertEnforced();
    }
}
