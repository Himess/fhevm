// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {ACL} from "../../contracts/ACL.sol";
import {FHEVMExecutor} from "../../contracts/FHEVMExecutor.sol";
import {FheType} from "../../contracts/shared/FheType.sol";
import {EmptyUUPSProxyACL} from "../../contracts/emptyProxyACL/EmptyUUPSProxyACL.sol";
import {HostContractsDeployerTestUtils} from "../../fhevm-foundry/HostContractsDeployerTestUtils.sol";
import {aclAdd, fhevmExecutorAdd, hcuLimitAdd, pauserSetAdd} from "../../addresses/FHEVMHostAddresses.sol";
import {euint64} from "../../lib/FHE.sol";
import {ACL as ACL_v0_7_0} from "./retirement/fixtures/ACL_v0_7_0.sol";
import {ACL as ACL_v0_8_0_attribution} from "./retirement/fixtures/ACL_v0_8_0_attribution.sol";
import {ERC7984RetirementToken} from "./retirement/RetirementMocks.sol";

interface IVmEvmVersion {
    function getEvmVersion() external view returns (string memory);
}

/**
 * @title ACLRetirementGasTest
 * @notice Gas of account retirement: ACL v0.7.0 (a fixture of the earlier release) against ACL v0.8.0, each deployed
 *         at the canonical addresses with Zama's empty-proxy flow. Before every measured call all touched accounts
 *         and slots are cooled (`vm.cool`), as at the start of a transaction. Numbers are the execution gas of the
 *         called frame (`vm.lastCallGas().gasTotalUsed`): no intrinsic or calldata gas. Run per hardfork with
 *         `--evm-version prague|osaka|amsterdam`; lines start with `GAS|`.
 */
contract ACLRetirementGasTest is HostContractsDeployerTestUtils {
    address internal constant owner = address(456);
    bytes32 internal constant ACL_LOCATION = 0xa688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00;

    address internal user = makeAddr("gas-user");
    address internal recipient = makeAddr("gas-recipient");
    address internal delegator = makeAddr("gas-delegator");
    address internal delegate = makeAddr("gas-delegate");
    address internal app = makeAddr("gas-app");

    address internal aclImpl;
    address internal execImpl;
    address internal hcuImpl;
    ERC7984RetirementToken internal token;

    function _deployStack(bool withRetirement) internal {
        _deployStackImpl(withRetirement ? address(new ACL()) : address(new ACL_v0_7_0()));
    }

    function _deployStackImpl(address impl) internal {
        address emptyProxyImplementation = address(new EmptyUUPSProxyACL());
        deployCodeTo(
            "fhevm-foundry/HostContractsDeployerTestUtils.sol:DeployableERC1967Proxy",
            abi.encode(emptyProxyImplementation, abi.encodeCall(EmptyUUPSProxyACL.initialize, (owner))),
            aclAdd
        );
        vm.prank(owner);
        EmptyUUPSProxyACL(aclAdd).upgradeToAndCall(impl, abi.encodeWithSignature("initializeFromEmptyProxy()"));
        aclImpl = impl;
        (, execImpl) = _deployFHEVMExecutor(owner);
        (, hcuImpl) = _deployHCULimit(owner);
        _deployPauserSet();
        token = new ERC7984RetirementToken();
    }

    function _cool() internal {
        vm.cool(aclAdd);
        vm.cool(aclImpl);
        vm.cool(fhevmExecutorAdd);
        vm.cool(execImpl);
        vm.cool(hcuLimitAdd);
        vm.cool(hcuImpl);
        vm.cool(pauserSetAdd);
        vm.cool(address(token));
    }

    function _gas() internal view returns (uint256) {
        return vm.lastCallGas().gasTotalUsed;
    }

    function _handle(uint256 seed, FheType t) internal view returns (bytes32 h) {
        h =
            keccak256(abi.encode("gas-handle", seed)) &
            0xffffffffffffffffffffffffffffffffffffffffff0000000000000000000000;
        h = h | (bytes32(uint256(0xff)) << 80) | (bytes32(uint256(uint64(block.chainid))) << 16);
        h = h | (bytes32(uint256(uint8(t))) << 8);
    }

    /// @dev Setup only: write a persisted pair directly (fhevm.storage.ACL, same layout in both versions).
    function _persist(bytes32 handle, address account) internal {
        vm.store(
            aclAdd,
            keccak256(abi.encode(account, keccak256(abi.encode(handle, uint256(ACL_LOCATION))))),
            bytes32(uint256(1))
        );
    }

    function _log(string memory label, uint256 base, uint256 withRetirement) internal view {
        string memory evm = IVmEvmVersion(address(vm)).getEvmVersion();
        int256 delta = int256(withRetirement) - int256(base);
        console.log(
            string.concat(
                "GAS|",
                evm,
                "|",
                label,
                "|",
                vm.toString(base),
                "|",
                vm.toString(withRetirement),
                "|",
                vm.toString(delta)
            )
        );
    }

    /// @dev Runs `measure(false)` and `measure(true)` from the same pre-state and logs both.
    function _compare(string memory label, function(bool) internal returns (uint256) measure) internal {
        uint256 snap = vm.snapshotState();
        uint256 base = measure(false);
        vm.revertToState(snap);
        uint256 withRetirement = measure(true);
        vm.revertToState(snap);
        _log(label, base, withRetirement);
    }

    ////////////////////////////////////////////////////////////////////////////
    // retireAccount
    ////////////////////////////////////////////////////////////////////////////

    function test_Gas_RetireAccount() public {
        _deployStack(true);
        _cool();
        vm.prank(user);
        ACL(aclAdd).retireAccount();
        uint256 first = _gas();
        _log("retireAccount (first, cold)", 0, first);
        _cool();
        vm.prank(user);
        try ACL(aclAdd).retireAccount() {} catch {}
        _log("retireAccount (second, reverts AccountAlreadyRetired)", 0, _gas());
    }

    ////////////////////////////////////////////////////////////////////////////
    // isAllowed: non-executor and executor paths
    ////////////////////////////////////////////////////////////////////////////

    function _mIsAllowedNonExecutorTrue(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _persist(h, user);
        _cool();
        assertTrue(ACL(aclAdd).isAllowed(h, user));
        return _gas();
    }

    function _mIsAllowedNonExecutorFalse(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _cool();
        assertFalse(ACL(aclAdd).isAllowed(h, user));
        return _gas();
    }

    function _mIsAllowedExecutorPersisted(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _persist(h, user);
        _cool();
        vm.prank(fhevmExecutorAdd);
        assertTrue(ACL(aclAdd).isAllowed(h, user));
        return _gas();
    }

    function _mIsAllowedExecutorTransient(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        vm.prank(fhevmExecutorAdd);
        ACL(aclAdd).allowTransient(h, user);
        _cool();
        vm.prank(fhevmExecutorAdd);
        assertTrue(ACL(aclAdd).isAllowed(h, user));
        return _gas();
    }

    function _mPersistAllowed(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _persist(h, user);
        _cool();
        assertTrue(ACL(aclAdd).persistAllowed(h, user));
        return _gas();
    }

    function test_Gas_IsAllowed() public {
        _compare("isAllowed, non-executor caller, persisted pair (true)", _mIsAllowedNonExecutorTrue);
        _compare("isAllowed, non-executor caller, no grant (false)", _mIsAllowedNonExecutorFalse);
        _compare("isAllowed, executor caller, persisted pair", _mIsAllowedExecutorPersisted);
        _compare("isAllowed, executor caller, transient grant", _mIsAllowedExecutorTransient);
        _compare("persistAllowed (true)", _mPersistAllowed);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Executor: per-operand cost through the real FHEVMExecutor
    ////////////////////////////////////////////////////////////////////////////

    function _mFheAddPersisted(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 x = _handle(1, FheType.Uint64);
        bytes32 y = _handle(2, FheType.Uint64);
        _persist(x, user);
        _persist(y, user);
        _cool();
        vm.prank(user);
        FHEVMExecutor(fhevmExecutorAdd).fheAdd(x, y, 0x00);
        return _gas();
    }

    function _mFheAddTransient(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        vm.startPrank(user);
        bytes32 x = FHEVMExecutor(fhevmExecutorAdd).trivialEncrypt(7, FheType.Uint64);
        bytes32 y = FHEVMExecutor(fhevmExecutorAdd).trivialEncrypt(3, FheType.Uint64);
        vm.stopPrank();
        _cool();
        vm.prank(user);
        FHEVMExecutor(fhevmExecutorAdd).fheAdd(x, y, 0x00);
        return _gas();
    }

    function _mFheIfThenElsePersisted(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 c = _handle(1, FheType.Bool);
        bytes32 x = _handle(2, FheType.Uint64);
        bytes32 y = _handle(3, FheType.Uint64);
        _persist(c, user);
        _persist(x, user);
        _persist(y, user);
        _cool();
        vm.prank(user);
        FHEVMExecutor(fhevmExecutorAdd).fheIfThenElse(c, x, y);
        return _gas();
    }

    function test_Gas_ExecutorPerOperand() public {
        _compare("executor fheAdd, 2 persisted operands", _mFheAddPersisted);
        _compare("executor fheAdd, 2 transient operands", _mFheAddTransient);
        _compare("executor fheIfThenElse, 3 persisted operands", _mFheIfThenElsePersisted);
    }

    ////////////////////////////////////////////////////////////////////////////
    // allow (grant path, never-retired caller)
    ////////////////////////////////////////////////////////////////////////////

    function _mAllow(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _persist(h, user);
        _cool();
        vm.prank(user);
        ACL(aclAdd).allow(h, recipient);
        return _gas();
    }

    function test_Gas_Allow() public {
        _compare("allow (new pair)", _mAllow);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Delegated views, with the contract check
    ////////////////////////////////////////////////////////////////////////////

    function _setUpDelegation() internal returns (bytes32 h) {
        h = _handle(1, FheType.Uint64);
        _persist(h, delegator);
        _persist(h, app);
        vm.prank(delegator);
        ACL(aclAdd).delegateForUserDecryption(delegate, app, uint64(block.timestamp + 1 days));
    }

    function _mIsHandleDelegated(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        bytes32 h = _setUpDelegation();
        _cool();
        assertTrue(ACL(aclAdd).isHandleDelegatedForUserDecryption(delegator, delegate, app, h));
        return _gas();
    }

    function _mIsDelegated(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        _setUpDelegation();
        _cool();
        assertTrue(ACL(aclAdd).isDelegatedForUserDecryption(delegator, delegate, app));
        return _gas();
    }

    function _mExpiry(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        _setUpDelegation();
        _cool();
        assertGt(ACL(aclAdd).getUserDecryptionDelegationExpirationDate(delegator, delegate, app), 0);
        return _gas();
    }

    function test_Gas_DelegatedViews() public {
        _compare("isHandleDelegatedForUserDecryption (true)", _mIsHandleDelegated);
        _compare("isDelegatedForUserDecryption (true)", _mIsDelegated);
        _compare("getUserDecryptionDelegationExpirationDate (non-zero)", _mExpiry);
    }

    ////////////////////////////////////////////////////////////////////////////
    // OpenZeppelin ERC-7984 0.5.3: transfer delta
    ////////////////////////////////////////////////////////////////////////////

    function _mErc7984Transfer(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        token.mint(user, 1_000);
        ACL(aclAdd).cleanTransientStorage();
        euint64 balance = token.confidentialBalanceOf(user);
        _cool();
        vm.prank(user);
        token.confidentialTransfer(recipient, balance);
        return _gas();
    }

    function _mErc7984Mint(bool withRetirement) internal returns (uint256) {
        _deployStack(withRetirement);
        _cool();
        token.mint(user, 1_000);
        return _gas();
    }

    function test_Gas_ERC7984() public {
        _compare("ERC-7984 confidentialTransfer(to, euint64) by holder", _mErc7984Transfer);
        _compare("ERC-7984 mint (token-internal grants only)", _mErc7984Mint);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Carry: multicall([allow(h_i, NEW)...]) (+ retireAccount() on v0.8.0)
    // Two metrics: frame gas (execution of the multicall frame) and caller-side gas (gasleft() delta around the
    // call: frame + CALL overhead + any gas charged outside the frame, e.g. Amsterdam state-creation gas).
    ////////////////////////////////////////////////////////////////////////////

    function _carryCalls(uint256 n, bool withRetire) internal returns (bytes[] memory calls) {
        calls = new bytes[](withRetire ? n + 1 : n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 h = _handle(1000 + i, FheType.Uint64);
            _persist(h, user);
            calls[i] = abi.encodeCall(ACL.allow, (h, recipient));
        }
        if (withRetire) calls[n] = abi.encodeCall(ACL.retireAccount, ());
    }

    function _carry(uint256 n, bool withRetirement, bool withRetire) internal returns (uint256 frame, uint256 caller) {
        _deployStack(withRetirement);
        bytes[] memory calls = _carryCalls(n, withRetire);
        _cool();
        vm.prank(user);
        uint256 g = gasleft();
        try ACL(aclAdd).multicall(calls) {
            caller = g - gasleft();
            frame = _gas();
        } catch (bytes memory err) {
            console.log(
                string.concat(
                    "GASFAIL|",
                    IVmEvmVersion(address(vm)).getEvmVersion(),
                    "|carry n=",
                    vm.toString(n),
                    "|",
                    vm.toString(err)
                )
            );
        }
    }

    function _carryRow(uint256 n) internal {
        uint256 snap = vm.snapshotState();
        (uint256 baseF, uint256 baseC) = _carry(n, false, false);
        vm.revertToState(snap);
        (uint256 grantsF, uint256 grantsC) = _carry(n, true, false);
        vm.revertToState(snap);
        (uint256 retireF, uint256 retireC) = _carry(n, true, true);
        vm.revertToState(snap);
        string memory k = string.concat("carry n=", vm.toString(n));
        _log(string.concat(k, ": multicall(allow x n) [base] vs same on v0.8.0 (frame)"), baseF, grantsF);
        _log(string.concat(k, ": multicall(allow x n) [base] vs v0.8.0 + retireAccount() (frame)"), baseF, retireF);
        _log(string.concat(k, ": multicall(allow x n) [base] vs same on v0.8.0 (caller-side)"), baseC, grantsC);
        _log(
            string.concat(k, ": multicall(allow x n) [base] vs v0.8.0 + retireAccount() (caller-side)"),
            baseC,
            retireC
        );
    }

    function test_Gas_Carry_n1() public {
        _carryRow(1);
    }

    function test_Gas_Carry_n10() public {
        _carryRow(10);
    }

    function test_Gas_Carry_n100() public {
        _carryRow(100);
    }

    function test_Gas_Carry_n500() public {
        _carryRow(500);
    }

    /// @dev Caller-side gas of the state-creating single operations (includes Amsterdam state-creation gas).
    function _callerAllow(bool withRetirement) internal returns (uint256 c) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _persist(h, user);
        _cool();
        vm.prank(user);
        uint256 g = gasleft();
        ACL(aclAdd).allow(h, recipient);
        c = g - gasleft();
    }

    function _callerNoop(bool withRetirement) internal returns (uint256 c) {
        _deployStack(withRetirement);
        bytes32 h = _handle(1, FheType.Uint64);
        _cool();
        uint256 g = gasleft();
        ACL(aclAdd).allowedTransient(h, user);
        uint256 used = g - gasleft();
        c = used - _gas();
    }

    function _callerErc7984Transfer(bool withRetirement) internal returns (uint256 c) {
        _deployStack(withRetirement);
        token.mint(user, 1_000);
        ACL(aclAdd).cleanTransientStorage();
        euint64 balance = token.confidentialBalanceOf(user);
        _cool();
        vm.prank(user);
        uint256 g = gasleft();
        token.confidentialTransfer(recipient, balance);
        c = g - gasleft();
    }

    function test_Gas_CallerSide() public {
        _compare("allow (new pair) (caller-side)", _callerAllow);
        _compare("CALL overhead into the ACL (caller-side minus frame)", _callerNoop);
        _compare("ERC-7984 confidentialTransfer(to, euint64) by holder (caller-side)", _callerErc7984Transfer);
        _deployStack(true);
        _cool();
        vm.prank(user);
        uint256 g = gasleft();
        ACL(aclAdd).retireAccount();
        _log("retireAccount (first, cold) (caller-side)", 0, g - gasleft());
    }

    ////////////////////////////////////////////////////////////////////////////
    // Attribution of the executor-path overhead: dispatcher/layout vs the exemption compare
    ////////////////////////////////////////////////////////////////////////////

    /// @dev variant 0 = v0.7.0, 1 = v0.8.0 without the exemption compare (fixture), 2 = v0.8.0.
    function _impl(uint256 variant) internal returns (address) {
        if (variant == 0) return address(new ACL_v0_7_0());
        if (variant == 1) return address(new ACL_v0_8_0_attribution());
        return address(new ACL());
    }

    function _attribIsAllowedTransient(uint256 variant) internal returns (uint256) {
        _deployStackImpl(_impl(variant));
        bytes32 h = _handle(1, FheType.Uint64);
        vm.prank(fhevmExecutorAdd);
        ACL(aclAdd).allowTransient(h, user);
        _cool();
        vm.prank(fhevmExecutorAdd);
        ACL(aclAdd).isAllowed(h, user);
        return _gas();
    }

    function _attribIsAllowedPersisted(uint256 variant) internal returns (uint256) {
        _deployStackImpl(_impl(variant));
        bytes32 h = _handle(1, FheType.Uint64);
        _persist(h, user);
        _cool();
        vm.prank(fhevmExecutorAdd);
        ACL(aclAdd).isAllowed(h, user);
        return _gas();
    }

    function _attribAllowedTransientGetter(uint256 variant) internal returns (uint256) {
        _deployStackImpl(_impl(variant));
        bytes32 h = _handle(1, FheType.Uint64);
        _cool();
        ACL(aclAdd).allowedTransient(h, user);
        return _gas();
    }

    function _attribFheAddPersisted(uint256 variant) internal returns (uint256) {
        _deployStackImpl(_impl(variant));
        bytes32 x = _handle(1, FheType.Uint64);
        bytes32 y = _handle(2, FheType.Uint64);
        _persist(x, user);
        _persist(y, user);
        _cool();
        vm.prank(user);
        FHEVMExecutor(fhevmExecutorAdd).fheAdd(x, y, 0x00);
        return _gas();
    }

    function _attribFheAddTransient(uint256 variant) internal returns (uint256) {
        _deployStackImpl(_impl(variant));
        vm.startPrank(user);
        bytes32 x = FHEVMExecutor(fhevmExecutorAdd).trivialEncrypt(7, FheType.Uint64);
        bytes32 y = FHEVMExecutor(fhevmExecutorAdd).trivialEncrypt(3, FheType.Uint64);
        vm.stopPrank();
        _cool();
        vm.prank(user);
        FHEVMExecutor(fhevmExecutorAdd).fheAdd(x, y, 0x00);
        return _gas();
    }

    function _attribute(string memory label, function(uint256) internal returns (uint256) measure) internal {
        uint256 snap = vm.snapshotState();
        uint256 g0 = measure(0);
        vm.revertToState(snap);
        uint256 g1 = measure(1);
        vm.revertToState(snap);
        uint256 g2 = measure(2);
        vm.revertToState(snap);
        _log(string.concat(label, " [dispatcher/layout: v0.7.0 vs v0.8.0-without-compare]"), g0, g1);
        _log(string.concat(label, " [exemption compare: v0.8.0-without-compare vs v0.8.0]"), g1, g2);
    }

    /// @dev Skipped under Amsterdam: it deploys the full stack 15 times, and contract-creation state gas under
    ///      that fork exhausts a creation frame. The attribution is code-level: the executor-path frame deltas are
    ///      identical under Prague, Osaka and Amsterdam (test_Gas_ExecutorPerOperand).
    function test_Gas_ExecutorOverheadAttribution() public {
        vm.skip(keccak256(bytes(IVmEvmVersion(address(vm)).getEvmVersion())) == keccak256("amsterdam"));
        _attribute("isAllowed, executor caller, transient grant", _attribIsAllowedTransient);
        _attribute("isAllowed, executor caller, persisted pair", _attribIsAllowedPersisted);
        _attribute("allowedTransient (unchanged code)", _attribAllowedTransientGetter);
        _attribute("executor fheAdd, 2 transient operands", _attribFheAddTransient);
        _attribute("executor fheAdd, 2 persisted operands", _attribFheAddPersisted);
    }
}
