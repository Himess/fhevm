// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {ACL} from "../../contracts/ACL.sol";
import {FHEVMExecutor} from "../../contracts/FHEVMExecutor.sol";
import {FheType} from "../../contracts/shared/FheType.sol";
import {HostContractsDeployerTestUtils} from "../../fhevm-foundry/HostContractsDeployerTestUtils.sol";
import {aclAdd, fhevmExecutorAdd, hcuLimitAdd, inputVerifierAdd} from "../../addresses/FHEVMHostAddresses.sol";
import {FHE, euint64, externalEuint64} from "../../lib/FHE.sol";
import {ERC7984} from "./retirement/oz-confidential-contracts-0.5.3/token/ERC7984/ERC7984.sol";
import {RetirementTestAccount, FromExternalDeputy, ERC7984RetirementToken, ERC7984AcceptingReceiver} from "./retirement/RetirementMocks.sol";

/// @dev Same shape as Zama's MockInputVerifier (fhevmExecutor.t.sol): returns the handle, never reverts.
contract RetirementMockInputVerifier {
    function verifyInput(
        FHEVMExecutor.ContextUserInputs memory,
        bytes32 inputHandle,
        bytes memory
    ) external pure returns (bytes32) {
        return inputHandle;
    }
}

/**
 * @title ACLRetirementExemptionTest
 * @notice The engine exemption is not an export route. A retired EIP-7702 EOA and a retired contract
 *         each compute through the real FHEVMExecutor (operand checks pass under the exemption and the result is
 *         granted transiently to them), then try every export path in the same transaction. Every attempt reverts;
 *         the never-retired control succeeds on the same path. Also the three executor invariants.
 */
contract ACLRetirementExemptionTest is HostContractsDeployerTestUtils {
    ACL internal acl;
    FHEVMExecutor internal executor;
    address internal executorImplementation;
    address internal aclImplementation;
    address internal hcuLimitImplementation;

    address internal constant owner = address(456);

    RetirementTestAccount internal accountCode;
    address internal eoa7702;
    uint256 internal eoa7702Key;
    address internal contractAccount;
    address internal control;

    FromExternalDeputy internal deputy;
    ERC7984RetirementToken internal token;

    address internal recipient = makeAddr("recipient");
    address internal holder = makeAddr("holder");

    bytes32 internal constant P = keccak256("RetirementTestAccount.RESULT_PLACEHOLDER");

    function setUp() public {
        (, aclImplementation) = _deployACL(owner);
        _deployPauserSet();
        (, executorImplementation) = _deployFHEVMExecutor(owner);
        (, hcuLimitImplementation) = _deployHCULimit(owner);
        acl = ACL(aclAdd);
        executor = FHEVMExecutor(fhevmExecutorAdd);

        accountCode = new RetirementTestAccount();
        (eoa7702, eoa7702Key) = makeAddrAndKey("eoa7702");
        vm.signAndAttachDelegation(address(accountCode), eoa7702Key);
        contractAccount = address(new RetirementTestAccount());
        control = address(new RetirementTestAccount());

        deputy = new FromExternalDeputy();
        token = new ERC7984RetirementToken();
    }

    ////////////////////////////////////////////////////////////////////////////
    // helpers
    ////////////////////////////////////////////////////////////////////////////

    function _acc(address a) internal pure returns (RetirementTestAccount) {
        return RetirementTestAccount(payable(a));
    }

    /// @dev Before retirement: the account mints a Uint64 handle through the executor and persists it to itself.
    function _seedHandle(address account) internal returns (bytes32 h) {
        h = abi.decode(
            _acc(account).execute(
                address(executor),
                0,
                abi.encodeCall(FHEVMExecutor.trivialEncrypt, (42, FheType.Uint64))
            ),
            (bytes32)
        );
        _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.allow, (h, account)));
        acl.cleanTransientStorage();
        assertTrue(acl.persistAllowed(h, account));
    }

    /// @dev The 7702 EOA retires with a plain transaction; the contract retires through its own code.
    function _retire(address account) internal {
        if (account == eoa7702) {
            assertEq(account.code.length, 23, "7702 delegation designator");
            vm.prank(account);
            acl.retireAccount();
        } else {
            _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.retireAccount, ()));
        }
        assertTrue(acl.isAccountRetired(account));
    }

    function _accounts() internal view returns (address[2] memory) {
        return [eoa7702, contractAccount];
    }

    /// @dev The exemption itself: a retired account still computes through the executor. The result is granted
    ///      transiently to it (raw getter true) but every non-executor view answers false.
    function _assertComputeStillWorks(address account, bytes32 operand) internal {
        bytes32 r = _acc(account).compute(operand);
        assertTrue(acl.allowedTransient(r, account), "executor granted the result transiently");
        assertFalse(acl.isAllowed(r, account), "non-executor view refuses the retired account");
        vm.prank(fhevmExecutorAdd);
        assertTrue(acl.isAllowed(r, account), "executor operand check passes");
    }

    /// @dev Compute through the executor, then call the export path, in one transaction. Returns the revert data.
    function _exportReverts(
        address account,
        bytes32 operand,
        address target,
        uint256 value,
        bytes memory template
    ) internal returns (bytes memory revertData) {
        bool ok;
        (ok, revertData) = account.call(
            abi.encodeCall(RetirementTestAccount.computeAndCall, (operand, target, value, template))
        );
        assertFalse(ok, "export by a retired account must revert");
    }

    function _exportSucceeds(
        address account,
        bytes32 operand,
        address target,
        uint256 value,
        bytes memory template
    ) internal returns (bytes32 result) {
        (result, ) = _acc(account).computeAndCall(operand, target, value, template);
    }

    function _decode2(bytes memory revertData) internal pure returns (bytes4 sel, bytes32 a, address b) {
        assembly {
            sel := mload(add(revertData, 32))
            a := mload(add(revertData, 36))
            b := mload(add(revertData, 68))
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // ACL export paths
    ////////////////////////////////////////////////////////////////////////////

    function test_Export_Allow() public {
        bytes memory template = abi.encodeCall(ACL.allow, (P, recipient));
        bytes32 hc = _seedHandle(control);
        bytes32 r = _exportSucceeds(control, hc, address(acl), 0, template);
        assertTrue(acl.persistAllowed(r, recipient), "control can export");

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 h = _seedHandle(account);
            _retire(account);
            _assertComputeStillWorks(account, h);
            bytes memory err = _exportReverts(account, h, address(acl), 0, template);
            assertEq(err, abi.encodeWithSelector(ACL.SenderRetired.selector, account));
        }
    }

    function test_Export_AllowForDecryption() public {
        bytes32[] memory list = new bytes32[](1);
        list[0] = P;
        bytes memory template = abi.encodeCall(ACL.allowForDecryption, (list));
        bytes32 hc = _seedHandle(control);
        bytes32 r = _exportSucceeds(control, hc, address(acl), 0, template);
        assertTrue(acl.isAllowedForDecryption(r), "control can publish");

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 h = _seedHandle(account);
            _retire(account);
            _assertComputeStillWorks(account, h);
            bytes memory err = _exportReverts(account, h, address(acl), 0, template);
            assertEq(err, abi.encodeWithSelector(ACL.SenderRetired.selector, account));
            // Publishing the persisted handle directly fails too.
            list[0] = h;
            vm.prank(account);
            vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, account));
            acl.allowForDecryption(list);
            list[0] = P;
        }
    }

    function test_Export_AllowTransient() public {
        bytes memory template = abi.encodeCall(ACL.allowTransient, (P, recipient));
        bytes32 hc = _seedHandle(control);
        bytes32 r = _exportSucceeds(control, hc, address(acl), 0, template);
        assertTrue(acl.allowedTransient(r, recipient), "control can grant transiently");

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 h = _seedHandle(account);
            _retire(account);
            _assertComputeStillWorks(account, h);
            bytes memory err = _exportReverts(account, h, address(acl), 0, template);
            assertEq(err, abi.encodeWithSelector(ACL.SenderRetired.selector, account));
        }
    }

    function test_Export_Multicall() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(ACL.allow, (P, recipient));
        calls[1] = abi.encodeCall(ACL.allowTransient, (P, recipient));
        bytes memory template = abi.encodeCall(acl.multicall, (calls));
        bytes32 hc = _seedHandle(control);
        bytes32 r = _exportSucceeds(control, hc, address(acl), 0, template);
        assertTrue(acl.persistAllowed(r, recipient), "control can batch");

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 h = _seedHandle(account);
            _retire(account);
            _assertComputeStillWorks(account, h);
            bytes memory err = _exportReverts(account, h, address(acl), 0, template);
            assertEq(err, abi.encodeWithSelector(ACL.SenderRetired.selector, account));
        }
    }

    function test_Export_DelegateForUserDecryption() public {
        address app = address(token);
        bytes memory template = abi.encodeCall(
            ACL.delegateForUserDecryption,
            (recipient, app, uint64(block.timestamp + 1 days))
        );
        bytes32 hc = _seedHandle(control);
        _exportSucceeds(control, hc, address(acl), 0, template);
        assertTrue(acl.isDelegatedForUserDecryption(control, recipient, app), "control can delegate");

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 h = _seedHandle(account);
            _retire(account);
            _assertComputeStillWorks(account, h);
            bytes memory err = _exportReverts(account, h, address(acl), 0, template);
            assertEq(err, abi.encodeWithSelector(ACL.SenderRetired.selector, account));
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Deputies: FHE.fromExternal(h, "")
    ////////////////////////////////////////////////////////////////////////////

    function test_Export_FromExternalEmptyProof() public {
        bytes memory template = abi.encodeCall(FromExternalDeputy.useHandle, (externalEuint64.wrap(P)));
        bytes32 hc = _seedHandle(control);
        _exportSucceeds(control, hc, address(deputy), 0, template);

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 h = _seedHandle(account);
            _retire(account);
            _assertComputeStillWorks(account, h);
            bytes memory err = _exportReverts(account, h, address(deputy), 0, template);
            (bytes4 sel, bytes32 handle, address sender) = _decode2(err);
            assertEq(sel, FHE.SenderNotAllowedToUseHandle.selector);
            assertEq(sender, account);
            assertTrue(acl.allowedTransient(handle, account), "the refused handle is the executor's fresh result");
            // The persisted handle is refused the same way.
            vm.prank(account);
            vm.expectRevert(abi.encodeWithSelector(FHE.SenderNotAllowedToUseHandle.selector, h, account));
            deputy.useHandle(externalEuint64.wrap(h));
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Deputies: OpenZeppelin ERC-7984 0.5.3 handle transfers and disclosure
    ////////////////////////////////////////////////////////////////////////////

    /// @dev Mints to the account before retirement; returns its balance handle (persisted to it by the token).
    function _fund(address account) internal returns (bytes32 balance) {
        token.mint(account, 1_000);
        acl.cleanTransientStorage();
        balance = euint64.unwrap(token.confidentialBalanceOf(account));
        assertTrue(acl.persistAllowed(balance, account));
    }

    function _assertTokenRefuses(bytes memory err, address account) internal view {
        (bytes4 sel, bytes32 amount, address user) = _decode2(err);
        assertEq(sel, ERC7984.ERC7984UnauthorizedUseOfEncryptedAmount.selector);
        assertEq(user, account);
        assertTrue(acl.allowedTransient(amount, account), "the refused amount is the executor's fresh result");
    }

    /// @dev Replaces the placeholder word in test-built calldata (same rule as RetirementTestAccount).
    function _subst(bytes memory data, bytes32 value) internal pure returns (bytes memory out) {
        out = bytes.concat(data);
        for (uint256 i = 0; i + 32 <= out.length; ) {
            bytes32 word;
            assembly {
                word := mload(add(add(out, 32), i))
            }
            if (word == P) {
                assembly {
                    mstore(add(add(out, 32), i), value)
                }
                i += 32;
            } else {
                i++;
            }
        }
    }

    /**
     * @dev One ERC-7984 handle path. The never-retired control computes, grants the token transient access to the
     *      result (OZ's handle overloads need the token to hold the amount too), then calls the token: success.
     *      Each retired account computes (exemption works), then calls the token with the fresh result: refused by
     *      OZ's caller-side `FHE.isAllowed(amount, msg.sender)`. Its persisted balance handle is refused the same way.
     */
    function _erc7984Path(bytes memory tokenCall, bool asOperator) internal {
        bytes32 bc = _fund(control);
        if (asOperator) {
            vm.prank(holder);
            token.setOperator(control, type(uint48).max);
        }
        RetirementTestAccount.Call[] memory batch = new RetirementTestAccount.Call[](2);
        batch[0] = RetirementTestAccount.Call(address(acl), 0, abi.encodeCall(ACL.allowTransient, (P, address(token))));
        batch[1] = RetirementTestAccount.Call(address(token), 0, tokenCall);
        _acc(control).computeAndCallBatch(bc, batch);

        for (uint256 i = 0; i < 2; i++) {
            address account = _accounts()[i];
            bytes32 b = _fund(account);
            if (asOperator) {
                vm.prank(holder);
                token.setOperator(account, type(uint48).max);
            }
            _retire(account);
            _assertComputeStillWorks(account, b);
            _assertTokenRefuses(_exportReverts(account, b, address(token), 0, tokenCall), account);

            (bool ok, bytes memory err) = account.call(
                abi.encodeCall(RetirementTestAccount.execute, (address(token), 0, _subst(tokenCall, b)))
            );
            assertFalse(ok);
            assertEq(err, abi.encodeWithSelector(ERC7984.ERC7984UnauthorizedUseOfEncryptedAmount.selector, b, account));
        }
    }

    function test_Export_ERC7984_ConfidentialTransferHandle() public {
        _erc7984Path(abi.encodeWithSignature("confidentialTransfer(address,bytes32)", recipient, P), false);
    }

    function test_Export_ERC7984_ConfidentialTransferFromHandle() public {
        token.mint(holder, 500);
        _erc7984Path(
            abi.encodeWithSignature("confidentialTransferFrom(address,address,bytes32)", holder, recipient, P),
            true
        );
    }

    function test_Export_ERC7984_ConfidentialTransferAndCallHandle() public {
        _erc7984Path(
            abi.encodeWithSignature("confidentialTransferAndCall(address,bytes32,bytes)", recipient, P, bytes("")),
            false
        );
    }

    function test_Export_ERC7984_ConfidentialTransferFromAndCallHandle() public {
        token.mint(holder, 500);
        _erc7984Path(
            abi.encodeWithSignature(
                "confidentialTransferFromAndCall(address,address,bytes32,bytes)",
                holder,
                recipient,
                P,
                bytes("")
            ),
            true
        );
    }

    function test_Export_ERC7984_RequestDiscloseEncryptedAmount() public {
        _erc7984Path(abi.encodeWithSignature("requestDiscloseEncryptedAmount(bytes32)", P), false);
    }

    /// @dev Inbound transfers to a retired account succeed (the token's grants are accepted) and are inert.
    function test_ERC7984_InboundTransferToRetiredAccepted_AndInert() public {
        token.mint(holder, 500);
        acl.cleanTransientStorage();
        _retire(eoa7702);
        bytes32 holderBalance = euint64.unwrap(token.confidentialBalanceOf(holder));
        vm.prank(holder);
        token.confidentialTransfer(eoa7702, euint64.wrap(holderBalance));
        bytes32 received = euint64.unwrap(token.confidentialBalanceOf(eoa7702));
        assertTrue(received != bytes32(0), "balance updated");
        assertTrue(acl.persistAllowed(received, address(token)), "token keeps access");
        assertFalse(acl.persistAllowed(received, eoa7702), "retired recipient has no usable access");
        assertFalse(acl.isAllowed(received, eoa7702));
    }

    /// @dev The AndCall variants assert FHE.isAllowed(retval, to) on recipients with code
    ///      (ERC7984Utils.sol:36). For a retired recipient with code the whole transfer reverts (fails closed: the
    ///      sender's balance handle is untouched). Asserted behaviour, not a Core change.
    function test_ERC7984_AndCallToRetiredContractRecipientReverts() public {
        ERC7984AcceptingReceiver receiver = new ERC7984AcceptingReceiver();
        token.mint(holder, 500);
        acl.cleanTransientStorage();
        receiver.retire();
        bytes32 before = euint64.unwrap(token.confidentialBalanceOf(holder));
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ACL.SenderRetired.selector, address(receiver)));
        token.confidentialTransferAndCall(address(receiver), euint64.wrap(before), "");
        assertEq(euint64.unwrap(token.confidentialBalanceOf(holder)), before);
    }

    /// @dev Asserted residual (limit 2, oracle access only): retirement does not stop the account acting as an
    ///      account. With a fresh input proof, a retired account still moves its funds; the ACL never consults the
    ///      retired account on this path (the executor grants the verified input to the token).
    function test_Residual_RetiredAccountStillTransfersWithFreshInput() public {
        vm.etch(inputVerifierAdd, address(new RetirementMockInputVerifier()).code);
        _fund(eoa7702);
        _retire(eoa7702);
        bytes32 input = (keccak256("fresh input") &
            0xffffffffffffffffffffffffffffffffffffffffff0000000000000000000000) |
            bytes32(uint256(uint8(FheType.Uint64)) << 8);
        vm.prank(eoa7702);
        token.confidentialTransfer(recipient, externalEuint64.wrap(input), hex"01");
        assertTrue(euint64.unwrap(token.confidentialBalanceOf(recipient)) != bytes32(0));
    }

    ////////////////////////////////////////////////////////////////////////////
    // Executor invariants, pinned
    ////////////////////////////////////////////////////////////////////////////

    function _args(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i = 0; i < out.length; i++) out[i] = data[i + 4];
    }

    /**
     * @dev Checks every recorded access:
     *  - invariant 1: every executor -> ACL read is isAllowed(ct, caller), the executor's direct caller;
     *  - invariant 2: every executor -> ACL grant is allowTransient(result, caller);
     *  - invariant 3: no other host contract reads the views as the executor. A view call has the executor as
     *    msg.sender only if code runs in the executor's context, i.e. the executor itself or code it DELEGATECALLs.
     *    So: the only DELEGATECALLs in the whole run are the UUPS proxy-to-own-implementation hops (ACL,
     *    FHEVMExecutor, HCULimit), and the host contracts the executor calls (HCULimit, InputVerifier) read no
     *    authorization view. (Foundry records a DELEGATECALL's accessor as the frame's msg.sender, so the hop is
     *    identified by its code address.)
     */
    function _checkInvariants(
        Vm.AccountAccess[] memory acc,
        address caller
    ) internal returns (uint256 reads, uint256 grants) {
        for (uint256 i = 0; i < acc.length; i++) {
            Vm.AccountAccess memory a = acc[i];
            bool isCall = a.kind == VmSafe.AccountAccessKind.Call || a.kind == VmSafe.AccountAccessKind.StaticCall;
            if (a.kind == VmSafe.AccountAccessKind.DelegateCall) {
                assertTrue(
                    a.account == aclImplementation ||
                        a.account == executorImplementation ||
                        a.account == hcuLimitImplementation,
                    "inv3: the only delegatecalls are proxy-to-own-implementation hops"
                );
            }
            if (!isCall || a.account != aclAdd || a.data.length < 4) continue;
            bytes4 sel = bytes4(a.data);
            if (a.accessor == fhevmExecutorAdd) {
                if (sel == ACL.isAllowed.selector) {
                    (, address subject) = abi.decode(_args(a.data), (bytes32, address));
                    assertEq(subject, caller, "inv1: operand check names the executor's caller");
                    reads++;
                } else if (sel == ACL.allowTransient.selector) {
                    (, address grantee) = abi.decode(_args(a.data), (bytes32, address));
                    assertEq(grantee, caller, "inv2: grant names the executor's caller");
                    grants++;
                } else {
                    fail("inv1/2: executor called another ACL function");
                }
            } else if (a.accessor == hcuLimitAdd || a.accessor == inputVerifierAdd) {
                assertTrue(
                    sel != ACL.isAllowed.selector &&
                        sel != ACL.persistAllowed.selector &&
                        sel != ACL.isHandleDelegatedForUserDecryption.selector &&
                        sel != ACL.isDelegatedForUserDecryption.selector &&
                        sel != ACL.getUserDecryptionDelegationExpirationDate.selector,
                    "inv3: host contracts called by the executor read no authorization view"
                );
            }
        }
    }

    function _runBattery(address account, bytes[] memory calls) internal returns (uint256 reads, uint256 grants) {
        vm.startStateDiffRecording();
        for (uint256 i = 0; i < calls.length; i++) {
            _acc(account).execute(address(executor), 0, calls[i]);
        }
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        (reads, grants) = _checkInvariants(acc, account);
    }

    /// @dev Handles of each type, persisted to `account` before it retires.
    function _seedTyped(address account) internal returns (bytes32 b, bytes32 x, bytes32 y, bytes32 z8) {
        b = abi.decode(
            _acc(account).execute(
                address(executor),
                0,
                abi.encodeCall(FHEVMExecutor.trivialEncrypt, (1, FheType.Bool))
            ),
            (bytes32)
        );
        x = abi.decode(
            _acc(account).execute(
                address(executor),
                0,
                abi.encodeCall(FHEVMExecutor.trivialEncrypt, (7, FheType.Uint64))
            ),
            (bytes32)
        );
        y = abi.decode(
            _acc(account).execute(
                address(executor),
                0,
                abi.encodeCall(FHEVMExecutor.trivialEncrypt, (3, FheType.Uint64))
            ),
            (bytes32)
        );
        z8 = abi.decode(
            _acc(account).execute(
                address(executor),
                0,
                abi.encodeCall(FHEVMExecutor.trivialEncrypt, (2, FheType.Uint8))
            ),
            (bytes32)
        );
        _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.allow, (b, account)));
        _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.allow, (x, account)));
        _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.allow, (y, account)));
        _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.allow, (z8, account)));
        acl.cleanTransientStorage();
    }

    function _batteryArithmetic(bytes32 x, bytes32 y) internal pure returns (bytes[] memory c) {
        bytes32 s = bytes32(uint256(2));
        c = new bytes[](12);
        c[0] = abi.encodeCall(FHEVMExecutor.fheAdd, (x, y, 0x00));
        c[1] = abi.encodeCall(FHEVMExecutor.fheAdd, (x, s, 0x01));
        c[2] = abi.encodeCall(FHEVMExecutor.fheSub, (x, y, 0x00));
        c[3] = abi.encodeCall(FHEVMExecutor.fheMul, (x, y, 0x00));
        c[4] = abi.encodeCall(FHEVMExecutor.fheDiv, (x, s, 0x01));
        c[5] = abi.encodeCall(FHEVMExecutor.fheRem, (x, s, 0x01));
        c[6] = abi.encodeCall(FHEVMExecutor.fheMin, (x, y, 0x00));
        c[7] = abi.encodeCall(FHEVMExecutor.fheMax, (x, y, 0x00));
        c[8] = abi.encodeCall(FHEVMExecutor.fheNeg, (x));
        c[9] = abi.encodeCall(FHEVMExecutor.fheMulDiv, (x, y, s, 0x01));
        c[10] = abi.encodeCall(FHEVMExecutor.fheMulDiv, (x, s, s, 0x03));
        c[11] = abi.encodeCall(FHEVMExecutor.cast, (x, FheType.Uint32));
    }

    function _batteryBitwiseCompare(bytes32 b, bytes32 x, bytes32 y) internal pure returns (bytes[] memory c) {
        bytes32 s = bytes32(uint256(1));
        c = new bytes[](16);
        c[0] = abi.encodeCall(FHEVMExecutor.fheBitAnd, (x, y, 0x00));
        c[1] = abi.encodeCall(FHEVMExecutor.fheBitOr, (x, y, 0x00));
        c[2] = abi.encodeCall(FHEVMExecutor.fheBitXor, (x, y, 0x00));
        c[3] = abi.encodeCall(FHEVMExecutor.fheShl, (x, s, 0x01));
        c[4] = abi.encodeCall(FHEVMExecutor.fheShr, (x, s, 0x01));
        c[5] = abi.encodeCall(FHEVMExecutor.fheRotl, (x, s, 0x01));
        c[6] = abi.encodeCall(FHEVMExecutor.fheRotr, (x, s, 0x01));
        c[7] = abi.encodeCall(FHEVMExecutor.fheEq, (x, y, 0x00));
        c[8] = abi.encodeCall(FHEVMExecutor.fheNe, (x, y, 0x00));
        c[9] = abi.encodeCall(FHEVMExecutor.fheGe, (x, y, 0x00));
        c[10] = abi.encodeCall(FHEVMExecutor.fheGt, (x, y, 0x00));
        c[11] = abi.encodeCall(FHEVMExecutor.fheLe, (x, y, 0x00));
        c[12] = abi.encodeCall(FHEVMExecutor.fheLt, (x, y, 0x00));
        c[13] = abi.encodeCall(FHEVMExecutor.fheNot, (b));
        c[14] = abi.encodeCall(FHEVMExecutor.fheIfThenElse, (b, x, y));
        c[15] = abi.encodeCall(FHEVMExecutor.fheBitAnd, (b, b, 0x00));
    }

    function _batteryNaryRandInput(bytes32 x, bytes32 y, bytes32 z8) internal view returns (bytes[] memory c) {
        bytes32[] memory values = new bytes32[](2);
        values[0] = x;
        values[1] = y;
        bytes32 input = (keccak256("battery input") &
            0xffffffffffffffffffffffffffffffffffffffffff0000000000000000000000) |
            bytes32(uint256(uint8(FheType.Uint64)) << 8);
        c = new bytes[](7);
        c[0] = abi.encodeCall(FHEVMExecutor.fheSum, (values, FheType.Uint64));
        c[1] = abi.encodeCall(FHEVMExecutor.fheIsIn, (x, values, FheType.Uint64));
        c[2] = abi.encodeCall(FHEVMExecutor.fheRand, (FheType.Uint64));
        c[3] = abi.encodeCall(FHEVMExecutor.fheRandBounded, (uint256(16), FheType.Uint8));
        c[4] = abi.encodeCall(FHEVMExecutor.trivialEncrypt, (uint256(9), FheType.Uint16));
        c[5] = abi.encodeCall(FHEVMExecutor.verifyInput, (input, address(this), hex"01", FheType.Uint64));
        c[6] = abi.encodeCall(FHEVMExecutor.cast, (z8, FheType.Uint64));
    }

    /// @dev External wrapper so the checker's failures can be expected.
    function checkInvariantsExternal(Vm.AccountAccess[] memory acc, address caller) external {
        _checkInvariants(acc, caller);
    }

    function _synthetic(
        VmSafe.AccountAccessKind kind,
        address account,
        address accessor,
        bytes memory data
    ) internal pure returns (Vm.AccountAccess[] memory acc) {
        acc = new Vm.AccountAccess[](1);
        acc[0].kind = kind;
        acc[0].account = account;
        acc[0].accessor = accessor;
        acc[0].data = data;
    }

    /// @dev Non-vacuity: the checker rejects each kind of violation the three invariants exclude.
    function test_ExecutorInvariantChecker_DetectsViolations() public {
        address caller = makeAddr("caller");
        address stranger = makeAddr("stranger");
        bytes32 h = keccak256("h");
        VmSafe.AccountAccessKind call = VmSafe.AccountAccessKind.Call;

        // A conforming record passes.
        this.checkInvariantsExternal(
            _synthetic(call, aclAdd, fhevmExecutorAdd, abi.encodeCall(ACL.isAllowed, (h, caller))),
            caller
        );
        // inv1: operand check on someone other than the executor's caller.
        vm.expectRevert();
        this.checkInvariantsExternal(
            _synthetic(call, aclAdd, fhevmExecutorAdd, abi.encodeCall(ACL.isAllowed, (h, stranger))),
            caller
        );
        // inv2: transient grant to someone other than the executor's caller.
        vm.expectRevert();
        this.checkInvariantsExternal(
            _synthetic(call, aclAdd, fhevmExecutorAdd, abi.encodeCall(ACL.allowTransient, (h, stranger))),
            caller
        );
        // inv1/2: any other ACL function called by the executor.
        vm.expectRevert();
        this.checkInvariantsExternal(
            _synthetic(call, aclAdd, fhevmExecutorAdd, abi.encodeCall(ACL.persistAllowed, (h, caller))),
            caller
        );
        // inv3: a delegatecall into code other than a proxy's own implementation.
        vm.expectRevert();
        this.checkInvariantsExternal(
            _synthetic(VmSafe.AccountAccessKind.DelegateCall, stranger, fhevmExecutorAdd, ""),
            caller
        );
        // inv3: a host contract called by the executor reading an authorization view.
        vm.expectRevert();
        this.checkInvariantsExternal(
            _synthetic(call, aclAdd, hcuLimitAdd, abi.encodeCall(ACL.isAllowed, (h, caller))),
            caller
        );
    }

    /// @dev One battery for one caller: the per-transaction HCU cap (20M in Zama's test deployer) bounds how many
    ///      operations fit in one test transaction, so each (battery, caller) pair is its own test.
    function _invariantRun(uint256 battery, uint256 who) internal {
        vm.etch(inputVerifierAdd, address(new RetirementMockInputVerifier()).code);
        address caller = who == 0
            ? eoa7702
            : who == 1
                ? contractAccount
                : control;
        (bytes32 b, bytes32 x, bytes32 y, bytes32 z8) = _seedTyped(caller);
        if (caller != control) _retire(caller);
        bytes[] memory calls = battery == 0
            ? _batteryArithmetic(x, y)
            : battery == 1
                ? _batteryBitwiseCompare(b, x, y)
                : _batteryNaryRandInput(x, y, z8);
        (uint256 reads, uint256 grants) = _runBattery(caller, calls);
        assertEq(grants, calls.length, "one transient grant to the caller per operation");
        if (battery != 2) assertGt(reads, 0);
    }

    /// @dev Binary arithmetic (encrypted and scalar), unary neg, mulDiv (both modes), cast.
    function test_ExecutorInvariants_Arithmetic_Retired7702() public {
        _invariantRun(0, 0);
    }

    function test_ExecutorInvariants_Arithmetic_RetiredContract() public {
        _invariantRun(0, 1);
    }

    function test_ExecutorInvariants_Arithmetic_NeverRetired() public {
        _invariantRun(0, 2);
    }

    /// @dev Bitwise, shifts and rotations, comparisons, not, ifThenElse.
    function test_ExecutorInvariants_BitwiseCompareTernary_Retired7702() public {
        _invariantRun(1, 0);
    }

    function test_ExecutorInvariants_BitwiseCompareTernary_RetiredContract() public {
        _invariantRun(1, 1);
    }

    function test_ExecutorInvariants_BitwiseCompareTernary_NeverRetired() public {
        _invariantRun(1, 2);
    }

    /// @dev Sum, isIn, rand, randBounded, trivialEncrypt, verifyInput, cast.
    function test_ExecutorInvariants_NaryRandInput_Retired7702() public {
        _invariantRun(2, 0);
    }

    function test_ExecutorInvariants_NaryRandInput_RetiredContract() public {
        _invariantRun(2, 1);
    }

    function test_ExecutorInvariants_NaryRandInput_NeverRetired() public {
        _invariantRun(2, 2);
    }
}
