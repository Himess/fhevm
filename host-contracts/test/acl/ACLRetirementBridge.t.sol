// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {TestHelperOz5} from "@layerzerolabs/test-devtools-evm-foundry/contracts/TestHelperOz5.sol";
import {MessagingFee} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

import {DeployableERC1967Proxy, HostContractsDeployerTestUtils} from "../../fhevm-foundry/HostContractsDeployerTestUtils.sol";
import {ACL} from "../../contracts/ACL.sol";
import {FHEVMExecutor} from "../../contracts/FHEVMExecutor.sol";
import {FheType} from "../../contracts/shared/FheType.sol";
import {EmptyUUPSProxy} from "../../contracts/emptyProxy/EmptyUUPSProxy.sol";
import {ConfidentialBridge} from "../../contracts/bridge/ConfidentialBridge.sol";
import {HandlesSender} from "../../contracts/bridge/HandlesSender.sol";
import {aclAdd, fhevmExecutorAdd} from "../../addresses/FHEVMHostAddresses.sol";
import {RetirementTestAccount} from "./retirement/RetirementMocks.sol";

/**
 * @title ACLRetirementBridgeTest
 * @notice The bridge `send` export path. A retired EIP-7702 EOA and a retired contract
 *         compute through the executor, then try to bridge the fresh result (and their persisted handle) through
 *         the real ConfidentialBridge. The bridge's per-handle check `isAllowed(handle, msg.sender)`
 *         (HandlesSender.sol `_checkAllAllowed`) refuses them; the never-retired control bridges successfully.
 */
contract ACLRetirementBridgeTest is TestHelperOz5, HostContractsDeployerTestUtils {
    uint32 internal constant SRC_EID = 1;
    uint32 internal constant DST_EID = 2;
    uint64 internal constant DST_CHAIN_ID = 4242;
    uint64 internal constant COMPOSE_GAS = 200_000;
    bytes32 internal constant P = keccak256("RetirementTestAccount.RESULT_PLACEHOLDER");

    address internal owner = makeAddr("owner");
    ACL internal acl;
    ConfidentialBridge internal srcBridge;

    address internal eoa7702;
    uint256 internal eoa7702Key;
    address internal contractAccount;
    address internal control;
    bytes32 internal dstApp = bytes32(uint256(uint160(0xBEEF)));

    function setUp() public virtual override {
        super.setUp();
        setUpEndpoints(2, LibraryType.SimpleMessageLib);
        _deployACL(owner);
        _deployFHEVMExecutor(owner);
        _deployHCULimit(owner);
        acl = ACL(aclAdd);

        uint32[] memory eids = new uint32[](1);
        uint64[] memory chainIds = new uint64[](1);
        eids[0] = DST_EID;
        chainIds[0] = DST_CHAIN_ID;
        srcBridge = _deployBridgeProxy(endpoints[SRC_EID], eids, chainIds);
        vm.prank(owner);
        srcBridge.setPeer(DST_EID, bytes32(uint256(uint160(makeAddr("dstBridge")))));

        RetirementTestAccount code = new RetirementTestAccount();
        (eoa7702, eoa7702Key) = makeAddrAndKey("eoa7702");
        vm.signAndAttachDelegation(address(code), eoa7702Key);
        contractAccount = address(new RetirementTestAccount());
        control = address(new RetirementTestAccount());
        vm.deal(eoa7702, 10 ether);
        vm.deal(contractAccount, 10 ether);
        vm.deal(control, 10 ether);
    }

    /// @dev Same as HandlesListConfidentialOAppTest._deployBridgeProxy (Zama's empty-proxy flow).
    function _deployBridgeProxy(
        address lzEndpoint,
        uint32[] memory dstEids,
        uint64[] memory dstChainIds
    ) internal returns (ConfidentialBridge proxy) {
        address emptyImpl = address(new EmptyUUPSProxy());
        DeployableERC1967Proxy raw = new DeployableERC1967Proxy(
            emptyImpl,
            abi.encodeCall(EmptyUUPSProxy.initialize, ())
        );
        address bridgeImpl = address(new ConfidentialBridge(lzEndpoint));
        vm.prank(owner);
        EmptyUUPSProxy(address(raw)).upgradeToAndCall(
            bridgeImpl,
            abi.encodeCall(ConfidentialBridge.initializeFromEmptyProxy, (dstEids, dstChainIds))
        );
        proxy = ConfidentialBridge(payable(address(raw)));
    }

    function _acc(address a) internal pure returns (RetirementTestAccount) {
        return RetirementTestAccount(payable(a));
    }

    function _seedHandle(address account) internal returns (bytes32 h) {
        h = abi.decode(
            _acc(account).execute(
                fhevmExecutorAdd,
                0,
                abi.encodeCall(FHEVMExecutor.trivialEncrypt, (42, FheType.Uint64))
            ),
            (bytes32)
        );
        _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.allow, (h, account)));
        acl.cleanTransientStorage();
    }

    function _retire(address account) internal {
        if (account == eoa7702) {
            vm.prank(account);
            acl.retireAccount();
        } else {
            _acc(account).execute(address(acl), 0, abi.encodeCall(ACL.retireAccount, ()));
        }
        assertTrue(acl.isAccountRetired(account));
    }

    function _sendCall(bytes32 handle) internal view returns (bytes memory) {
        bytes32[] memory list = new bytes32[](1);
        list[0] = handle;
        return abi.encodeCall(HandlesSender.send, (DST_EID, dstApp, bytes(""), list, COMPOSE_GAS));
    }

    function _fee(address srcApp) internal view returns (uint256) {
        bytes32[] memory list = new bytes32[](1);
        list[0] = P;
        MessagingFee memory fee = srcBridge.quote(DST_EID, srcApp, dstApp, "", list, COMPOSE_GAS);
        return fee.nativeFee;
    }

    function test_Export_BridgeSend() public {
        // Control: compute, then bridge the fresh result. The bridge accepts it.
        bytes32 hc = _seedHandle(control);
        _acc(control).computeAndCall(hc, address(srcBridge), _fee(control), _sendCall(P));

        address[2] memory accounts = [eoa7702, contractAccount];
        for (uint256 i = 0; i < 2; i++) {
            address account = accounts[i];
            bytes32 h = _seedHandle(account);
            _retire(account);

            // The exemption: compute still works and grants the result transiently to the retired account.
            bytes32 r = _acc(account).compute(h);
            assertTrue(acl.allowedTransient(r, account));
            assertFalse(acl.isAllowed(r, account));

            uint256 fee = _fee(account);
            (bool ok, bytes memory err) = account.call(
                abi.encodeCall(RetirementTestAccount.computeAndCall, (h, address(srcBridge), fee, _sendCall(P)))
            );
            assertFalse(ok, "retired account cannot bridge a computed handle");
            bytes4 sel;
            bytes32 refused;
            address srcApp;
            assembly {
                sel := mload(add(err, 32))
                refused := mload(add(err, 36))
                srcApp := mload(add(err, 68))
            }
            assertEq(sel, HandlesSender.HandleNotAllowed.selector);
            assertEq(srcApp, account);
            assertTrue(acl.allowedTransient(refused, account), "the refused handle is the executor's fresh result");

            // Its persisted handle is refused the same way.
            (ok, err) = account.call(
                abi.encodeCall(RetirementTestAccount.execute, (address(srcBridge), fee, _sendCall(h)))
            );
            assertFalse(ok, "retired account cannot bridge its persisted handle");
            assertEq(err, abi.encodeWithSelector(HandlesSender.HandleNotAllowed.selector, h, account));
        }
    }
}
