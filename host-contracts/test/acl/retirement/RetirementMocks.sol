// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {FHE, ebool, euint64, externalEuint64} from "@fhevm-host-contracts/lib/FHE.sol";
import {CoprocessorSetup} from "@fhevm-host-contracts/lib/CoprocessorSetup.sol";
import {FHEVMExecutor} from "@fhevm-host-contracts/contracts/FHEVMExecutor.sol";
import {aclAdd, fhevmExecutorAdd} from "@fhevm-host-contracts/addresses/FHEVMHostAddresses.sol";
import {ACL} from "@fhevm-host-contracts/contracts/ACL.sol";

import {ERC7984} from "./oz-confidential-contracts-0.5.3/token/ERC7984/ERC7984.sol";
import {IERC7984Receiver} from "./oz-confidential-contracts-0.5.3/interfaces/IERC7984Receiver.sol";

/**
 * @notice Test-only account for the retirement tests. It is deployed as a plain contract, or attached as the
 *         EIP-7702 delegate of an EOA (`vm.signAndAttachDelegation`), so the same code exercises a contract
 *         account and a 7702 account. Unrestricted on purpose: test-only.
 * @dev `computeAndCall` performs a computation through the FHEVMExecutor (which checks the operand with the
 *      engine exemption and grants the result transiently to this account), then, in the same transaction,
 *      calls an export path with the fresh result substituted for `RESULT_PLACEHOLDER` in the calldata.
 */
contract RetirementTestAccount {
    bytes32 public constant RESULT_PLACEHOLDER = keccak256("RetirementTestAccount.RESULT_PLACEHOLDER");

    struct Call {
        address target;
        uint256 value;
        bytes template;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) _bubble(ret);
    }

    /// @notice Computes `operand + operand` through the FHEVMExecutor.
    function compute(bytes32 operand) public returns (bytes32 result) {
        result = FHEVMExecutor(fhevmExecutorAdd).fheAdd(operand, operand, 0x00);
    }

    /// @notice Computes through the executor, then calls `target` with `template`, where every 32-byte occurrence
    ///         of `RESULT_PLACEHOLDER` (at any byte offset, so nested calldata works) is replaced by the result.
    function computeAndCall(
        bytes32 operand,
        address target,
        uint256 value,
        bytes calldata template
    ) external payable returns (bytes32 result, bytes memory ret) {
        result = compute(operand);
        bytes memory data = _fill(template, result);
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) _bubble(ret);
    }

    /// @notice Same as `computeAndCall`, with several calls in sequence (for example a transient grant to a token,
    ///         then the token call).
    function computeAndCallBatch(bytes32 operand, Call[] calldata calls) external payable returns (bytes32 result) {
        result = compute(operand);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(_fill(calls[i].template, result));
            if (!ok) _bubble(ret);
        }
    }

    receive() external payable {}

    function _fill(bytes memory data, bytes32 value) internal pure returns (bytes memory) {
        bytes32 needle = RESULT_PLACEHOLDER;
        uint256 len = data.length;
        uint256 i;
        while (i + 32 <= len) {
            bytes32 word;
            assembly {
                word := mload(add(add(data, 32), i))
            }
            if (word == needle) {
                assembly {
                    mstore(add(add(data, 32), i), value)
                }
                i += 32;
            } else {
                unchecked {
                    ++i;
                }
            }
        }
        return data;
    }

    function _bubble(bytes memory ret) private pure {
        assembly {
            revert(add(ret, 32), mload(ret))
        }
    }
}

/**
 * @notice A deputy that accepts caller-held handles through `FHE.fromExternal(h, "")`, which checks
 *         `isAllowed(h, msg.sender)` with the deputy as the ACL caller.
 */
contract FromExternalDeputy {
    event HandleAccepted(address indexed caller, bytes32 handle);

    constructor() {
        FHE.setCoprocessor(CoprocessorSetup.defaultConfig());
    }

    function useHandle(externalEuint64 inputHandle) external returns (euint64 value) {
        value = FHE.fromExternal(inputHandle, "");
        emit HandleAccepted(msg.sender, euint64.unwrap(value));
    }
}

/**
 * @notice OpenZeppelin ERC-7984 (confidential-contracts 0.5.3, vendored test-only copy) with a test mint.
 */
contract ERC7984RetirementToken is ERC7984 {
    constructor() ERC7984("Retirement Test Token", "RTT", "") {
        FHE.setCoprocessor(CoprocessorSetup.defaultConfig());
    }

    function mint(address to, uint64 amount) external returns (euint64) {
        return _mint(to, FHE.asEuint64(amount));
    }
}

/**
 * @notice ERC-7984 receiver that accepts every transfer, mirroring OpenZeppelin's receiver mock: it answers with
 *         `FHE.asEbool(true)` and grants the token transient access to that answer. It can retire itself.
 */
contract ERC7984AcceptingReceiver is IERC7984Receiver {
    constructor() {
        FHE.setCoprocessor(CoprocessorSetup.defaultConfig());
    }

    function onConfidentialTransferReceived(address, address, euint64, bytes calldata) external returns (ebool) {
        ebool accepted = FHE.asEbool(true);
        FHE.allowTransient(accepted, msg.sender);
        return accepted;
    }

    function retire() external {
        ACL(aclAdd).retireAccount();
    }
}

/**
 * @notice Upgrade-matrix implementation (U4c): reports the right retirement storage location but no longer
 *         declares the Core interface through ERC-165.
 */
contract ACLLocationOnlyNoCore is ACL {
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == 0x01ffc9a7;
    }
}

/**
 * @notice Upgrade-matrix implementation (U4b, report-level): declares Core but reports another retirement
 *         storage location. `ACL_v0_8_0_drift` (fixture) is the storage-level version of the same failure.
 */
contract ACLCoreOtherLocation is ACL {
    function retirementStorageLocation() public pure virtual override returns (bytes32) {
        return keccak256("another namespace");
    }
}
