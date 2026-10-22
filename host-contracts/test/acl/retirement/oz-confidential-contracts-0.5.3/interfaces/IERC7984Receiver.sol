// SPDX-License-Identifier: MIT
// TEST-ONLY COPY of OpenZeppelin Confidential Contracts, ported mechanically as stated below. Do not edit by hand.
// Source: @openzeppelin/confidential-contracts 0.5.3, interfaces/IERC7984Receiver.sol
// Source sha256: 562aced7399eba2269f20ddd3a9652e8b30f3e802ace134e3ff0d2686d132fde
// Mechanical port to solc 0.8.24 (nothing else changed): 1 FHE import(s) re-pointed to host-contracts lib/FHE.sol
// OpenZeppelin Confidential Contracts (last updated v0.5.2) (interfaces/IERC7984Receiver.sol)
pragma solidity ^0.8.24;

import {ebool, euint64} from "@fhevm-host-contracts/lib/FHE.sol";

/// @dev Interface for contracts that can receive ERC7984 transfers with a callback.
interface IERC7984Receiver {
    /**
     * @dev Called upon receiving a confidential token transfer. Returns an encrypted boolean indicating success
     * of the callback. If false is returned, the token contract will attempt to refund the transfer.
     *
     * NOTE: The calling contract (token) must be granted ACL allowance to read the confidential return value if
     * it is initialized. Uninitialized return values are treated as a false boolean.
     *
     * WARNING: Do not manually refund the transfer AND return false, as this can lead to double refunds.
     */
    function onConfidentialTransferReceived(
        address operator,
        address from,
        euint64 amount,
        bytes calldata data
    ) external returns (ebool);
}
