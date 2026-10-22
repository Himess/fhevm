// SPDX-License-Identifier: MIT
// TEST-ONLY COPY of OpenZeppelin Confidential Contracts, ported mechanically as stated below. Do not edit by hand.
// Source: @openzeppelin/confidential-contracts 0.5.3, token/ERC7984/utils/ERC7984Utils.sol
// Source sha256: 2903ed4f58c874454a541389fa2a68cb6ffceefa6281bc5362ff7b5c98969472
// Mechanical port to solc 0.8.24 (nothing else changed): pragma ^0.8.27 -> ^0.8.24; 1 FHE import(s) re-pointed to host-contracts lib/FHE.sol; 1 require(bool, error) -> if (!(cond)) revert error
// OpenZeppelin Confidential Contracts (last updated v0.5.2) (token/ERC7984/utils/ERC7984Utils.sol)
pragma solidity ^0.8.24;

import {FHE, ebool, euint64} from "@fhevm-host-contracts/lib/FHE.sol";

import {IERC7984Receiver} from "../../../interfaces/IERC7984Receiver.sol";
import {ERC7984} from "../ERC7984.sol";

/// @dev Library that provides common {ERC7984} utility functions.
library ERC7984Utils {
    error ERC7984UtilsUnauthorizedUseOfEncryptedAmount(ebool retval, address to);

    /**
     * @dev Performs a transfer callback to the recipient of the transfer `to`. Should be invoked
     * after all transfers "withCallback" on a {ERC7984}.
     *
     * The transfer callback is not invoked on the recipient if the recipient has no code (i.e. is an EOA). If the
     * recipient has non-zero code, it must implement
     * {IERC7984Receiver-onConfidentialTransferReceived} and return an `ebool` indicating
     * whether the transfer was accepted or not. If the `ebool` is `false`, the transfer function
     * should try to refund the `from` address.
     */
    function checkOnTransferReceived(
        address operator,
        address from,
        address to,
        euint64 amount,
        bytes calldata data
    ) internal returns (ebool) {
        if (to.code.length > 0) {
            try IERC7984Receiver(to).onConfidentialTransferReceived(operator, from, amount, data) returns (
                ebool retval
            ) {
                if (!(!FHE.isInitialized(retval) || FHE.isAllowed(retval, to))) revert ERC7984UtilsUnauthorizedUseOfEncryptedAmount(retval, to);
                return retval;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert ERC7984.ERC7984InvalidReceiver(to);
                } else {
                    assembly ("memory-safe") {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return FHE.asEbool(true);
        }
    }
}
