// SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";

contract BatchSchnorrVerifier {
    Schnorr public schnorr;

    constructor(address _schnorr) {
        schnorr = Schnorr(_schnorr);
    }

    struct Signature {
        uint8 parity;
        bytes32 px;
        bytes32 e;
        bytes32 s;
    }

    /**
     * @notice Verifies multiple Schnorr signatures against a single message derived from a list of value lists
     * @param signatures Array of signatures to verify
     * @param valueLists Array of value lists, where each inner list must have exactly 5 values
     * @return bool True if all signatures are valid, false otherwise
     */
    function verifyBatch(
        Signature[] calldata signatures,
        bytes32[5][] calldata valueLists
    ) external view returns (bool) {
        require(signatures.length > 0, "No signatures provided");
        require(valueLists.length > 0, "No value lists provided");

        // Hash all value lists together to create the message
        bytes32 message = keccak256(abi.encodePacked(valueLists));

        // Verify each signature
        for (uint256 i = 0; i < signatures.length; i++) {
            bool isValid = schnorr.verify(
                signatures[i].parity,
                signatures[i].px,
                message,
                signatures[i].e,
                signatures[i].s
            );
            if (!isValid) {
                return false;
            }
        }

        return true;
    }

    function coinDeposit(
        Signature[] calldata signatures,
        bytes32[5] calldata valueList
    ) external view returns (bool) {
        require(signatures.length > 0, "No signatures provided");
        require(valueList.length == 5, "Invalid value list length");

        // Hash all value lists together to create the message
        bytes32 message = keccak256(abi.encodePacked(valueList));

        // Verify each signature
        for (uint256 i = 0; i < signatures.length; i++) {
            bool isValid = schnorr.verify(
                signatures[i].parity,
                signatures[i].px,
                message,
                signatures[i].e,
                signatures[i].s
            );
            if (!isValid) {
                return false;
            }
        }

        return true;
    }
} 