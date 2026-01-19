// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ArbiterBase } from "@rhinestone/compact-utils/src/base/arbiter/ArbiterBase.sol";
import {
    AdapterBasePrefund,
    AdapterBase
} from "@rhinestone/compact-utils/src/base/adapter/AdapterBasePrefund.sol";
import { SemVer } from "@rhinestone/compact-utils/src/common/semver/SemVer.sol";
import { TokenIdLib } from "@rhinestone/compact-utils/src/common/TokenIdLib.sol";
import { SafeTransferLib } from "@solady/utils/SafeTransferLib.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";
import { Constants } from "@rhinestone/compact-utils/src/types/Constants.sol";

contract MockAdapter is AdapterBasePrefund, ArbiterBase {
    using TokenIdLib for uint256[2][];
    using SafeTransferLib for address;

    struct ClaimDataCompact {
        Types.Order order;
        Types.Signatures userSigs;
        bytes32[] otherElements;
        bytes allocatorData;
        uint256 elementIndex;
    }

    struct ClaimDataPermit2 {
        Types.Order order;
        Types.Signatures userSigs;
    }

    constructor(
        address router,
        address compact,
        address addressBook
    )
        AdapterBasePrefund(router, address(this))
        SemVer(0, 1)
        ArbiterBase(router, compact, addressBook)
    {
        ARBITER = address(this);
    }

    function _tokenInRecipient() internal pure returns (address tokenInRecipient) {
        (uint256 relayerContextLength, bytes calldata relayerContext) = _loadRelayerContext();
        require(relayerContextLength == 20, InvalidRelayerContext());
        return address(bytes20(relayerContext[:20]));
    }

    function mock_compact_handleClaim(ClaimDataCompact calldata claimData)
        external
        payable
        onlyViaRouter
        returns (bytes4)
    {
        address solver = _tokenInRecipient();
        _prefundRecipient(msg.sender, claimData.order.recipient, claimData.order.tokenOut);

        if (claimData.elementIndex == 0 && claimData.order.notarizedChainId == block.chainid) {
            MockAdapter(payable(ARBITER)).handleNotarizedChain(claimData, solver);
        } else {
            MockAdapter(payable(ARBITER)).handleExogenousChain(claimData, solver);
        }

        emit RouterFilled(claimData.order.sponsor, claimData.order.nonce);
        return this.mock_compact_handleClaim.selector;
    }

    function mock_handleFill(Types.Order calldata order)
        external
        payable
        onlyViaRouter
        returns (bytes4)
    {
        _prefundRecipient(msg.sender, order.recipient, order.tokenOut);
        emit RouterFilled(order.sponsor, order.nonce);
        return this.mock_handleFill.selector;
    }

    function handleNotarizedChain(ClaimDataCompact calldata claimData, address solver) external {
        bytes32 mandateHash = _compactPreClaimOps({
            order: claimData.order,
            sigs: claimData.userSigs,
            otherElements: claimData.otherElements,
            elementOffset: 0,
            notarizedChainId: block.chainid
        });

        _unlockNotarizedChain({
            order: claimData.order,
            otherElements: claimData.otherElements,
            originChainSig: claimData.userSigs.notarizedClaimSig,
            allocatorData: claimData.allocatorData,
            depositor: address(this),
            mandateHash: mandateHash
        });

        _transferToSolver(claimData.order.tokenIn, solver);
    }

    function mock_permit2_handleClaim(ClaimDataPermit2 calldata claimData)
        external
        payable
        onlyViaRouter
        returns (bytes4)
    {
        address solver = _tokenInRecipient();
        _prefundRecipient(msg.sender, claimData.order.recipient, claimData.order.tokenOut);

        MockAdapter(payable(ARBITER)).handlePermit2(claimData, solver);

        emit RouterFilled(claimData.order.sponsor, claimData.order.nonce);
        return this.mock_permit2_handleClaim.selector;
    }

    function handlePermit2(ClaimDataPermit2 calldata claimData, address solver) external {
        // Permit2 always uses block.chainid as origin chain
        bytes32 mandateHash =
            _permit2PreClaimOps({ order: claimData.order, sigs: claimData.userSigs });

        _unlockPermit2({
            order: claimData.order,
            sig: claimData.userSigs.notarizedClaimSig,
            depositor: address(this),
            mandateHash: mandateHash
        });

        _transferToSolver(claimData.order.tokenIn, solver);
    }

    function handleExogenousChain(ClaimDataCompact calldata claimData, address solver) external {
        uint256 notarizedChainId = claimData.order.notarizedChainId;

        bytes32 mandateHash = _compactPreClaimOps({
            order: claimData.order,
            sigs: claimData.userSigs,
            otherElements: claimData.otherElements,
            elementOffset: claimData.elementIndex + 1,
            notarizedChainId: notarizedChainId
        });

        _unlockExogenousChain({
            order: claimData.order,
            originChainSig: claimData.userSigs.notarizedClaimSig,
            allocatorData: claimData.allocatorData,
            notarizedChainId: notarizedChainId,
            otherElements: claimData.otherElements,
            chainIndex: claimData.elementIndex,
            depositor: address(this),
            mandateHash: mandateHash
        });

        _transferToSolver(claimData.order.tokenIn, solver);
    }

    function _transferToSolver(uint256[2][] calldata idsAndAmounts, address solver) internal {
        for (uint256 i; i < idsAndAmounts.length; i++) {
            (address token, uint256 amount) = idsAndAmounts.unpack(i);
            if (token == Constants.NATIVE_TOKEN) {
                solver.safeTransferETH(amount);
            } else {
                token.safeTransfer(solver, amount);
            }
        }
    }

    function supportsInterface(bytes4 selector)
        public
        pure
        override(AdapterBase, ArbiterBase)
        returns (bool)
    {
        return selector == this.mock_compact_handleClaim.selector
            || selector == this.mock_permit2_handleClaim.selector
            || selector == this.mock_handleFill.selector || AdapterBase.supportsInterface(selector)
            || ArbiterBase.supportsInterface(selector);
    }

    receive() external payable { }
}
