// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Contracts
import { OwnableValidator } from "@mocks/MockOwnableValidator.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IERC1271 } from "@modulekit/module-bases/interfaces/IERC1271.sol";

// Libraries
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

// Types
import {
    PermissionId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { Vm } from "forge-std/Vm.sol";
import {
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { CALLTYPE_STATIC } from "erc7579/lib/ModeLib.sol";

/// @title SmartSessionERC7739 Unit Test Base
/// @notice Base contract for the ERC-7739 signature path, with a real ECDSA session validator
///         and the ERC-7739 `TypedDataSign` digest computed in the test
contract SmartSessionERC7739_Unit_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 constant ERC7739_DETECTION_HASH =
        0x7739773977397739773977397739773977397739773977397739773977397739;
    bytes4 constant ERC7739_SUPPORT_VALUE = 0x77390002;

    /// @dev The `TypedDataSign` fields after `contents`, as ERC-7739 defines them.
    string constant TYPED_DATA_SIGN_FIELDS =
        " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";

    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Session validator that checks a real ECDSA signature
    OwnableValidator internal ownableValidator;

    /// @notice The key the session validator accepts
    Vm.Wallet internal sessionKey;

    /// @notice A second account with the emissary installed
    AccountInstance internal otherInstance;

    /// @notice The app domain the sessions enable by default
    bytes32 internal appDomainSeparator;

    /// @notice A second app domain
    bytes32 internal otherAppDomainSeparator;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        ownableValidator = new OwnableValidator();
        sessionKey = vm.createWallet("sessionKey");

        _setUpAccount(instance);
        otherInstance = makeAccountInstance("OtherAccount");
        _setUpAccount(otherInstance);

        appDomainSeparator = _appDomainSeparator("ExternalApp");
        otherAppDomainSeparator = _appDomainSeparator("OtherApp");
    }

    /// @notice Deploys `account` and installs the emissary and the EIP-712 domain fallback
    function _setUpAccount(AccountInstance memory account) internal {
        account.deployAccount();
        account.installModule({
            moduleTypeId: MODULE_TYPE_FALLBACK,
            module: address(fallbackModule),
            data: abi.encode(EIP712.eip712Domain.selector, CALLTYPE_STATIC, "")
        });
        account.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
        });
    }

    /*//////////////////////////////////////////////////////////////
                            SESSION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables `descriptions` under `domain` on `account`, signed for by `sessionKey`
    function _enableContents(
        AccountInstance memory account,
        bytes32 domain,
        string[] memory descriptions
    )
        internal
        returns (PermissionId)
    {
        address[] memory owners = new address[](1);
        owners[0] = sessionKey.addr;
        return _enableContents({
            account: account,
            validator: ISessionValidator(address(ownableValidator)),
            validatorInitData: abi.encode(uint256(1), owners),
            domain: domain,
            descriptions: descriptions
        });
    }

    /// @notice Enables `descriptions` under `domain` on `instance` with a session validator that
    ///         accepts any signature, so only the envelope can reject
    function _enableContentsAnySignature(
        bytes32 domain,
        string[] memory descriptions
    )
        internal
        returns (PermissionId)
    {
        return _enableContents({
            account: instance,
            validator: ISessionValidator(address(yesSessionValidator)),
            validatorInitData: "mockInitData",
            domain: domain,
            descriptions: descriptions
        });
    }

    function _enableContents(
        AccountInstance memory account,
        ISessionValidator validator,
        bytes memory validatorInitData,
        bytes32 domain,
        string[] memory descriptions
    )
        internal
        returns (PermissionId)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = descriptions;
        allowedContent[0].appDomainSeparator = domain;

        Session[] memory sessions = new Session[](1);
        sessions[0] = Session({
            sessionValidator: validator,
            salt: keccak256(abi.encode(domain, descriptions)),
            sessionValidatorInitData: validatorInitData,
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: allowedContent, erc1271Policies: policyDatas
            }),
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        vm.prank(account.account);
        return smartSessionEmissary.enableSessions(sessions, NO_LOCK_TAG)[0];
    }

    /*//////////////////////////////////////////////////////////////
                            ERC-7739 DIGEST
    //////////////////////////////////////////////////////////////*/

    /// @notice The ERC-7739 `TypedDataSign` typehash, with the type strings as given
    function _typedDataSignTypehash(
        string memory contentsName,
        string memory contentsType
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("TypedDataSign(", contentsName, TYPED_DATA_SIGN_FIELDS, contentsType)
        );
    }

    /// @notice The ERC-7739 digest a session key signs for `account`: the app domain over
    ///         `hashStruct(TypedDataSign)`, whose domain fields are the account's `eip712Domain`
    function _typedDataSignDigest(
        address account,
        bytes32 domain,
        bytes32 typedDataSignTypehash,
        bytes32 contents
    )
        internal
        view
        returns (bytes32)
    {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = EIP712(account).eip712Domain();
        bytes32 typedDataSign = keccak256(
            abi.encode(
                typedDataSignTypehash,
                contents,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract,
                salt
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, typedDataSign));
    }

    /// @notice EIP-712 `hashStruct` from a type string and `encodeData`
    function _hashStruct(
        string memory contentsType,
        bytes memory encodeData
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(keccak256(bytes(contentsType)), encodeData));
    }

    /// @notice The hash the app passes to `isValidSignature`
    function _appHash(bytes32 domain, bytes32 contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domain, contents));
    }

    function _appDomainSeparator(string memory appName) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(appName)),
                keccak256("1"),
                block.chainid,
                address(0xC0FFEE)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                           SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice A mode 0x01 signature: header, then the appended data and its trailer
    function _envelope(
        PermissionId permissionId,
        bytes memory validatorSignature,
        bytes32 domain,
        bytes memory encodeData,
        bytes memory description
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes1(0x01),
            permissionId,
            uint256(64 + validatorSignature.length),
            validatorSignature,
            domain,
            encodeData,
            description,
            uint16(encodeData.length / 32),
            uint16(description.length)
        );
    }

    /// @notice Validates `signature` through `account`'s ERC-1271
    function _isValidSignature(
        AccountInstance memory account,
        bytes32 hash,
        bytes memory signature
    )
        internal
        view
        returns (bytes4)
    {
        return IERC1271(account.account)
            .isValidSignature(hash, abi.encodePacked(address(smartSessionEmissary), signature));
    }

    /// @notice Calls the emissary as `instance`, reporting a revert instead of propagating it
    function _tryIsValidSignature(
        bytes32 hash,
        bytes memory signature
    )
        internal
        returns (bool reverted, bytes4 result)
    {
        vm.prank(instance.account);
        try smartSessionEmissary.isValidSignatureWithSender(
            address(this), hash, signature
        ) returns (
            bytes4 value
        ) {
            result = value;
        } catch {
            reverted = true;
        }
    }
}
