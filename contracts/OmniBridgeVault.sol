// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";

import { OApp, MessagingFee, Origin } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { OAppOptionsType3 } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OAppOptionsType3.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { WrappedToken } from "./WrappedToken.sol";

interface IEndpointEid {
    function eid() external view returns (uint32);
}

contract OmniBridgeVault is ReentrancyGuard, OApp, OAppOptionsType3 {
    using SafeERC20 for IERC20;

    uint8 private constant MSG_REGISTER = 1;
    uint8 private constant MSG_TRANSFER = 2;
    uint256 private constant MAX_METADATA_LENGTH = 64;

    uint16 public constant MAX_FEE_BPS = 3000;
    uint16 public constant SEND = 1;

    uint32 public immutable localEid;
    address public immutable wrappedTokenImpl;

    address public feeAdmin;
    uint16 public defaultFeeBps;
    uint256 public defaultMaxFee;
    address public defaultFeeReceiver;
    uint256 public defaultEthFee;

    uint64 public nextNonce;
    uint256 private currentEthFee;

    mapping(bytes32 => bool) public processed;

    struct TokenInfo {
        bool registered;
        bool isWrapped;
        uint32 originEid;
        bytes32 originToken;
    }

    struct FeeConfig {
        bool configured;
        uint16 feeBps;
        uint256 maxFee;
        address feeReceiver;
        uint256 ethFee;
    }

    mapping(address => TokenInfo) public tokenInfo;
    mapping(bytes32 => address) public tokenByOrigin;
    mapping(address => FeeConfig) public tokenFeeConfig;

    event TokenRegistered(
        uint32 indexed originEid,
        bytes32 indexed originToken,
        address indexed localToken,
        bool isWrapped,
        string name,
        string symbol,
        uint8 decimals
    );
    event Sent(
        address indexed token,
        address indexed from,
        address indexed to,
        uint256 amount,
        bytes32 messageId,
        uint64 nonce
    );
    event Received(
        address indexed token,
        address indexed to,
        uint256 amount,
        bytes32 messageId
    );
    event FeeConfigUpdated(uint16 feeBps, uint256 maxFee, address feeReceiver, uint256 ethFee);
    event TokenFeeConfigUpdated(address indexed token, uint16 feeBps, uint256 maxFee, address feeReceiver, uint256 ethFee);
    event FeeAdminUpdated(address indexed feeAdmin);
    event EthFeeWithdrawn(address indexed to, uint256 amount);
    event EndpointConfigured(bytes data);

    error AlreadyProcessed();
    error NotFeeAdmin();
    error InvalidToken();
    error TokenNotRegistered();
    error WrappedTokenCannotRegister();
    error NativeTokenCannotRegister();
    error FeeOnTransferNotSupported();
    error TokenMetadataTooLong();
    error TokenMetadataUnavailable();

    constructor(address endpointAddress) OApp(endpointAddress, msg.sender) Ownable(msg.sender) {
        require(endpointAddress != address(0), "endpoint=0");
        localEid = IEndpointEid(endpointAddress).eid();
        wrappedTokenImpl = address(new WrappedToken());
        feeAdmin = msg.sender;
        emit FeeAdminUpdated(msg.sender);
    }

    modifier onlyFeeAdmin() {
        if (msg.sender != feeAdmin) revert NotFeeAdmin();
        _;
    }

    function setFeeAdmin(address feeAdmin_) external onlyFeeAdmin {
        require(feeAdmin_ != address(0), "feeAdmin=0");
        feeAdmin = feeAdmin_;
        emit FeeAdminUpdated(feeAdmin_);
    }

    function setDefaultFeeConfig(
        uint16 feeBps_,
        uint256 maxFee_,
        address feeReceiver_,
        uint256 ethFee_
    ) external onlyFeeAdmin {
        require(feeBps_ <= MAX_FEE_BPS, "fee>max");
        defaultFeeBps = feeBps_;
        defaultMaxFee = maxFee_;
        defaultFeeReceiver = feeReceiver_;
        defaultEthFee = ethFee_;
        emit FeeConfigUpdated(feeBps_, maxFee_, feeReceiver_, ethFee_);
    }

    function setTokenFeeConfig(
        address token,
        uint16 feeBps_,
        uint256 maxFee_,
        address feeReceiver_,
        uint256 ethFee_
    ) external onlyFeeAdmin {
        require(token != address(0), "token=0");
        require(feeBps_ <= MAX_FEE_BPS, "fee>max");
        tokenFeeConfig[token] = FeeConfig({
            configured: true,
            feeBps: feeBps_,
            maxFee: maxFee_,
            feeReceiver: feeReceiver_,
            ethFee: ethFee_
        });
        emit TokenFeeConfigUpdated(token, feeBps_, maxFee_, feeReceiver_, ethFee_);
    }

    function withdrawEthFees(uint256 amount) external nonReentrant {
        (bool ok, ) = feeAdmin.call{ value: amount }("");
        require(ok, "withdraw-failed");
        emit EthFeeWithdrawn(feeAdmin, amount);
    }

    function configureEndpoint(bytes calldata data) external onlyOwner {
        (bool ok, ) = address(endpoint).call(data);
        require(ok, "endpoint-config-failed");
        emit EndpointConfigured(data);
    }

    function registerToken(
        address token,
        uint32 dstEid,
        bytes calldata extraOptions
    ) external payable nonReentrant returns (bytes32 messageId) {
        if (token == address(0)) revert InvalidToken();
        if (dstEid == 0) revert InvalidToken();
        if (token.code.length == 0) revert InvalidToken();
        TokenInfo memory info = tokenInfo[token];
        if (info.registered && info.isWrapped) revert WrappedTokenCannotRegister();
        if (!info.registered) {
            _registerNativeToken(token);
        }

        (string memory name, string memory symbol, uint8 decimals) = _readMetadata(token);

        uint64 nonce = nextNonce++;
        bytes32 originToken = _toBytes32(token);
        messageId = keccak256(
            abi.encodePacked(address(this), msg.sender, token, dstEid, nonce, block.chainid, MSG_REGISTER)
        );
        bytes memory payload = abi.encode(
            localEid,
            originToken,
            name,
            symbol,
            decimals,
            messageId
        );
        bytes memory message = abi.encode(MSG_REGISTER, payload);
        bytes memory options = combineOptions(dstEid, SEND, extraOptions);
        MessagingFee memory messagingFee = _quote(dstEid, message, options, false);
        _lzSend(dstEid, message, options, messagingFee, msg.sender);
    }

    function sendToken(
        address token,
        address to,
        uint256 amount,
        uint32 dstEid,
        bytes calldata extraOptions
    ) external payable nonReentrant returns (bytes32 messageId) {
        if (token == address(0)) revert InvalidToken();
        if (to == address(0)) revert InvalidToken();
        if (amount == 0) revert InvalidToken();
        if (dstEid == 0) revert InvalidToken();

        TokenInfo memory info = tokenInfo[token];
        if (!info.registered) {
            info = _registerNativeToken(token);
        }

        (uint256 feeAmount, uint256 netAmount, address feeReceiver, uint256 ethFee) =
            _takeTokenFee(token, amount, info.isWrapped);

        uint64 nonce = nextNonce++;
        messageId = keccak256(
            abi.encodePacked(address(this), msg.sender, token, to, netAmount, nonce, block.chainid, info.originEid, info.originToken)
        );
        bytes memory payload = abi.encode(
            info.originEid,
            info.originToken,
            to,
            netAmount,
            messageId
        );
        bytes memory message = abi.encode(MSG_TRANSFER, payload);
        bytes memory options = combineOptions(dstEid, SEND, extraOptions);
        MessagingFee memory messagingFee = _quote(dstEid, message, options, false);
        _setCurrentEthFee(ethFee);
        _lzSend(dstEid, message, options, messagingFee, msg.sender);
        _clearCurrentEthFee();
        emit Sent(token, msg.sender, to, netAmount, messageId, nonce);
    }

    function _lzReceive(
        Origin calldata,
        bytes32,
        bytes calldata message,
        address,
        bytes calldata
    ) internal override nonReentrant {
        (uint8 msgType, bytes memory payload) = abi.decode(message, (uint8, bytes));
        if (msgType == MSG_REGISTER) {
            _handleRegister(payload);
        } else if (msgType == MSG_TRANSFER) {
            _handleTransfer(payload);
        } else {
            revert InvalidToken();
        }
    }

    function _handleRegister(bytes memory payload) internal {
        (
            uint32 originEid,
            bytes32 originToken,
            string memory name,
            string memory symbol,
            uint8 decimals,
            bytes32 messageId
        ) = abi.decode(payload, (uint32, bytes32, string, string, uint8, bytes32));

        if (processed[messageId]) revert AlreadyProcessed();
        processed[messageId] = true;

        if (originEid == localEid) revert NativeTokenCannotRegister();

        bytes32 key = _originKey(originEid, originToken);
        address existing = tokenByOrigin[key];
        if (existing != address(0)) {
            return;
        }

        bytes32 salt = keccak256(abi.encode(originEid, originToken));
        address predicted = Clones.predictDeterministicAddress(wrappedTokenImpl, salt, address(this));
        if (predicted.code.length == 0) {
            Clones.cloneDeterministic(wrappedTokenImpl, salt);
            WrappedToken(predicted).initialize(name, symbol, decimals, address(this));
        }

        tokenByOrigin[key] = predicted;
        tokenInfo[predicted] = TokenInfo({
            registered: true,
            isWrapped: true,
            originEid: originEid,
            originToken: originToken
        });

        emit TokenRegistered(originEid, originToken, predicted, true, name, symbol, decimals);
    }

    function _handleTransfer(bytes memory payload) internal {
        (
            uint32 originEid,
            bytes32 originToken,
            address to,
            uint256 amount,
            bytes32 messageId
        ) = abi.decode(payload, (uint32, bytes32, address, uint256, bytes32));

        if (processed[messageId]) revert AlreadyProcessed();
        processed[messageId] = true;

        address localToken = tokenByOrigin[_originKey(originEid, originToken)];
        if (localToken == address(0)) revert TokenNotRegistered();

        TokenInfo memory info = tokenInfo[localToken];
        if (info.isWrapped) {
            WrappedToken(localToken).mint(to, amount);
        } else {
            IERC20(localToken).safeTransfer(to, amount);
        }

        emit Received(localToken, to, amount, messageId);
    }

    function _registerNativeToken(address token) internal returns (TokenInfo memory info) {
        info = TokenInfo({
            registered: true,
            isWrapped: false,
            originEid: localEid,
            originToken: _toBytes32(token)
        });
        tokenInfo[token] = info;
        tokenByOrigin[_originKey(localEid, info.originToken)] = token;
    }

    function _takeTokenFee(
        address token,
        uint256 amount,
        bool isWrapped
    ) internal returns (uint256 feeAmount, uint256 netAmount, address feeReceiver, uint256 ethFee) {
        (uint16 feeBps, uint256 maxFee, address feeReceiver_, uint256 ethFee_) = _resolveFeeConfig(token);
        feeReceiver = feeReceiver_;
        ethFee = ethFee_;
        if (isWrapped) {
            feeAmount = _computeFee(amount, feeBps, maxFee, feeReceiver);
            netAmount = amount - feeAmount;
            require(netAmount > 0, "net=0");
            WrappedToken(token).burnFrom(msg.sender, amount);
            if (feeAmount > 0 && feeReceiver != address(0)) {
                WrappedToken(token).mint(feeReceiver, feeAmount);
            }
        } else {
            uint256 balanceBefore = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            uint256 balanceAfter = IERC20(token).balanceOf(address(this));
            uint256 received = balanceAfter - balanceBefore;
            if (received != amount) revert FeeOnTransferNotSupported();
            feeAmount = _computeFee(amount, feeBps, maxFee, feeReceiver);
            netAmount = amount - feeAmount;
            require(netAmount > 0, "net=0");
            if (feeAmount > 0 && feeReceiver != address(0)) {
                IERC20(token).safeTransfer(feeReceiver, feeAmount);
            }
        }
    }

    function _computeFee(
        uint256 amount,
        uint16 feeBps,
        uint256 maxFee,
        address feeReceiver
    ) internal pure returns (uint256) {
        if (feeReceiver == address(0) || feeBps == 0 || maxFee == 0) {
            return 0;
        }
        uint256 fee = (amount * feeBps) / 10_000;
        if (fee > maxFee) {
            fee = maxFee;
        }
        if (fee > amount) {
            return amount;
        }
        return fee;
    }

    function _resolveFeeConfig(address token)
        internal
        view
        returns (uint16 feeBps, uint256 maxFee, address feeReceiver, uint256 ethFee)
    {
        FeeConfig memory cfg = tokenFeeConfig[token];
        if (cfg.configured) {
            return (cfg.feeBps, cfg.maxFee, cfg.feeReceiver, cfg.ethFee);
        }
        return (defaultFeeBps, defaultMaxFee, defaultFeeReceiver, defaultEthFee);
    }

    function _originKey(uint32 originEid, bytes32 originToken) internal pure returns (bytes32) {
        return keccak256(abi.encode(originEid, originToken));
    }

    function _toBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    function _readMetadata(address token) internal view returns (string memory, string memory, uint8) {
        IERC20Metadata meta = IERC20Metadata(token);
        string memory name;
        string memory symbol;
        uint8 decimals;

        try meta.name() returns (string memory n) {
            if (bytes(n).length > MAX_METADATA_LENGTH) revert TokenMetadataTooLong();
            name = n;
        } catch {
            revert TokenMetadataUnavailable();
        }

        try meta.symbol() returns (string memory s) {
            if (bytes(s).length > MAX_METADATA_LENGTH) revert TokenMetadataTooLong();
            symbol = s;
        } catch {
            revert TokenMetadataUnavailable();
        }

        try meta.decimals() returns (uint8 d) {
            decimals = d;
        } catch {
            revert TokenMetadataUnavailable();
        }

        return (name, symbol, decimals);
    }

    function _setCurrentEthFee(uint256 ethFee) internal {
        currentEthFee = ethFee;
    }

    function _clearCurrentEthFee() internal {
        currentEthFee = 0;
    }

    function _payNative(uint256 _nativeFee) internal override returns (uint256 nativeFee) {
        if (msg.value != _nativeFee + currentEthFee) revert NotEnoughNative(msg.value);
        if (currentEthFee > 0) {
            feeAdmin.call{ value: currentEthFee, gas: 2300 }("");
        }
        return _nativeFee;
    }
}
