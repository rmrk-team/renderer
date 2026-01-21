// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IRendererApprovalPolicy {

    function approved(uint256 chainId, address collection) external view returns (bool);
    function approvedUntil(uint256 chainId, address collection) external view returns (uint64);

    function approvalKeyCount() external view returns (uint256);

    function approvalKeysPage(
        uint256 start,
        uint256 limit
    )
        external
        view
        returns (
            uint256[] memory chainIds,
            address[] memory collections,
            uint64[] memory approvedUntil
        );
}

/// @notice Approval contract for renderer collection registration (V2).
contract RendererApprovalsV2 is IRendererApprovalPolicy {
    struct Approval {
        uint64 approvedUntil;
        uint64 approvedAt;
        address payer;
    }

    struct ApprovalKey {
        uint256 chainId;
        address collection;
    }

    IERC20 public immutable token;
    address public treasury;
    uint256 public fee;
    address public owner;
    bool public paused;
    bool private locked;

    mapping(uint256 => mapping(address => Approval)) internal approvals;
    ApprovalKey[] internal approvalKeys;
    mapping(bytes32 => uint256) internal approvalKeyIndexPlusOne;

    event ApprovalUpdated(
        uint256 indexed chainId,
        address indexed collection,
        uint64 approvedUntil,
        address payer,
        uint256 amountPaid
    );
    event ApprovalRevoked(uint256 indexed chainId, address indexed collection);
    event TreasuryUpdated(address indexed previous, address indexed next);
    event FeeUpdated(uint256 previous, uint256 next);
    event OwnerUpdated(address indexed previous, address indexed next);
    event Paused(address indexed account);
    event Unpaused(address indexed account);

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "PAUSED");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "REENTRANT");
        locked = true;
        _;
        locked = false;
    }

    constructor(address tokenAddress, address treasuryAddress, uint256 feeAmount) {
        require(tokenAddress != address(0), "TOKEN_ZERO");
        require(treasuryAddress != address(0), "TREASURY_ZERO");
        token = IERC20(tokenAddress);
        treasury = treasuryAddress;
        fee = feeAmount;
        owner = msg.sender;
    }

    /// @notice Approve a collection for rendering by paying the fee.
    function approve(uint256 chainId, address collection) external whenNotPaused nonReentrant {
        require(collection != address(0), "COLLECTION_ZERO");
        Approval storage approval = approvals[chainId][collection];
        require(approval.approvedUntil <= block.timestamp, "ALREADY_APPROVED");
        _collectFee(msg.sender, fee);
        _setApproval(chainId, collection, type(uint64).max, msg.sender, fee);
    }

    /// @notice Approve a collection for a fixed duration.
    function approveFor(
        uint256 chainId,
        address collection,
        uint64 durationSeconds
    ) external whenNotPaused nonReentrant {
        require(collection != address(0), "COLLECTION_ZERO");
        require(durationSeconds > 0, "DURATION_ZERO");
        _collectFee(msg.sender, fee);
        Approval storage approval = approvals[chainId][collection];
        uint64 current = uint64(block.timestamp);
        uint64 base = approval.approvedUntil > current ? approval.approvedUntil : current;
        require(durationSeconds <= type(uint64).max - base, "DURATION_OVERFLOW");
        uint64 newUntil = base + durationSeconds;
        _setApproval(chainId, collection, newUntil, msg.sender, fee);
    }

    /// @notice Grant approval without payment.
    function adminGrant(
        uint256 chainId,
        address collection,
        uint64 approved_until
    ) external onlyOwner {
        require(collection != address(0), "COLLECTION_ZERO");
        require(approved_until > 0, "APPROVAL_ZERO");
        _setApproval(chainId, collection, approved_until, msg.sender, 0);
    }

    function adminRevoke(uint256 chainId, address collection) external onlyOwner {
        Approval storage approval = approvals[chainId][collection];
        approval.approvedUntil = 0;
        approval.payer = address(0);
        emit ApprovalRevoked(chainId, collection);
    }

    function getApproval(
        uint256 chainId,
        address collection
    ) external view returns (uint64 approved_until, uint64 approvedAt, address payer) {
        Approval storage approval = approvals[chainId][collection];
        return (approval.approvedUntil, approval.approvedAt, approval.payer);
    }

    function approved(uint256 chainId, address collection) external view returns (bool) {
        return approvals[chainId][collection].approvedUntil > block.timestamp;
    }

    function isApproved(uint256 chainId, address collection) external view returns (bool) {
        return approvals[chainId][collection].approvedUntil > block.timestamp;
    }

    function approvedUntil(uint256 chainId, address collection) external view returns (uint64) {
        return approvals[chainId][collection].approvedUntil;
    }

    function approvalKeyCount() external view returns (uint256) {
        return approvalKeys.length;
    }

    function approvalKeyAt(
        uint256 index
    ) external view returns (uint256 chainId, address collection, uint64 approved_until) {
        require(index < approvalKeys.length, "INDEX_OOB");
        ApprovalKey storage key = approvalKeys[index];
        return (key.chainId, key.collection, approvals[key.chainId][key.collection].approvedUntil);
    }

    function approvalKeysPage(
        uint256 start,
        uint256 limit
    )
        external
        view
        returns (
            uint256[] memory chainIds,
            address[] memory collections,
            uint64[] memory approved_untils
        )
    {
        uint256 total = approvalKeys.length;
        if (start >= total) {
            return (new uint256[](0), new address[](0), new uint64[](0));
        }
        uint256 end = start + limit;
        if (end > total) {
            end = total;
        }
        uint256 size = end - start;
        chainIds = new uint256[](size);
        collections = new address[](size);
        approved_untils = new uint64[](size);
        for (uint256 i = 0; i < size; i++) {
            ApprovalKey storage key = approvalKeys[start + i];
            chainIds[i] = key.chainId;
            collections[i] = key.collection;
            approved_untils[i] = approvals[key.chainId][key.collection].approvedUntil;
        }
    }

    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "TREASURY_ZERO");
        emit TreasuryUpdated(treasury, newTreasury);
        treasury = newTreasury;
    }

    function setFee(uint256 newFee) external onlyOwner {
        emit FeeUpdated(fee, newFee);
        fee = newFee;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "OWNER_ZERO");
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function _setApproval(
        uint256 chainId,
        address collection,
        uint64 approved_until,
        address payer,
        uint256 amountPaid
    ) internal {
        Approval storage approval = approvals[chainId][collection];
        if (approval.approvedAt == 0) {
            approval.approvedAt = uint64(block.timestamp);
        }
        approval.approvedUntil = approved_until;
        approval.payer = payer;
        _ensureApprovalKey(chainId, collection);
        emit ApprovalUpdated(chainId, collection, approved_until, payer, amountPaid);
    }

    function _ensureApprovalKey(uint256 chainId, address collection) internal {
        bytes32 key = keccak256(abi.encode(chainId, collection));
        if (approvalKeyIndexPlusOne[key] == 0) {
            approvalKeys.push(ApprovalKey(chainId, collection));
            approvalKeyIndexPlusOne[key] = approvalKeys.length;
        }
    }

    function _collectFee(address from, uint256 amount) internal {
        if (amount == 0) {
            return;
        }
        _safeTransferFrom(token, from, treasury, amount);
    }

    function _safeTransferFrom(
        IERC20 erc20,
        address from,
        address to,
        uint256 amount
    ) internal {
        (bool success, bytes memory data) = address(erc20).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "TRANSFER_FAILED");
    }
}
