// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Fixed 1% fee escrow for requester-funded compute; no token issuance.
/// @dev Output quality and confidential execution are verified outside this contract.
///      Parties must accept the disclosed adjudicator and timeout rules before work.
contract ComputeEscrow is ReentrancyGuard {
    using SafeERC20 for IERC20;
    uint16 public constant FEE_BPS = 100;
    uint16 public constant BPS = 10_000;
    uint16 public constant MAX_WORKERS = 128;
    uint32 public constant MIN_REVIEW_SECONDS = 1 days;
    uint32 public constant MAX_REVIEW_SECONDS = 14 days;
    uint32 public constant MIN_DISPUTE_SECONDS = 1 days;
    uint32 public constant MAX_DISPUTE_SECONDS = 30 days;

    IERC20 public immutable token;
    address public immutable founderRecipient;
    uint256 public totalLiability;

    enum State { None, Funded, Active, Delivered, Disputed, Settled }
    struct Terms {
        bytes32 jobHash;
        uint256 budget;
        address deliveryManager;
        address adjudicator;
        uint64 acceptBy;
        uint64 deliverBy;
        uint32 reviewSeconds;
        uint32 disputeSeconds;
    }
    struct Order {
        address requester;
        Terms terms;
        State state;
        uint16 workerCount;
        uint16 acceptedCount;
        uint64 reviewBy;
        uint64 resolveBy;
        bytes32 outputDigest;
        bytes32 disputeDigest;
        uint256 grossPaid;
        uint256 workerPool;
        uint256 acceptedBitmap;
        uint256 withdrawnBitmap;
    }
    struct Worker {
        address account;
        uint16 cumulativeBps;
    }

    mapping(bytes32 => Order) public orders;
    mapping(bytes32 => Worker[]) private workers;
    mapping(bytes32 => mapping(address => uint16)) private workerIndexPlusOne;
    mapping(address => uint256) public credits;

    error InvalidTerms();
    error InvalidState();
    error Unauthorized();
    error Deadline();
    error AlreadyAccepted();
    error NothingToWithdraw();
    error InexactTokenTransfer();

    event Funded(bytes32 indexed orderId, address indexed requester, bytes32 indexed jobHash, uint256 budget);
    event WorkerAccepted(bytes32 indexed orderId, address indexed worker);
    event Activated(bytes32 indexed orderId);
    event Delivered(bytes32 indexed orderId, bytes32 outputDigest, uint64 reviewBy);
    event Disputed(bytes32 indexed orderId, bytes32 reasonDigest, uint64 resolveBy);
    event Settled(bytes32 indexed orderId, uint256 grossPaid, uint256 founderFee, uint256 requesterRefund);
    event Withdrawn(address indexed account, address indexed recipient, uint256 amount);

    constructor(address tokenAddress, address feeRecipient) {
        if (tokenAddress.code.length == 0 || feeRecipient == address(0) || feeRecipient == address(this)) revert InvalidTerms();
        token = IERC20(tokenAddress);
        founderRecipient = feeRecipient;
    }

    function orderId(address requester, bytes32 jobHash) public view returns (bytes32) {
        return keccak256(abi.encode("Cannabis compute order v1", block.chainid, address(this), requester, jobHash));
    }

    /// @notice All workers must accept these immutable terms before any work starts.
    function fund(Terms calldata terms, address[] calldata accounts, uint16[] calldata sharesBps)
        external nonReentrant returns (bytes32 id)
    {
        if (terms.jobHash == bytes32(0) || terms.budget == 0 ||
            terms.adjudicator == address(0) || terms.adjudicator == address(this) ||
            terms.adjudicator == msg.sender || terms.adjudicator == founderRecipient ||
            terms.acceptBy <= block.timestamp || terms.deliverBy <= terms.acceptBy ||
            terms.deliverBy > block.timestamp + 90 days ||
            terms.reviewSeconds < MIN_REVIEW_SECONDS || terms.reviewSeconds > MAX_REVIEW_SECONDS ||
            terms.disputeSeconds < MIN_DISPUTE_SECONDS || terms.disputeSeconds > MAX_DISPUTE_SECONDS ||
            accounts.length == 0 || accounts.length > MAX_WORKERS || accounts.length != sharesBps.length) revert InvalidTerms();

        id = orderId(msg.sender, terms.jobHash);
        if (orders[id].state != State.None) revert InvalidState();
        uint256 cumulative;
        bool managerFound;
        for (uint256 i; i < accounts.length; ++i) {
            address account = accounts[i];
            if (account == address(0) || account == address(this) || account == msg.sender ||
                account == terms.adjudicator || sharesBps[i] == 0 || workerIndexPlusOne[id][account] != 0) revert InvalidTerms();
            cumulative += sharesBps[i];
            if (cumulative > BPS) revert InvalidTerms();
            workerIndexPlusOne[id][account] = uint16(i + 1);
            workers[id].push(Worker(account, uint16(cumulative)));
            if (account == terms.deliveryManager) managerFound = true;
        }
        if (cumulative != BPS || !managerFound) revert InvalidTerms();
        Order storage order = orders[id];
        order.requester = msg.sender;
        order.terms = terms;
        order.state = State.Funded;
        order.workerCount = uint16(accounts.length);
        totalLiability += terms.budget;
        uint256 previousBalance = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), terms.budget);
        if (token.balanceOf(address(this)) - previousBalance != terms.budget) revert InexactTokenTransfer();
        emit Funded(id, msg.sender, terms.jobHash, terms.budget);
    }

    function workerAt(bytes32 id, uint256 index) external view returns (Worker memory) { return workers[id][index]; }

    function accept(bytes32 id) external {
        Order storage order = orders[id];
        if (order.state != State.Funded) revert InvalidState();
        if (block.timestamp >= order.terms.acceptBy) revert Deadline();
        uint16 index = workerIndexPlusOne[id][msg.sender];
        if (index == 0) revert Unauthorized();
        uint256 bit = uint256(1) << (index - 1);
        if (order.acceptedBitmap & bit != 0) revert AlreadyAccepted();
        order.acceptedBitmap |= bit;
        ++order.acceptedCount;
        emit WorkerAccepted(id, msg.sender);
        if (order.acceptedCount == order.workerCount) {
            order.state = State.Active;
            emit Activated(id);
        }
    }

    /// @notice Cancellation is allowed only before all workers have accepted.
    function cancel(bytes32 id) external {
        Order storage order = orders[id];
        if (order.state != State.Funded) revert InvalidState();
        if (msg.sender != order.requester) revert Unauthorized();
        _settle(id, order, 0);
    }

    /// @notice Only the agreed group delivery manager can publish the encrypted output digest.
    function deliver(bytes32 id, bytes32 outputDigest) external {
        Order storage order = orders[id];
        if (order.state != State.Active) revert InvalidState();
        if (msg.sender != order.terms.deliveryManager) revert Unauthorized();
        if (block.timestamp >= order.terms.deliverBy) revert Deadline();
        if (outputDigest == bytes32(0)) revert InvalidTerms();
        order.outputDigest = outputDigest;
        order.reviewBy = uint64(block.timestamp + order.terms.reviewSeconds);
        order.state = State.Delivered;
        emit Delivered(id, outputDigest, order.reviewBy);
    }

    function approve(bytes32 id) external {
        Order storage order = orders[id];
        if (order.state != State.Delivered) revert InvalidState();
        if (msg.sender != order.requester) revert Unauthorized();
        _settle(id, order, order.terms.budget);
    }

    /// @notice A requester must dispute within the agreed review window.
    function dispute(bytes32 id, bytes32 encryptedReasonDigest) external {
        Order storage order = orders[id];
        if (order.state != State.Delivered) revert InvalidState();
        if (msg.sender != order.requester) revert Unauthorized();
        if (block.timestamp >= order.reviewBy) revert Deadline();
        if (encryptedReasonDigest == bytes32(0)) revert InvalidTerms();
        order.disputeDigest = encryptedReasonDigest;
        order.resolveBy = uint64(block.timestamp + order.terms.disputeSeconds);
        order.state = State.Disputed;
        emit Disputed(id, encryptedReasonDigest, order.resolveBy);
    }

    /// @notice The mutually accepted adjudicator awards an amount, never changes recipients.
    function resolve(bytes32 id, uint256 grossPaid) external {
        Order storage order = orders[id];
        if (order.state != State.Disputed) revert InvalidState();
        if (msg.sender != order.terms.adjudicator) revert Unauthorized();
        if (block.timestamp >= order.resolveBy) revert Deadline();
        if (grossPaid > order.terms.budget) revert InvalidTerms();
        _settle(id, order, grossPaid);
    }

    /// @notice Anyone may finish an expired phase. Rules are fixed before worker acceptance.
    function finalizeExpired(bytes32 id) external {
        Order storage order = orders[id];
        if (order.state == State.Funded && block.timestamp >= order.terms.acceptBy ||
            order.state == State.Active && block.timestamp >= order.terms.deliverBy ||
            order.state == State.Disputed && block.timestamp >= order.resolveBy) {
            _settle(id, order, 0);
        } else if (order.state == State.Delivered && block.timestamp >= order.reviewBy) {
            _settle(id, order, order.terms.budget);
        } else revert Deadline();
    }

    function _settle(bytes32 id, Order storage order, uint256 grossPaid) private {
        uint256 fee = grossPaid / 100; // Exactly 1%, rounded down to a token base unit.
        uint256 refund = order.terms.budget - grossPaid;
        order.state = State.Settled;
        order.grossPaid = grossPaid;
        order.workerPool = grossPaid - fee;
        credits[founderRecipient] += fee;
        credits[order.requester] += refund;
        emit Settled(id, grossPaid, fee, refund);
    }

    function workerDue(bytes32 id, address account) public view returns (uint256) {
        Order storage order = orders[id];
        uint16 index = workerIndexPlusOne[id][account];
        if (order.state != State.Settled || index == 0 ||
            order.withdrawnBitmap & (uint256(1) << (index - 1)) != 0) return 0;
        uint256 previous = index == 1 ? 0 : workers[id][index - 2].cumulativeBps;
        uint256 current = workers[id][index - 1].cumulativeBps;
        // Cumulative rounding conserves every base unit across any worker split.
        return Math.mulDiv(order.workerPool, current, BPS) - Math.mulDiv(order.workerPool, previous, BPS);
    }

    function withdrawWorker(bytes32 id, address recipient) external nonReentrant {
        uint256 amount = workerDue(id, msg.sender);
        if (amount == 0) revert NothingToWithdraw();
        uint16 index = workerIndexPlusOne[id][msg.sender];
        orders[id].withdrawnBitmap |= uint256(1) << (index - 1);
        _withdraw(recipient, amount);
    }

    function withdrawCredit(address recipient) external nonReentrant {
        uint256 amount = credits[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credits[msg.sender] = 0;
        _withdraw(recipient, amount);
    }

    function _withdraw(address recipient, uint256 amount) private {
        if (recipient == address(0) || recipient == address(this)) revert InvalidTerms();
        totalLiability -= amount;
        token.safeTransfer(recipient, amount);
        emit Withdrawn(msg.sender, recipient, amount);
    }
}
