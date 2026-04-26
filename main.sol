// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    eyeupOHA — "soft signals, hard guarantees"
    ------------------------------------------
    A minimal, non-custodial on-chain social layer for:
      - Friend discovery (likes, mutual matches, blocks)
      - Conversation threads (hash pointers only, no plaintext messages)
      - A "chatbot lane" represented as attestable prompt/response hashes

    Notes:
      - No ETH or token custody; all payable entry points revert.
      - Designed for EVM mainnets: explicit input validation, bounded loops,
        role-based moderation, and predictable storage growth.
      - Message contents are referenced by bytes32 digests (e.g. keccak256 of
        encrypted payload / CID / off-chain blob).
*/

contract eyeupOHA {
    // =============================================================
    // Errors (domain-specific, unique)
    // =============================================================
    error EYU__NotOwner();
    error EYU__NotRole(bytes32 role);
    error EYU__Paused();
    error EYU__EtherRejected();
    error EYU__BadInput();
    error EYU__HandleTaken();
    error EYU__NoProfile();
    error EYU__AlreadyExists();
    error EYU__NotFound();
    error EYU__Blocked();
    error EYU__TooLarge();
    error EYU__RateLimited();
    error EYU__UnsafeOp();
    error EYU__EpochMismatch();
    error EYU__NonceMismatch();

    // =============================================================
    // Events (unique)
    // =============================================================
    event EYU_OwnerTransferred(address indexed oldOwner, address indexed newOwner);
    event EYU_PauseSet(bool paused);
    event EYU_RoleGranted(bytes32 indexed role, address indexed account, address indexed by);
    event EYU_RoleRevoked(bytes32 indexed role, address indexed account, address indexed by);

    event EYU_ProfileCreated(address indexed user, bytes32 indexed handleHash, uint64 at);
    event EYU_ProfileUpdated(address indexed user, uint32 fields, uint64 at);
    event EYU_HandleChanged(address indexed user, bytes32 indexed oldHandleHash, bytes32 indexed newHandleHash, uint64 at);
    event EYU_BlockSet(address indexed by, address indexed target, bool blocked, uint64 at);
    event EYU_LikeSet(address indexed by, address indexed target, bool liked, uint64 at);
    event EYU_MatchMade(address indexed a, address indexed b, bytes32 indexed threadId, uint64 at);
    event EYU_MatchBroken(address indexed a, address indexed b, bytes32 indexed threadId, uint64 at);

    event EYU_ThreadMessage(address indexed from, bytes32 indexed threadId, uint40 seq, bytes32 payloadHash, uint64 at);
    event EYU_ThreadMeta(bytes32 indexed threadId, uint32 key, bytes32 value, uint64 at);

    event EYU_BotLaneOpened(address indexed user, bytes32 indexed laneId, uint64 at);
    event EYU_BotPrompt(address indexed user, bytes32 indexed laneId, uint40 indexed n, bytes32 promptHash, uint64 at);
    event EYU_BotReplyAttested(address indexed attestor, address indexed user, bytes32 indexed laneId, uint40 n, bytes32 replyHash, uint64 at);
    event EYU_ReportFiled(address indexed reporter, address indexed accused, uint32 reason, bytes32 noteHash, uint64 at);
    event EYU_Moderation(address indexed mod, address indexed user, uint8 action, uint32 code, uint64 untilTs, uint64 at);

    // =============================================================
    // Main constants / identity noise (unique)
    // =============================================================
    uint32 private constant _HANDLE_MAX = 24;
    uint32 private constant _BIO_MAX = 240;
    uint32 private constant _TAG_COUNT_MAX = 12;
    uint32 private constant _TAGLEN_MAX = 18;
    uint32 private constant _HANDLE_MIN = 3;

    uint32 private constant _BROWSE_PAGE_MAX = 60;
    uint32 private constant _MUTUAL_SCAN_MAX = 48;
    uint32 private constant _REPORT_NOTE_MAX = 64;

    uint40 private constant _THREAD_SEQ_MAX = type(uint40).max;
    uint32 private constant _BOT_MAX_PER_LANE = 2048;

    // salts used only as domain separation to reduce accidental collisions
    bytes32 private constant _EYU_DOMAIN =
        hex"3a9f8f0b0e2d6d4d86a9ac0bce117bb4d1c8cfd4de4a1c08a2b9dc4c7b2d9a3e";
    bytes32 private constant _EYU_NOISE =
        hex"91b6d3a7a4c5f2f1d0e0c4a8b82b9b6d44f3942f0d98bcf05a0c4b4c2f1a9e77";

    // 3 generic addresses for uniqueness and optional off-chain coordination.
    // They do not receive funds or special powers by default.
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    // =============================================================
    // Ownership + pause
    // =============================================================
    address public owner;
    bool public paused;

    modifier onlyOwner() {
        if (msg.sender != owner) revert EYU__NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert EYU__Paused();
        _;
    }

