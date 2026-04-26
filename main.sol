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

    // =============================================================
    // Roles (lightweight AccessControl-like)
    // =============================================================
    bytes32 public constant ROLE_MODERATOR = keccak256("eyeupOHA.ROLE_MODERATOR");
    bytes32 public constant ROLE_ATTESTOR = keccak256("eyeupOHA.ROLE_ATTESTOR");
    bytes32 public constant ROLE_CURATOR = keccak256("eyeupOHA.ROLE_CURATOR");

    mapping(bytes32 => mapping(address => bool)) private _hasRole;

    modifier onlyRole(bytes32 role) {
        if (!_hasRole[role][msg.sender]) revert EYU__NotRole(role);
        _;
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _hasRole[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        if (account == address(0)) revert EYU__BadInput();
        if (_hasRole[role][account]) revert EYU__AlreadyExists();
        _hasRole[role][account] = true;
        emit EYU_RoleGranted(role, account, msg.sender);
    }

    function revokeRole(bytes32 role, address account) external onlyOwner {
        if (!_hasRole[role][account]) revert EYU__NotFound();
        _hasRole[role][account] = false;
        emit EYU_RoleRevoked(role, account, msg.sender);
    }

    // =============================================================
    // User state + moderation
    // =============================================================
    enum ModerationFlag {
        None,
        ShadowBanned,
        Muted, // user may read but cannot post (app semantics)
        Suspended
    }

    struct ModerationState {
        ModerationFlag flag;
        uint64 untilTs;
        uint32 code;
    }

    mapping(address => ModerationState) public moderationOf;

    function _isRestricted(address u) internal view returns (bool) {
        ModerationState memory m = moderationOf[u];
        if (m.flag == ModerationFlag.None) return false;
        if (m.untilTs == 0) return true;
        return block.timestamp < m.untilTs;
    }

    function setModeration(address user, uint8 action, uint32 code, uint64 untilTs) external onlyRole(ROLE_MODERATOR) {
        if (user == address(0)) revert EYU__BadInput();
        if (action > uint8(ModerationFlag.Suspended)) revert EYU__BadInput();
        moderationOf[user] = ModerationState({flag: ModerationFlag(action), untilTs: untilTs, code: code});
        emit EYU_Moderation(msg.sender, user, action, code, untilTs, uint64(block.timestamp));
    }

    // =============================================================
    // Profile model
    // =============================================================
    struct Profile {
        bytes32 handleHash;     // keccak256(normalized handle)
        bytes32 bioHash;        // keccak256(bio text) OR keccak256(CID bytes)
        bytes32 avatarHash;     // keccak256(avatar blob) OR keccak256(CID bytes)
        bytes32 extrasHash;     // keccak256(json) or other structured data hash
        uint64 createdAt;
        uint64 updatedAt;
        uint16 age;             // optional; 0 means unset
        uint16 countryCode;     // ISO numeric or project-specific (0 unset)
        uint32 prefsBits;       // app-defined preferences bitset
    }

    mapping(address => Profile) private _profileOf;
    mapping(bytes32 => address) public ownerOfHandleHash;

    // Tags: stored as bytes32 hashes; UI can map to human-readable strings off-chain.
    mapping(address => bytes32[]) private _tagsOf;

    // =============================================================
    // Social edges
    // =============================================================
    mapping(address => mapping(address => bool)) public blocked;
    mapping(address => mapping(address => bool)) public liked;
    mapping(address => mapping(address => bool)) public matched;

    // match threads (deterministic, symmetric)
    mapping(bytes32 => uint40) public threadSeq;
    mapping(bytes32 => mapping(uint32 => bytes32)) public threadMeta; // key => value (hash pointers)

    // =============================================================
    // Rate limit (per-account leaky-ish bucket)
    // =============================================================
    struct Rate {
        uint64 lastTs;
        uint32 debt;
    }
    mapping(address => Rate) private _rate;

    uint32 private constant _RATE_QUANTA = 18;   // per minute budget (approx)
    uint32 private constant _RATE_BURST = 42;

    function _tickRate(address u, uint32 cost) internal {
