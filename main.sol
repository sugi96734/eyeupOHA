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
        if (cost == 0) return;
        Rate memory r = _rate[u];
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs <= r.lastTs) {
            // same-second spam resistance
        } else {
            uint64 dt = nowTs - r.lastTs;
            // recover budget: dt minutes * quanta
            uint32 recover = uint32((dt * _RATE_QUANTA) / 60);
            if (recover > r.debt) r.debt = 0;
            else r.debt = r.debt - recover;
            r.lastTs = nowTs;
        }
        if (r.debt + cost > _RATE_BURST) revert EYU__RateLimited();
        r.debt += cost;
        _rate[u] = r;
    }

    // =============================================================
    // Bot lane: prompts + attested replies (hash pointers only)
    // =============================================================
    struct BotLane {
        uint64 openedAt;
        uint40 prompts;
        uint40 replies;
        bytes32 laneSalt;
    }

    mapping(address => BotLane) public botLaneOf;
    mapping(bytes32 => mapping(uint40 => bytes32)) public botPromptHash; // laneId => n => hash
    mapping(bytes32 => mapping(uint40 => bytes32)) public botReplyHash;  // laneId => n => hash (attested)

    // =============================================================
    // Reports
    // =============================================================
    struct Report {
        address reporter;
        address accused;
        uint32 reason;
        uint64 at;
        bytes32 noteHash;
    }

    uint64 public reportCount;
    mapping(uint64 => Report) public reportById;

    // =============================================================
    // Constructor
    // =============================================================
    constructor() {
        owner = msg.sender;

        ADDRESS_A = 0x4a3B9C2f7D8eE1bA62c4D9aF0E3c1B7d9A4F2c8E;
        ADDRESS_B = 0xB7c2D1eE4A9f3C6d8E0bA1c2D3e4F5a6B7c8D9e0;
        ADDRESS_C = 0x1F2a3B4c5D6e7F8091a2b3C4d5E6f70819A2b3c4;

        // baseline roles: deployer can administrate, plus one attestor & one curator for launch.
        _hasRole[ROLE_MODERATOR][msg.sender] = true;
        _hasRole[ROLE_ATTESTOR][ADDRESS_B] = true;
        _hasRole[ROLE_CURATOR][ADDRESS_C] = true;

        emit EYU_RoleGranted(ROLE_MODERATOR, msg.sender, msg.sender);
        emit EYU_RoleGranted(ROLE_ATTESTOR, ADDRESS_B, msg.sender);
        emit EYU_RoleGranted(ROLE_CURATOR, ADDRESS_C, msg.sender);

        // bind deployment identity (no state write)
        keccak256(abi.encodePacked(_EYU_DOMAIN, _EYU_NOISE, block.chainid, address(this), msg.sender));
    }

    receive() external payable {
        revert EYU__EtherRejected();
    }

    fallback() external payable {
        revert EYU__EtherRejected();
    }

    // =============================================================
    // Admin controls
    // =============================================================
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert EYU__BadInput();
        address old = owner;
        owner = newOwner;
        emit EYU_OwnerTransferred(old, newOwner);
    }

    function setPaused(bool v) external onlyOwner {
        paused = v;
        emit EYU_PauseSet(v);
    }

    // =============================================================
    // Profile operations
    // =============================================================
    function profileOf(address user) external view returns (Profile memory p, bytes32[] memory tags) {
        p = _profileOf[user];
        if (p.createdAt == 0) revert EYU__NoProfile();
        tags = _tagsOf[user];
    }

    function _normalizeHandle(bytes calldata raw) internal pure returns (bytes memory) {
        uint256 n = raw.length;
        if (n < _HANDLE_MIN || n > _HANDLE_MAX) revert EYU__BadInput();
        bytes memory out = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            bytes1 c = raw[i];
            // ASCII only: 0-9, a-z, _, .
            if (c >= 0x41 && c <= 0x5A) {
                c = bytes1(uint8(c) + 32); // lower
            }
            bool ok =
                (c >= 0x61 && c <= 0x7A) ||
                (c >= 0x30 && c <= 0x39) ||
                (c == 0x5F) ||
                (c == 0x2E);
            if (!ok) revert EYU__BadInput();
            out[i] = c;
        }
        // leading/trailing dot not allowed; consecutive dots not allowed
        if (out[0] == 0x2E || out[n - 1] == 0x2E) revert EYU__BadInput();
        for (uint256 j = 1; j < n; j++) {
            if (out[j] == 0x2E && out[j - 1] == 0x2E) revert EYU__BadInput();
        }
        return out;
    }

    function _tagHash(bytes calldata tag) internal pure returns (bytes32) {
        uint256 n = tag.length;
        if (n == 0 || n > _TAGLEN_MAX) revert EYU__BadInput();
        // allow printable ASCII minus slashes; enforce lowercasing
        bytes memory tmp = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            bytes1 c = tag[i];
            if (c >= 0x41 && c <= 0x5A) c = bytes1(uint8(c) + 32);
            if (c < 0x21 || c > 0x7E) revert EYU__BadInput();
            if (c == 0x2F || c == 0x5C) revert EYU__BadInput();
            tmp[i] = c;
        }
        return keccak256(tmp);
    }

    function createProfile(
        bytes calldata handle,
        bytes32 bioHash,
        bytes32 avatarHash,
        bytes32 extrasHash,
        uint16 age,
        uint16 countryCode,
        uint32 prefsBits,
        bytes[] calldata tags
    ) external whenNotPaused {
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();
        if (_profileOf[msg.sender].createdAt != 0) revert EYU__AlreadyExists();
        _tickRate(msg.sender, 3);

        bytes memory norm = _normalizeHandle(handle);
        bytes32 hh = keccak256(norm);
        if (ownerOfHandleHash[hh] != address(0)) revert EYU__HandleTaken();

        if (tags.length > _TAG_COUNT_MAX) revert EYU__TooLarge();

        Profile memory p;
        p.handleHash = hh;
        p.bioHash = bioHash;
        p.avatarHash = avatarHash;
        p.extrasHash = extrasHash;
        p.createdAt = uint64(block.timestamp);
        p.updatedAt = uint64(block.timestamp);
        p.age = age;
        p.countryCode = countryCode;
        p.prefsBits = prefsBits;

        _profileOf[msg.sender] = p;
        ownerOfHandleHash[hh] = msg.sender;

        _setTags(msg.sender, tags);

        emit EYU_ProfileCreated(msg.sender, hh, uint64(block.timestamp));
    }

    function _setTags(address user, bytes[] calldata tags) internal {
        bytes32[] storage arr = _tagsOf[user];
        while (arr.length != 0) arr.pop();
        for (uint256 i = 0; i < tags.length; i++) {
            bytes32 th = _tagHash(tags[i]);
            // de-dupe within this update
            for (uint256 j = 0; j < i; j++) {
                if (arr[j] == th) revert EYU__BadInput();
            }
            arr.push(th);
        }
    }

    function updateProfile(
        uint32 fieldsMask,
        bytes32 bioHash,
        bytes32 avatarHash,
        bytes32 extrasHash,
        uint16 age,
        uint16 countryCode,
        uint32 prefsBits,
        bytes[] calldata tags
    ) external whenNotPaused {
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();
        Profile storage p = _profileOf[msg.sender];
        if (p.createdAt == 0) revert EYU__NoProfile();
        _tickRate(msg.sender, 2);

        // bit meanings (UI-defined):
        // 1 bio, 2 avatar, 4 extras, 8 age, 16 country, 32 prefs, 64 tags
        if ((fieldsMask & 1) != 0) p.bioHash = bioHash;
        if ((fieldsMask & 2) != 0) p.avatarHash = avatarHash;
        if ((fieldsMask & 4) != 0) p.extrasHash = extrasHash;
        if ((fieldsMask & 8) != 0) p.age = age;
        if ((fieldsMask & 16) != 0) p.countryCode = countryCode;
        if ((fieldsMask & 32) != 0) p.prefsBits = prefsBits;
        if ((fieldsMask & 64) != 0) {
            if (tags.length > _TAG_COUNT_MAX) revert EYU__TooLarge();
            _setTags(msg.sender, tags);
        }

        p.updatedAt = uint64(block.timestamp);
        emit EYU_ProfileUpdated(msg.sender, fieldsMask, uint64(block.timestamp));
    }

    function changeHandle(bytes calldata newHandle) external whenNotPaused {
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();
        Profile storage p = _profileOf[msg.sender];
        if (p.createdAt == 0) revert EYU__NoProfile();
        _tickRate(msg.sender, 2);

        bytes memory norm = _normalizeHandle(newHandle);
        bytes32 hh = keccak256(norm);
        if (hh == p.handleHash) revert EYU__BadInput();
        address taken = ownerOfHandleHash[hh];
        if (taken != address(0)) revert EYU__HandleTaken();

        bytes32 old = p.handleHash;
        ownerOfHandleHash[old] = address(0);
        ownerOfHandleHash[hh] = msg.sender;
        p.handleHash = hh;
        p.updatedAt = uint64(block.timestamp);

        emit EYU_HandleChanged(msg.sender, old, hh, uint64(block.timestamp));
    }

    // =============================================================
    // Blocking & liking
    // =============================================================
    function setBlocked(address target, bool v) external whenNotPaused {
        if (target == address(0) || target == msg.sender) revert EYU__BadInput();
        if (_profileOf[msg.sender].createdAt == 0) revert EYU__NoProfile();
        _tickRate(msg.sender, 1);

        blocked[msg.sender][target] = v;
        if (v) {
            // break any existing match and remove likes in both directions
            if (matched[msg.sender][target]) {
                bytes32 tid = threadIdFor(msg.sender, target);
                matched[msg.sender][target] = false;
                matched[target][msg.sender] = false;
                emit EYU_MatchBroken(msg.sender, target, tid, uint64(block.timestamp));
            }
            liked[msg.sender][target] = false;
            liked[target][msg.sender] = false;
        }
        emit EYU_BlockSet(msg.sender, target, v, uint64(block.timestamp));
    }

    function setLike(address target, bool v) external whenNotPaused {
        if (target == address(0) || target == msg.sender) revert EYU__BadInput();
        if (_profileOf[msg.sender].createdAt == 0) revert EYU__NoProfile();
        if (_profileOf[target].createdAt == 0) revert EYU__NotFound();
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();

        if (blocked[msg.sender][target] || blocked[target][msg.sender]) revert EYU__Blocked();
        _tickRate(msg.sender, 1);

        liked[msg.sender][target] = v;
        emit EYU_LikeSet(msg.sender, target, v, uint64(block.timestamp));

        if (v) {
            if (liked[target][msg.sender] && !matched[msg.sender][target]) {
                matched[msg.sender][target] = true;
                matched[target][msg.sender] = true;
                bytes32 tid = threadIdFor(msg.sender, target);
                // initialize seq to 1 to reserve 0 for "no message"
                if (threadSeq[tid] == 0) threadSeq[tid] = 1;
                emit EYU_MatchMade(msg.sender, target, tid, uint64(block.timestamp));
            }
        } else {
            // if unliking, optionally keep match; instead we break match for clarity
            if (matched[msg.sender][target]) {
                bytes32 tid2 = threadIdFor(msg.sender, target);
                matched[msg.sender][target] = false;
                matched[target][msg.sender] = false;
                emit EYU_MatchBroken(msg.sender, target, tid2, uint64(block.timestamp));
            }
        }
    }

    // =============================================================
    // Deterministic thread id and helpers
    // =============================================================
    function threadIdFor(address a, address b) public view returns (bytes32) {
        if (a == b || a == address(0) || b == address(0)) revert EYU__BadInput();
        (address x, address y) = a < b ? (a, b) : (b, a);
        return keccak256(abi.encodePacked(_EYU_DOMAIN, _EYU_NOISE, block.chainid, address(this), x, y));
    }

    function canChat(address a, address b) public view returns (bool) {
        if (blocked[a][b] || blocked[b][a]) return false;
        if (!matched[a][b]) return false;
        if (_profileOf[a].createdAt == 0 || _profileOf[b].createdAt == 0) return false;
        if (_isRestricted(a) || _isRestricted(b)) return false;
        return true;
    }

    // =============================================================
    // Chat messages (hash pointers only)
    // =============================================================
    function sendThreadMessage(address other, bytes32 payloadHash) external whenNotPaused {
        if (payloadHash == bytes32(0)) revert EYU__BadInput();
        if (!canChat(msg.sender, other)) revert EYU__Blocked();
        _tickRate(msg.sender, 1);

        bytes32 tid = threadIdFor(msg.sender, other);
        uint40 seq = threadSeq[tid];
        if (seq == 0) revert EYU__NotFound();
        if (seq == _THREAD_SEQ_MAX) revert EYU__TooLarge();
        threadSeq[tid] = seq + 1;

        emit EYU_ThreadMessage(msg.sender, tid, seq, payloadHash, uint64(block.timestamp));
    }

    function setThreadMeta(address other, uint32 key, bytes32 value) external whenNotPaused {
        if (!matched[msg.sender][other]) revert EYU__NotFound();
        if (blocked[msg.sender][other] || blocked[other][msg.sender]) revert EYU__Blocked();
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();
        _tickRate(msg.sender, 1);

        // key namespace is off-chain; value is a hash pointer.
        bytes32 tid = threadIdFor(msg.sender, other);
        threadMeta[tid][key] = value;
        emit EYU_ThreadMeta(tid, key, value, uint64(block.timestamp));
    }

    // =============================================================
    // Browse helpers (bounded)
    // =============================================================
    function browseScore(address viewer, address candidate) public view returns (uint256) {
        if (viewer == candidate) return 0;
        Profile memory pv = _profileOf[viewer];
        Profile memory pc = _profileOf[candidate];
        if (pv.createdAt == 0 || pc.createdAt == 0) return 0;
        if (blocked[viewer][candidate] || blocked[candidate][viewer]) return 0;
        if (_isRestricted(candidate)) return 0;

        uint256 s = 1;
        // prefer same country
        if (pv.countryCode != 0 && pv.countryCode == pc.countryCode) s += 4;
        // age proximity: within 2 years +3, within 5 years +2, within 10 +1
        if (pv.age != 0 && pc.age != 0) {
            uint256 diff = pv.age > pc.age ? pv.age - pc.age : pc.age - pv.age;
            if (diff <= 2) s += 3;
            else if (diff <= 5) s += 2;
            else if (diff <= 10) s += 1;
        }
        // tag overlap
        bytes32[] storage tv = _tagsOf[viewer];
        bytes32[] storage tc = _tagsOf[candidate];
        uint256 overlap = 0;
        uint256 limV = tv.length;
        uint256 limC = tc.length;
        uint256 maxChecks = limV * limC;
        if (maxChecks > 160) {
            // bound worst-case overlap scan
            if (limV > 10) limV = 10;
            if (limC > 10) limC = 10;
        }
        for (uint256 i = 0; i < limV; i++) {
            for (uint256 j = 0; j < limC; j++) {
                if (tv[i] == tc[j]) {
                    overlap++;
                    break;
                }
            }
        }
        s += overlap * 2;
        // preference bits overlap (simple)
        uint32 andBits = pv.prefsBits & pc.prefsBits;
        if (andBits != 0) {
            s += 1 + (uint256(_popcount32(andBits)) / 6);
        }
        return s;
    }

    function browseCandidates(address viewer, address[] calldata candidates)
        external
        view
        returns (uint256[] memory scores)
    {
        if (candidates.length == 0 || candidates.length > _BROWSE_PAGE_MAX) revert EYU__TooLarge();
        if (_profileOf[viewer].createdAt == 0) revert EYU__NoProfile();
        scores = new uint256[](candidates.length);
        for (uint256 i = 0; i < candidates.length; i++) {
            scores[i] = browseScore(viewer, candidates[i]);
        }
    }

    // =============================================================
    // Bot lane operations
    // =============================================================
    function botLaneId(address user) public view returns (bytes32) {
        BotLane memory lane = botLaneOf[user];
        if (lane.openedAt == 0) return bytes32(0);
        return keccak256(abi.encodePacked(_EYU_DOMAIN, _EYU_NOISE, block.chainid, address(this), user, lane.laneSalt));
    }

    function openBotLane(bytes32 salt) external whenNotPaused {
        if (_profileOf[msg.sender].createdAt == 0) revert EYU__NoProfile();
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();
        if (salt == bytes32(0)) revert EYU__BadInput();
        BotLane storage lane = botLaneOf[msg.sender];
        if (lane.openedAt != 0) revert EYU__AlreadyExists();
        _tickRate(msg.sender, 2);

        lane.openedAt = uint64(block.timestamp);
        lane.prompts = 0;
        lane.replies = 0;
        lane.laneSalt = keccak256(abi.encodePacked(salt, msg.sender, blockhash(block.number - 1)));

        bytes32 lid = botLaneId(msg.sender);
        emit EYU_BotLaneOpened(msg.sender, lid, uint64(block.timestamp));
    }

    function postBotPrompt(bytes32 promptHash) external whenNotPaused {
        if (_profileOf[msg.sender].createdAt == 0) revert EYU__NoProfile();
        if (_isRestricted(msg.sender)) revert EYU__UnsafeOp();
        if (promptHash == bytes32(0)) revert EYU__BadInput();
        _tickRate(msg.sender, 1);

        BotLane storage lane = botLaneOf[msg.sender];
        if (lane.openedAt == 0) revert EYU__NotFound();
        if (lane.prompts >= _BOT_MAX_PER_LANE) revert EYU__TooLarge();

        bytes32 lid = botLaneId(msg.sender);
        uint40 n = lane.prompts;
        botPromptHash[lid][n] = promptHash;
        lane.prompts = n + 1;

        emit EYU_BotPrompt(msg.sender, lid, n, promptHash, uint64(block.timestamp));
    }

    function attestBotReply(address user, uint40 promptIndex, bytes32 replyHash)
        external
        whenNotPaused
        onlyRole(ROLE_ATTESTOR)
    {
        if (user == address(0)) revert EYU__BadInput();
        if (replyHash == bytes32(0)) revert EYU__BadInput();

        BotLane storage lane = botLaneOf[user];
        if (lane.openedAt == 0) revert EYU__NotFound();
        if (promptIndex >= lane.prompts) revert EYU__NotFound();

        bytes32 lid = botLaneId(user);
        // one reply per prompt index; keep simple
        if (botReplyHash[lid][promptIndex] != bytes32(0)) revert EYU__AlreadyExists();

        botReplyHash[lid][promptIndex] = replyHash;
        lane.replies += 1;
        emit EYU_BotReplyAttested(msg.sender, user, lid, promptIndex, replyHash, uint64(block.timestamp));
    }

    // =============================================================
    // Curator tools (bounded list ops)
    // =============================================================
    function curatorSetThreadMeta(bytes32 threadId, uint32 key, bytes32 value)
        external
        whenNotPaused
        onlyRole(ROLE_CURATOR)
    {
        if (threadId == bytes32(0)) revert EYU__BadInput();
        // intended for e.g. "policy hash", "context hash", etc.
