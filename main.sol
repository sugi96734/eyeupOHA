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
