SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


interface IIssuerRegistry {
    function isAuthorized(address issuer) external view returns (bool);
    function issuerKeyId(address issuer) external view returns (bytes32);
}


contract CredentialRegistry {
    // --- Tipuri & evenimente ---
    struct Credential {
        address issuer;
        address subject;
        bytes32 schemaId;
        bytes32 dataHash;     // ancora VC off-chain
        uint256 issuedAt;
        uint256 expiresAt;    // 0 => fara expirare
        bool    revoked;
    }

    enum RevokeReason { Unspecified, KeyCompromise, PolicyBreach, SubjectRequest }

    event CredentialIssued(
        uint256 indexed id,
        address indexed issuer,
        address indexed subject,
        bytes32 schemaId,
        bytes32 dataHash
    );

    event CredentialRevoked(uint256 indexed id, uint16 reasonCode);

    event PresentationVerified(uint256 indexed id, address indexed verifier, uint256 timestamp);

    error NotAuthorized();        // emitent neautorizat
    error InvalidExpiry();        // expiresAt <= block.timestamp (cand != 0)
    error NotIssuer();            // msg.sender != issuer al credentialului
    error AlreadyRevoked();       // deja revocat
    error InvalidSignature();     // semnatura VP invalida
    error ReplayDetected();       // prezentare repetata (anti-replay)
    error InvalidId();            // credential inexistent

    
    IIssuerRegistry public immutable issuerRegistry;

    mapping(uint256 => Credential) private _credentials;
    uint256 public nextId; // auto-increment

    
    mapping(bytes32 => bool) public usedPresentations;

    constructor(address issuerRegistryAddress) {
        require(issuerRegistryAddress != address(0), "ZeroIssuerRegistry");
        issuerRegistry = IIssuerRegistry(issuerRegistryAddress);
        nextId = 0;
    }

    

    
    function issueCredential(
        address subject,
        bytes32 schemaId,
        bytes32 dataHash,
        uint256 expiresAt
    ) external returns (uint256 id)
    {
        if (!issuerRegistry.isAuthorized(msg.sender)) revert NotAuthorized();
        if (expiresAt != 0 && expiresAt <= block.timestamp) revert InvalidExpiry();
        require(subject != address(0), "ZeroSubject");
        require(dataHash != bytes32(0), "ZeroHash");
        // note: schemaId poate fi 0x0 daca se doreste; recomandat sa fie != 0

        unchecked { id = ++nextId; }
        _credentials[id] = Credential({
            issuer: msg.sender,
            subject: subject,
            schemaId: schemaId,
            dataHash: dataHash,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            revoked: false
        });

        emit CredentialIssued(id, msg.sender, subject, schemaId, dataHash);
    }

    function revokeCredential(
        uint256 credentialId,
        uint16 reasonCode
    ) external {
        Credential storage c = _credentials[credentialId];
        if (c.issuer == address(0)) revert InvalidId();
        if (msg.sender != c.issuer) revert NotIssuer();
        if (c.revoked) revert AlreadyRevoked();

        c.revoked = true;
        emit CredentialRevoked(credentialId, reasonCode);
    }

    function getCredential(
        uint256 credentialId
    ) external view returns (
        address issuer,
        address subject,
        bytes32 schemaId,
        bytes32 dataHash,
        uint256 issuedAt,
        uint256 expiresAt,
        bool revoked
    ) {
        Credential storage c = _credentials[credentialId];
        if (c.issuer == address(0)) revert InvalidId();
        return (c.issuer, c.subject, c.schemaId, c.dataHash, c.issuedAt, c.expiresAt, c.revoked);
    }

    function verifyPresentation(
        uint256 credentialId,
        bytes32 presentationHash,
        bytes calldata signature
    ) external {
        Credential storage c = _credentials[credentialId];
        if (c.issuer == address(0)) revert InvalidId();

        // status curent: nerevocat si (neexpirat sau fara expirare)
        if (c.revoked) revert AlreadyRevoked();
        if (c.expiresAt != 0 && c.expiresAt <= block.timestamp) revert InvalidExpiry();

        // anti-replay (optional, dar activat aici)
        if (usedPresentations[presentationHash]) revert ReplayDetected();
        usedPresentations[presentationHash] = true;

        // verificare semnatura holder (subject) peste presentationHash (EIP-191 prefix)
        address signer = _recoverEthSigned(presentationHash, signature);
        if (signer != c.subject) revert InvalidSignature();

        emit PresentationVerified(credentialId, msg.sender, block.timestamp);
    }




    function isActive(uint256 credentialId) external view returns (bool) {
        Credential storage c = _credentials[credentialId];
        if (c.issuer == address(0)) return false;
        if (c.revoked) return false;
        if (c.expiresAt != 0 && c.expiresAt <= block.timestamp) return false;
        return true;
    }

    function _recoverEthSigned(bytes32 messageHash, bytes calldata signature) internal pure returns (address) {
        
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
       
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();


        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address signer = ecrecover(ethSigned, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }
}