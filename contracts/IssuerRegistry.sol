SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IssuerRegistry {
    
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "OwnerOnly");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZeroAddr");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }


    mapping(address => bool) private _authorizedIssuer;
    mapping(address => bytes32) private _issuerKeyId; // optional: identificator de cheie publica

    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event KeyRotated(address indexed issuer, bytes32 newKeyId);

    function addIssuer(address issuer, bytes32 initialKeyId) external onlyOwner {
        require(issuer != address(0), "ZeroAddr");
        require(!_authorizedIssuer[issuer], "AlreadyAuthorized");
        _authorizedIssuer[issuer] = true;
        _issuerKeyId[issuer] = initialKeyId;
        emit IssuerAdded(issuer);
        if (initialKeyId != bytes32(0)) emit KeyRotated(issuer, initialKeyId);
    }

    function removeIssuer(address issuer) external onlyOwner {
        require(_authorizedIssuer[issuer], "NotAuthorized");
        _authorizedIssuer[issuer] = false;
        emit IssuerRemoved(issuer);
    }

    function rotateKey(address issuer, bytes32 newKeyId) external onlyOwner {
        require(_authorizedIssuer[issuer], "NotAuthorized");
        _issuerKeyId[issuer] = newKeyId;
        emit KeyRotated(issuer, newKeyId);
    }

    
    function isAuthorized(address issuer) external view returns (bool) {
        return _authorizedIssuer[issuer];
    }

    function issuerKeyId(address issuer) external view returns (bytes32) {
        return _issuerKeyId[issuer];
    }
}