// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title EncryptedPlayerRegistry
 * @notice Simple player registry for Zama FHEVM:
 *         - Each player registers with a public name (string) and an encrypted age (euint8).
 *         - Age is always stored and processed as ciphertext.
 *         - Uses only official Zama FHE library & SepoliaConfig.
 */

import { FHE, euint8, externalEuint8 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract EncryptedPlayerRegistry is ZamaEthereumConfig {
    /* ---------------------------- Version & Events ---------------------------- */

    function version() external pure returns (string memory) {
        return "EncryptedPlayerRegistry/1.0.0";
    }

    /// @notice Emitted when a player registers or updates profile.
    /// @param player     Player address.
    /// @param name       Plaintext name stored on-chain.
    /// @param ageHandle  Handle of encrypted age (euint8 -> bytes32).
    event PlayerRegistered(
        address indexed player,
        string name,
        bytes32 ageHandle
    );

    /// @notice Emitted when a player chooses to make their age publicly decryptable.
    event PlayerAgeMadePublic(
        address indexed player,
        bytes32 ageHandle
    );

    /// @notice Emitted when a player profile is logically cleared.
    event PlayerCleared(address indexed player);

    /* -------------------------------- Ownable -------------------------------- */

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero owner");
        owner = newOwner;
    }

    /* ----------------------------- Player storage ---------------------------- */

    struct Player {
        bool exists;
        string name;
        euint8 age;
    }

    mapping(address => Player) private _players;

    /* ------------------------------- View helpers ---------------------------- */

    function isRegistered(address player) external view returns (bool) {
        return _players[player].exists;
    }

    function getPlayer(
        address player
    )
        external
        view
        returns (
            bool exists,
            string memory name,
            bytes32 ageHandle
        )
    {
        Player storage p = _players[player];

        if (!p.exists) {
            return (false, "", bytes32(0));
        }

        return (true, p.name, FHE.toBytes32(p.age));
    }

    function getMyAgeHandle() external view returns (bytes32) {
        Player storage p = _players[msg.sender];
        require(p.exists, "Not registered");
        return FHE.toBytes32(p.age);
    }

    /* ---------------------- Registration & update (encrypted) ---------------- */

    function registerEncrypted(
        string calldata name,
        externalEuint8 ageExt,
        bytes calldata proof
    ) external {
        require(bytes(name).length > 0, "Empty name");
        require(proof.length > 0, "Empty proof");

        euint8 ageCt = FHE.fromExternal(ageExt, proof);

        FHE.allowThis(ageCt);
        FHE.allow(ageCt, msg.sender);

        Player storage p = _players[msg.sender];
        p.exists = true;
        p.name = name;
        p.age = ageCt;

        emit PlayerRegistered(msg.sender, name, FHE.toBytes32(ageCt));
    }

    function registerPlain(
        string calldata name,
        uint8 agePlain
    ) external {
        require(bytes(name).length > 0, "Empty name");

        euint8 ageCt = FHE.asEuint8(agePlain);

        FHE.allowThis(ageCt);
        FHE.allow(ageCt, msg.sender);

        Player storage p = _players[msg.sender];
        p.exists = true;
        p.name = name;
        p.age = ageCt;

        emit PlayerRegistered(msg.sender, name, FHE.toBytes32(ageCt));
    }

    function updateName(string calldata newName) external {
        require(bytes(newName).length > 0, "Empty name");

        Player storage p = _players[msg.sender];
        require(p.exists, "Not registered");

        p.name = newName;

        emit PlayerRegistered(
            msg.sender,
            newName,
            FHE.toBytes32(p.age)
        );
    }

    function updateAgeEncrypted(
        externalEuint8 newAgeExt,
        bytes calldata proof
    ) external {
        require(proof.length > 0, "Empty proof");

        Player storage p = _players[msg.sender];
        require(p.exists, "Not registered");

        euint8 newAgeCt = FHE.fromExternal(newAgeExt, proof);

        FHE.allowThis(newAgeCt);
        FHE.allow(newAgeCt, msg.sender);

        p.age = newAgeCt;

        emit PlayerRegistered(
            msg.sender,
            p.name,
            FHE.toBytes32(newAgeCt)
        );
    }

    /* ----------------------------- Public age control ------------------------ */

    function makeMyAgePublic() external {
        Player storage p = _players[msg.sender];
        require(p.exists, "Not registered");

        FHE.makePubliclyDecryptable(p.age);

        emit PlayerAgeMadePublic(
            msg.sender,
            FHE.toBytes32(p.age)
        );
    }

    function makePlayerAgePublic(address player) external onlyOwner {
        Player storage p = _players[player];
        require(p.exists, "Not registered");

        FHE.makePubliclyDecryptable(p.age);

        emit PlayerAgeMadePublic(
            player,
            FHE.toBytes32(p.age)
        );
    }

    /* ------------------------------- Admin helpers --------------------------- */

    function clearPlayer(address player) external onlyOwner {
        Player storage p = _players[player];
        require(p.exists, "Not registered");

        p.exists = false;
        p.name = "";

        euint8 zeroAge = FHE.asEuint8(0);
        FHE.allowThis(zeroAge);
        p.age = zeroAge;

        emit PlayerCleared(player);
    }
}
