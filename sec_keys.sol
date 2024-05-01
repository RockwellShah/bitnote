// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8;

import "./authed_contract.sol";

contract sec_keys is authed_contract {
    mapping(bytes32 => bytes) private index_space;
    mapping(bytes32 => string) private name_space;

    constructor(address init_auth_contract) authed_contract(init_auth_contract){}

    function setDataAtIndex(bytes32 index, bytes calldata new_bytes, string calldata username) external requireOwnership(index) {
        index_space[index] = new_bytes;
        name_space[index] = username;
    }

    function getDataAtIndex(bytes32 index) external view returns (bytes memory, string memory){
        return (index_space[index], name_space[index]);
    }
}
