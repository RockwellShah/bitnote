// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8;

import "./authed_contract.sol";

contract better_notes_contract is authed_contract {
    mapping(bytes32 => bytes) private indexed_space;
    mapping(bytes32 => address) private owner_index;
    mapping(address => bytes32[]) private users_index;
    mapping(address => uint256) private last_update;

    mapping(bytes32 => address) private transfer_index;

    constructor(address init_auth_contract) authed_contract(init_auth_contract){}

    modifier payRef(){
        refPayout();
        updateInternal();
        _;
    }

    modifier requireOwner(bytes32 index){
        require(owner_index[index] == msg.sender);
        _;
    }

    function updateInternal() internal {
        last_update[msg.sender] = block.timestamp;
    }

    function setIndexBytes(bytes32 index, bytes calldata data) internal {
        require(indexed_space[index].length == 0 || owner_index[index] == msg.sender);
        indexed_space[index] = data;
        if(owner_index[index] != msg.sender)
            owner_index[index] = msg.sender;
    }

    function clearIndexBytes(bytes32 index) internal {
        indexed_space[index] = "";
        owner_index[index] = 0x0000000000000000000000000000000000000000;
    }

    function deleteUserIndexAtPos(uint256 pos) internal {
        users_index[msg.sender][pos] = users_index[msg.sender][users_index[msg.sender].length - 1];
        users_index[msg.sender].pop();
    }

    function setUserBytes(bytes32 index, bytes calldata data) external payable payRef{
        setIndexBytes(index, data);
        users_index[msg.sender].push(index);
    }

    function setBytes(bytes32 index, bytes calldata data) external payable payRef {
        setIndexBytes(index, data);
    }

    function setBytesMulti(bytes32[] calldata index, bytes[] calldata data) external payable payRef {
        require(index.length == data.length);
        for(uint256 i = 0; i < index.length; i++){
            setIndexBytes(index[i], data[i]);
            users_index[msg.sender].push(index[i]);
        }
    }

    function updateUsersIndexWhereNeeded(bytes32[] calldata new_index) external payable payRef {
        for (uint i = 0; i < new_index.length; i++) {
            if (users_index[msg.sender][i] != new_index[i]) 
                users_index[msg.sender][i] = new_index[i];
        }
    }

    function updateUsersIndex(bytes32[] calldata new_index) external payable payRef {
        users_index[msg.sender] = new_index;
    }

    function clearBytesMulti(bytes32[] calldata indexes) external payable payRef{
         for(uint256 i = 0; i < indexes.length; i++){
            if(owner_index[indexes[i]] == msg.sender)
                clearIndexBytes(indexes[i]);
         }
    }

    function clearAll(uint256 pos, bytes32 index) external payable payRef requireOwner(index) {
        clearIndexBytes(index);
        deleteUserIndexAtPos(pos);
    }

    function appendSingleIndex(bytes32 index) external  {
        users_index[msg.sender].push(index);
    }

    function updateSingleIndex(uint256 index, bytes32 new_index) external {
        users_index[msg.sender][index] = new_index;
    }

    function deleteSingleUserIndex(uint256 pos) external {
        deleteUserIndexAtPos(pos);
    }

    function ownershipTransferInit(bytes32 index, address addr) external {
        require(owner_index[index] == msg.sender);
        transfer_index[index] = addr;
    }

    function ownershipTransferAccept(bytes32 index) external {
        require(transfer_index[index] == msg.sender);
        owner_index[index] = msg.sender;
    }

    function clearOwnership(bytes32 index) external requireOwner(index) {
        owner_index[index] = 0x0000000000000000000000000000000000000000;
    }

    function getDataAtIndexArray(bytes32[] calldata index_array) external view returns (bytes[] memory){
        bytes[] memory ret_string = new bytes[](index_array.length);
        for(uint256 i = 0; i < index_array.length; i++)
            ret_string[i] = indexed_space[index_array[i]];
        return ret_string;
    }

    function getUserIndex(address addr) external view returns (bytes32[] memory){
        return users_index[addr];
    }

    function getUserBytes(address addr) external view returns (bytes[] memory, uint256, bytes32[] memory){
        bytes[] memory ret_string = new bytes[](users_index[addr].length);
        for(uint256 i = 0; i < users_index[addr].length; i++)
            ret_string[i] = indexed_space[users_index[addr][i]];
        return (ret_string, last_update[addr], users_index[addr]);
    }

    function getLastUpdate(address addr) external view returns (uint256) {
        return last_update[addr];
    }
}
