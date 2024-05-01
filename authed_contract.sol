// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8;

interface OwnedContract {
    function auth_addr() external view returns (address);
}

contract authed_contract{
    OwnedContract private contract_owner;

    constructor(address init_contract_owner){
        contract_owner = OwnedContract(init_contract_owner);
    }

    receive() external payable {}

    modifier confirmValue(){
        require(msg.value >= ((((gasleft()*(tx.gasprice/1e9))*1e9)/100) * taxRate()));
        _;
    }

    modifier authCall(){
        require(msg.sender == address(contract_owner) || msg.sender == contract_owner.auth_addr());
        _;
    }

    modifier requireOwnership(bytes32 index){
        require (getAddressLink(index) == msg.sender);
        _;
    }

    function migrateModContract(address new_addr) external authCall {
        contract_owner = OwnedContract(new_addr);
    }

    function authPayout(uint256 amount) external authCall {
        payable(address(contract_owner)).transfer(amount);
    }

    function authPayoutFull() external authCall {
        payable(address(contract_owner)).transfer(address(this).balance);
    }

    function taxRate() internal view returns (uint256) {
        (, bytes memory data) = address(contract_owner).staticcall(abi.encodeWithSignature("tax_rate()"));
        return  abi.decode(data, (uint256));
    }

    function basePrice() internal view returns (uint256) {
        (,bytes memory data) = address(contract_owner).staticcall(abi.encodeWithSignature("base_price()"));
        return  abi.decode(data, (uint256));
    }

    function getAddressLink(bytes32 index) internal view returns (address){
        (, bytes memory data) = address(contract_owner).staticcall(abi.encodeWithSignature("getAddressLink(bytes32)", index));
        return abi.decode(data, (address));
    }

    function getReferrer() internal view returns (address){
        (, bytes memory data) = address(contract_owner).staticcall(abi.encodeWithSignature("getReferrer(address)", msg.sender));
        return abi.decode(data, (address));
    }

    function refPayout() internal confirmValue {
        address ref = getReferrer();
        if(ref != 0x0000000000000000000000000000000000000000)
            payable(ref).transfer(((msg.value / 100)*30));
    }

    function stdPayout() internal confirmValue {
        payable(address(contract_owner)).transfer(msg.value);
    }

    function getContractOwner() external view returns(address){
        return address(contract_owner);
    }
}