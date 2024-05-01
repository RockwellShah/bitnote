// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8;

contract mod_contract {
    mapping(address => bool) private verified_contracts;
    address public auth_addr;
    uint256 public base_price;
    uint256 public tax_rate;
    mapping(address => bytes) private user_pk;
    mapping(address => bytes) private ecdh_pub;
    mapping(address => bytes) private ecdk_pk;
    mapping(bytes32 => address) private address_links;
    mapping(address => address) private refferal_addr;

    constructor(){
        base_price = 1e18;
        tax_rate = 10;
        auth_addr = msg.sender;
    }

    receive() external payable {}

    modifier requireAuth(){
        require(msg.sender == auth_addr);
        _;
    }

    function migrateInternalAuthAddr(address new_owner) external requireAuth{
        auth_addr = new_owner;
    }

    function setVerifiedContractStatus(address c_addr, bool status) external requireAuth {
        verified_contracts[c_addr] = status;
    }

    function setBasePrice(uint256 new_bp) external requireAuth {
        base_price = new_bp;
    }

    function sendFunds(uint256 amount, address addr) external requireAuth {
        payable(addr).transfer(amount);
    }

    function setTaxRate(uint256 new_rate) external requireAuth {
        tax_rate = new_rate;
    }

    function externalCallAuth(address c_addr, bytes calldata data) external requireAuth {
        require(verified_contracts[c_addr]);
        (bool success, ) = c_addr.call(data);
        require(success);
    }

    function setString(bytes calldata new_string) internal {
        user_pk[msg.sender] = new_string;
    }

    function setReferrer(address ref) internal {
        if(ref != 0x0000000000000000000000000000000000000000)
            refferal_addr[msg.sender] = ref;
    }

    function initAccount(bytes calldata new_string, bytes32 link_hash, string calldata link_str, bytes calldata new_priv, bytes calldata new_pub, address new_ref) external payable {
        setReferrer(new_ref);
        createAddressLink(link_hash, link_str);
        setString(new_string);
        setPair(new_priv, new_pub);
    }

    function setPair(bytes calldata new_priv, bytes calldata new_pub) public {
        ecdk_pk[msg.sender] = new_priv;
        ecdh_pub[msg.sender] = new_pub;
    }

    function createAddressLink(bytes32 link_hash, string memory link_str) public payable {
        require(address_links[link_hash] == 0x0000000000000000000000000000000000000000, "link in use");
        require(link_hash == keccak256(abi.encodePacked(link_str)));

        uint256 str_len = strlen(link_str);
        if(str_len >= 5)
            require(msg.value >= base_price/100);
        else if(str_len == 4)
            require(msg.value >= base_price/10);
        else if(str_len == 3)
            require(msg.value >= base_price);
        else if(str_len == 2)
            require(msg.value >= base_price*10);
        else if(str_len == 1)
            require(msg.value >= base_price*100);

        address_links[link_hash] = msg.sender;

        if(refferal_addr[msg.sender] != 0x0000000000000000000000000000000000000000)
            payable(refferal_addr[msg.sender]).transfer((msg.value / 100)*30);
    }

    function migrateAddressLink(bytes32 link_hash, address new_addr) external payable {
        require(msg.value >= base_price/100);
        require(address_links[link_hash] == msg.sender);
        address_links[link_hash] = new_addr;

        if(refferal_addr[msg.sender] != 0x0000000000000000000000000000000000000000)
            payable(refferal_addr[msg.sender]).transfer((msg.value / 100)*30);
    }

    function getReferrer(address addr) external view returns (address) {
        return refferal_addr[addr];
    }

    function getPrivString(address addr) external view returns (bytes memory){
        return ecdk_pk[addr];
    }

    function getPubString(address addr) external view returns (bytes memory){
        return ecdh_pub[addr];
    }

    function getString(address addr) external view returns (bytes memory){
        return user_pk[addr];
    }

    function getAddressLink(bytes32 addr_link) external view returns (address){
        return address_links[addr_link];
    }

    function isVerifiedContract(address c_addr) external view returns (bool) {
        return verified_contracts[c_addr];
    }

    function strlen(string memory link_str) internal pure returns (uint256) {
        uint256 len;
        uint256 i = 0;
        uint256 bytelength = bytes(link_str).length;

        for (len = 0; i < bytelength; len++) {
            bytes1 b = bytes(link_str)[i];
            if (b < 0x80)
                i += 1;
            else if (b < 0xE0)
                i += 2;
            else if (b < 0xF0)
                i += 3;
            else if (b < 0xF8)
                i += 4;
            else if (b < 0xFC)
                i += 5;
            else 
                i += 6;
        }
        return len;
    }
}
