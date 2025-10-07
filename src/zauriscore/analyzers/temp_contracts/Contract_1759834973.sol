// T.ME/F_U_G_A_Z_I

pragma solidity ^0.8.20;

// SPDX-License-Identifier: UNLICENSED
contract FUGAZI {
    uint    public constant decimals = 18;
    uint    public constant MAX_INT  = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    uint    public totalSupply       = 1e29;

    string  public constant name     = "FUGAZI";
    string  public constant symbol   = "FUGAZI";

    event   Approval(address indexed src, address indexed guy, uint wad);
    event   Transfer(address indexed src, address indexed dst, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != MAX_INT) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }
}