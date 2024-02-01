// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(unused_function)]
module tests::treasury_tests {
    use sui::tx_context::{Self, TxContext};
    use sui::test_utils;
    use sui::deny_list;
    use sui::coin;

    use tests::otw::{Self, OTW}; // creates currency

    use controlled_treasury::treasury::{
        Self,
        AdminCap,
        DenyMutCap,
        MintCap,
        WhitelistCap,
    };

    /// For tests that are not implemented yet.
    const ENotImplemented: u64 = 1337;
    /// For tests that are expected to fail to not deal with unused values.
    const EExpectedFailure: u64 = 1338;

    // === Generic Behavior + Admin Features ===

    #[test]
    // Test that we can create a new treasury and destroy it.
    fun test_pack_unpack() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);

        let treasury = treasury::new(treasury_cap, denycap, @admin, ctx);
        let (treasury_cap, denycap, bag) = treasury.deconstruct(ctx);

        test_utils::destroy(treasury_cap);
        test_utils::destroy(denycap);
        test_utils::destroy(bag);
    }

    #[test]
    // Scenario: admin adds whitelist, mint and denycap abilities
    fun test_assign_multiple_roles() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        // check that admin capability is there and assign others
        assert!(treasury.has_cap<OTW, AdminCap>(@admin), 0);

        treasury.add_capability(@admin, treasury::new_mint_cap(1000, ctx), ctx);
        treasury.add_capability(@admin, treasury::new_deny_mut_cap(), ctx);
        treasury.add_capability(@admin, treasury::new_whitelist_cap(), ctx);

        // check that newly added capabilities are there
        assert!(treasury.has_cap<OTW, MintCap>(@admin), 1);
        assert!(treasury.has_cap<OTW, DenyMutCap>(@admin), 2);
        assert!(treasury.has_cap<OTW, WhitelistCap>(@admin), 3);

        // remove all of them
        treasury.remove_capability<OTW, MintCap>(@admin, ctx);
        treasury.remove_capability<OTW, DenyMutCap>(@admin, ctx);
        treasury.remove_capability<OTW, WhitelistCap>(@admin, ctx);

        // make sure they're removed
        assert!(!treasury.has_cap<OTW, MintCap>(@admin), 4);
        assert!(!treasury.has_cap<OTW, DenyMutCap>(@admin), 5);
        assert!(!treasury.has_cap<OTW, WhitelistCap>(@admin), 6);

        // gracefully share object
        treasury.share()
    }

    #[test, expected_failure(abort_code = treasury::EAdminsCantBeZero)]
    // Scenario:
    // 1. Admin adds a new admin
    // 2. Second admin removes first and tries to remove themselves
    fun test_remove_self() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.add_capability(@user, treasury::new_admin_cap(), ctx);

        let ctx = &mut tx(@user, 1); // 2nd tx by user

        treasury.remove_capability<OTW, AdminCap>(@admin, ctx);
        treasury.remove_capability<OTW, AdminCap>(@user, ctx);

        abort EExpectedFailure
    }

    // === Denylist ===

    #[test]
    // Scenario:
    // 1. admin assigns a denylist role to `dl_admin`
    // 2. `dl_admin` adds `user` to the denylist
    // 3. `dl_admin` removes `user` from the denylist
    fun test_denylist_add_remove() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.add_capability(@dl_admin, treasury::new_deny_mut_cap(), ctx);

        let ctx = &mut tx(@dl_admin, 1); // 2nd tx by dl_admin
        let mut deny_list = deny_list::new_for_testing(ctx);

        treasury.add_deny_address(&mut deny_list, @user, ctx);
        treasury.remove_deny_address(&mut deny_list, @user, ctx);

        test_utils::destroy(deny_list);
        test_utils::destroy(treasury);
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: admin tries to add a record to denylist without a denylist cap
    fun add_denylist_entry_no_cap_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);
        let mut deny_list = deny_list::new_for_testing(ctx);

        treasury.add_deny_address(&mut deny_list, @user, ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: admin tries to add a record to denylist without a denylist cap
    fun remove_denylist_entry_no_cap_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);
        let mut deny_list = deny_list::new_for_testing(ctx);

        treasury.remove_deny_address(&mut deny_list, @user, ctx);

        abort EExpectedFailure
    }

    // === Whitelist & Mint/Burn ===

    #[test]
    // Scenario:
    // 1. admin assigns a whitelist role to `wl_admin` and a mint role to `mint_admin`
    // 3. `wl_admin` adds `user` to the whitelist
    // 4. `mint_admin` mints 1000 tokens to `user`
    // 5. `user` burns 1000 tokens
    fun test_whitelist_mint() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.add_capability(@wl_admin, treasury::new_whitelist_cap(), ctx);
        treasury.add_capability(@mint_admin, treasury::new_mint_cap(1000, ctx), ctx);

        let ctx = &mut tx(@wl_admin, 1); // 2nd tx by wl_admin
        treasury.add_whitelist_entry(@user, ctx);

        let ctx = &mut tx(@mint_admin, 2); // 3rd tx by mint_admin
        treasury.mint_and_transfer(1000, @user, ctx);

        let ctx = &mut tx(@user, 3); // 4th tx by user
        treasury.burn(coin::mint_for_testing<OTW>(1000, ctx), ctx);

        test_utils::destroy(treasury);
    }

    #[test, expected_failure(abort_code = treasury::ENoWhitelistRecord)]
    // Scenario:
    // 1. admin assigns a mint role to `mint_admin`
    // 2. `mint_admin` mints 1000 tokens to `user` - failure
    fun try_mint_to_non_whitelisted_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.add_capability(@mint_admin, treasury::new_mint_cap(1000, ctx), ctx);

        let ctx = &mut tx(@mint_admin, 1); // 2nd tx by mint_admin
        treasury.mint_and_transfer(1000, @user, ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: admin tries a whitelist operation without a whitelist cap
    fun add_whitelist_entry_no_wl_cap_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.add_whitelist_entry(@user, ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: admin tries to remove a whitelist entry without a whitelist cap
    fun remove_whitelist_entry_no_wl_cap_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.remove_whitelist_entry(@user, ctx);

        abort EExpectedFailure
    }

    // === Authorization Failures ===

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: not an admin tries to add a whitelist cap to treasury
    fun test_add_capability_not_admin_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        let ctx = &mut tx(@user, 1); // 2nd tx by user
        treasury.add_capability(@user, treasury::new_whitelist_cap(), ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: user tries to remove admin cap from admin
    fun remove_capability_not_admin_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        let ctx = &mut tx(@user, 1); // 2nd tx by user
        treasury.remove_capability<OTW, AdminCap>(@admin, ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: admin tries a mint operation without a mint cap
    fun mint_no_mint_cap_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.mint_and_transfer(1000, @user, ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure(abort_code = treasury::ENoAuthRecord)]
    // Scenario: admin tries a burn operation without a whitelist entry
    fun burn_no_mint_cap_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @admin, ctx);

        treasury.burn(coin::mint_for_testing<OTW>(1000, ctx), ctx);

        abort EExpectedFailure
    }

    #[test, expected_failure]
    // TODO: make this test work.
    fun test_remove_self_fail() {
        let ctx = &mut tx(@admin, 0);
        let (treasury_cap, denycap) = otw::create_currency(ctx);
        let mut treasury = treasury::new(treasury_cap, denycap, @0x0, ctx);

        treasury.remove_capability<OTW, AdminCap>(@0x0, ctx);
        test_utils::destroy(treasury);

        abort ENotImplemented
    }

    // === Test Helpers ===

    /// Create a new `TxContext` to create objects and read sender.
    ///
    /// Refer to this example for how to use the `dummy` context:
    /// https://examples.sui.io/testing/dummy-context.html
    fun tx(sender: address, hint: u64): TxContext {
        tx_context::new_from_hint(sender, hint, 1, 0, 0)
    }

    /// Create a dummy context for a TX with a given epoch.
    ///
    /// Refer to this example for how to use the `dummy` context:
    /// https://examples.sui.io/testing/dummy-context.html
    fun tx_with_epoch(sender: address, hint: u64, epoch: u64): TxContext {
        tx_context::new_from_hint(sender, hint, epoch, 0, 0)
    }
}
