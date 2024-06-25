// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A smart contract to manage the treasury and associated caps of a controlled coin.
/// Features:
/// - An admin can set permissions for different operations, and delete permissions, with effcient (immediate) revocation
/// - All addresses holding permissions can be multi-sigs.
///
// Architecture notes:
/// - The treasury contract is a public object that can be shared with others.
/// - The treasury contract has a bag of capabilities that can be added and removed by the admin.
module controlled_treasury::treasury {
    use std::type_name;
    use sui::coin::{DenyCap, TreasuryCap};
    use sui::bag::{Bag, Self};

    /// Trying to remove the last admin.
    const EAdminsCantBeZero: u64 = 0;
    /// The Authorization record does not exist.
    const ENoAuthRecord: u64 = 1;
    /// The record already exists.
    const ERecordExists: u64 = 2;
    const ERemoveAuthFirst: u64 = 3;

    // A structure that wrapps the treasury cap of a coin and adds capabilities to so
    // that operations are controlled by a more granular and flexible policy. Can wrap
    // the capavilities after calling the constructor of a controlled coin.
    // Note: Upgrade cap can also be added to allow for upgrades
    public struct ControlledTreasury<phantom T> has key {
        id: UID,
        /// Number of currently active admins.
        /// Can't ever be zero, as the treasury would be locked.
        admin_count: u8,
        /// The treasury cap of the Coin.
        treasury_cap: TreasuryCap<T>,
        deny_cap: DenyCap<T>,
        own_capabilities: Bag,
    }

    /// An administrator capability that may manage permissions
    public struct AdminCap<phantom T> has key {
        id: UID,
    }
    
    /// An authorization witness for the admin capability
    public struct AdminAuth<phantom T> has store, drop {}

    // === DF Keys ===

    /// Namespace for dynamic fields: one for each of the Cap's.
    public struct RoleKey<phantom W: store + drop> has copy, store, drop { id: ID }

    // Note all "address" can represent multi-signature addresses and be authorized at any threshold

    // === Capabilities ===

    /// Create a new controlled treasury by wrapping the treasury cap of a coin
    /// The `ControlledTreasury` becomes a public shared object with an initial Admin capability is returned.
    ///
    /// The `ControlledTreasury` has to be `share`d after the creation.
    public fun new<T>(
        treasury_cap: TreasuryCap<T>,
        deny_cap: DenyCap<T>,
        ctx: &mut TxContext
    ): (ControlledTreasury<T>, AdminCap<T>) {
        let mut treasury = ControlledTreasury {
            id: object::new(ctx),
            treasury_cap,
            deny_cap,
            admin_count: 1,
            own_capabilities: bag::new(ctx),
        };
        let admin_cap = AdminCap { id: object::new(ctx) };
        add_auth(&mut treasury, &admin_cap, AdminAuth<T> {});
        (treasury, admin_cap)
    }

    #[lint_allow(share_owned)]
    /// Make ControlledTreasury a shared object.
    public fun share<T>(treasury: ControlledTreasury<T>) {
        transfer::share_object(treasury);
    }

    /// Unpack the `ControlledTreasury` and return the treasury cap, deny cap
    /// and the Bag. The Bag must be cleared by the admin to be unpacked
    public fun deconstruct<T>(
        admin_cap: &AdminCap<T>,
        treasury: ControlledTreasury<T>,
    ): (TreasuryCap<T>, DenyCap<T>, Bag) {
        assert!(has_auth<T, AdminAuth<T>>(&treasury, object::id(admin_cap)), ENoAuthRecord);
        // Deconstruct the structure and return the parts
        let ControlledTreasury {
            id,
            admin_count: _,
            treasury_cap,
            deny_cap,
            own_capabilities
        } = treasury;
        object::delete(id);

        (treasury_cap, deny_cap, own_capabilities)
    }

    // === General Role (Cap) assignment ===

    /// Allow the admin to add capabilities to the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    ///
    /// Aborts if:
    /// - the sender does not have AdminAuth
    /// - the receiver already has a `C` cap
    public fun add_authorization<T, C: key, W: store + drop>(
        admin_cap: &AdminCap<T>,
        treasury: &mut ControlledTreasury<T>,
        new_cap: &C,
        auth_witness: W
    ) {
        assert!(has_auth<T, AdminAuth<T>>(treasury, object::id(admin_cap)), ENoAuthRecord);
        assert!(!has_auth<T, W>(treasury, object::id(new_cap)), ERecordExists);
        // using a reflection trick to update admin count when adding a new admin
        if (type_name::get<W>() == type_name::get<AdminAuth<T>>()) {
            treasury.admin_count = treasury.admin_count + 1;
        };

        add_auth(treasury, new_cap, auth_witness);
    }

    /// Allow the admin to remove capabilities from the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    ///
    /// Aborts if:
    /// - the sender does not have `AdminAuth`
    /// - the receiver does not have `C` cap
    public fun remove_authorization<T, W: store + drop>(
        admin_cap: &AdminCap<T>,
        treasury: &mut ControlledTreasury<T>,
        cap_id: ID
    ) {
        assert!(has_auth<T, AdminAuth<T>>(treasury, object::id(admin_cap)), ENoAuthRecord);
        assert!(has_auth<T, W>(treasury, cap_id), ENoAuthRecord);

        // using a reflection trick to update admin count when removing an admin
        // make sure there's at least one admin always
        if (type_name::get<W>() == type_name::get<AdminAuth<T>>()) {
            assert!(treasury.admin_count > 1, EAdminsCantBeZero);
            treasury.admin_count = treasury.admin_count - 1;
        };

        remove_auth<T, W>(treasury, cap_id);
    }

    public use fun delete_admin_cap as AdminCap.delete;
    public fun delete_admin_cap<T>(
        admin_cap: AdminCap<T>,
        treasury: &ControlledTreasury<T>
    ) {
        assert!(!has_auth<T, AdminAuth<T>>(treasury, object::id(&admin_cap)), ERemoveAuthFirst);
        let AdminCap<T> { id } = admin_cap;
        id.delete();
    }

    // === Utilities ===

    /// Check if a capability `Cap` is assigned to the `owner`. Publicly available for tests
    /// and interoperability with other packages / modules.
    public fun has_auth<T, W: store + drop>(treasury: &ControlledTreasury<T>, id: ID): bool {
        bag::contains_with_type<RoleKey<W>, W>(&treasury.own_capabilities, RoleKey<W> { id })
    }

    // === Private Utilities ===

    /// Adds a capability `cap` for `owner`.
    fun add_auth<T, C: key, W: store + drop>(treasury: &mut ControlledTreasury<T>, cap: &C, auth: W) {
        bag::add(&mut treasury.own_capabilities, RoleKey<W> { id: object::id(cap) }, auth);
    }

    /// Remove a `Cap` from the `owner`.
    fun remove_auth<T, W: store + drop>(treasury: &mut ControlledTreasury<T>, id: ID) {
        bag::remove<RoleKey<W>, W>(&mut treasury.own_capabilities, RoleKey<W> { id });
    }

    public fun borrow_treasury_cap<T, C: key, W: store + drop>(self: &ControlledTreasury<T>, cap: &C, _: W): &TreasuryCap<T> {
        assert!(has_auth<T, W>(self, object::id(cap)), ENoAuthRecord);
        &self.treasury_cap
    }

    public fun borrow_treasury_cap_mut<T, C: key, W: store + drop>(self: &mut ControlledTreasury<T>, cap: &C, _: W): &mut TreasuryCap<T> {
        assert!(has_auth<T, W>(self, object::id(cap)), ENoAuthRecord);
        &mut self.treasury_cap
    }

    public fun borrow_deny_cap<T, C: key, W: store + drop>(self: &ControlledTreasury<T>, cap: &C, _: W): &DenyCap<T> {
        assert!(has_auth<T, W>(self, object::id(cap)), ENoAuthRecord);
        &self.deny_cap
    }

    public fun borrow_deny_cap_mut<T, C: key, W: store + drop>(self: &mut ControlledTreasury<T>, cap: &C, _: W): &mut DenyCap<T> {
        assert!(has_auth<T, W>(self, object::id(cap)), ENoAuthRecord);
        &mut self.deny_cap
    }
}
