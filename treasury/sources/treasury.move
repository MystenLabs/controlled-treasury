/// A smart contract to manage the treasury and associated caps of a controlled coin.
/// Features:
/// - An admin can set permissions for different operations, and delete permissions, with effcient (immediate) revocation
/// - A deny permission allow modifying the deny list for this coin.
/// - A whitelist permission allows adding and removing addresses of market makets receivng minted and burning coins.
/// - A mint permission allows minting coins to a whitelisted address, within some limit.
/// - A burn permission allows burning coins from a whitelisted address.
/// - The treasury contract never holds any coins, they are immediately transfered on mint or burn by others.
/// - All addresses holding permissions can be multi-sigs.
/// - Events are emitted to keep track of mint and burn events.
///
/// Still TODO features:
/// - Allow cancelations of a partially authorized actions.
/// - Allow coordination of a multi-sig action on chain.
///
// Architecture notes:
/// - The treasury contract is a public object that can be shared with others.
/// - The treasury contract has a bag of capabilities that can be added and removed by the admin.
/// - Whitelist entries are also represented as capabilities in the bag.
/// - The treasury contract has a deny list that can be modified by the deny list capability.
/// - When calling a function you indicate the name of the capability in the bag to authorize the action.
module controlled_treasury::treasury {
    use std::type_name;
    use sui::tx_context::{sender, epoch, TxContext};
    use sui::coin::{Self, Coin, DenyCap, TreasuryCap};
    use sui::deny_list::DenyList;
    use sui::object::{Self, UID};
    use sui::bag::{Bag, Self};
    use sui::transfer;
    use sui::event;

    /// The Capability record does not exist.
    const ENoAuthRecord: u64 = 0;
    /// The limit for minting has been exceeded.
    const ELimitExceeded: u64 = 1;
    /// The capability record does not exist.
    const ENoCapRecord: u64 = 2;
    /// Trying to add a capability that already exists.
    const ERecordExists: u64 = 3;
    /// Trying to add an address that is already on denylist.
    const EDenyEntryExists: u64 = 4;
    /// Trying to remove an address that is not on denylist.
    const ENoDenyEntry: u64 = 5;
    /// Trying to add a whitelist entry that already exists.
    const EWhitelistRecordExists: u64 = 6;
    /// Trying to remove a whitelist entry that does not exist.
    const ENoWhitelistRecord: u64 = 7;
    /// Trying to remove the last admin.
    const EAdminsCantBeZero: u64 = 8;

    // A structure that wrapps the treasury cap of a coin and adds capabilities to so
    // that operations are controlled by a more granular and flexible policy. Can wrap
    // the capavilities after calling the constructor of a controlled coin.
    // Note: Upgrade cap can also be added to allow for upgrades
    struct ControlledTreasury<phantom T> has key {
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
    struct AdminCap has store, drop {}

    /// A risk manager capability that managed KYC addresses
    struct WhitelistCap has store, drop {}

    /// A whitelist entry signifies that the address is authorized to burn, and safe to mint to
    struct WhitelistEntry has store, drop {}

    /// Define a capability to modify the deny list
    struct DenyMutCap has store, drop { }

    /// Define a mint capability that may mint coins, with a limit
    struct MintCap has store, drop {
        limit: u64,
        epoch: u64,
        left: u64,
    }

    // === Events ===

    struct MintEvent<phantom T> has copy, drop {
        amount: u64,
        to: address,
    }

    struct BurnEvent<phantom T> has copy, drop {
        amount: u64,
        from: address,
    }

    // === DF Keys ===

    /// Namespace for dynamic fields: one for each of the Cap's.
    struct RoleKey<phantom T> has copy, store, drop { owner: address }

    // Note all "address" can represent multi-signature addresses and be authorized at any threshold

    // === Capabilities ===

    /// Create a new `AdminCap` to assign.
    public fun new_admin_cap(): AdminCap { AdminCap {} }

    /// Create a new `WhitelistCap` to assign.
    public fun new_whitelist_cap(): WhitelistCap { WhitelistCap {} }

    /// Create a new `MintCap` to assign.
    public fun new_mint_cap(limit: u64, ctx: &TxContext): MintCap {
        MintCap {
            limit,
            epoch: epoch(ctx),
            left: limit,
        }
    }

    /// Create a new `DenyMutCap` to assign.
    public fun new_deny_mut_cap(): DenyMutCap { DenyMutCap {} }

    /// Create a new controlled treasury by wrapping the treasury cap of a coin
    /// The `ControlledTreasury` becomes a public shared object with an initial Admin capability assigned to
    /// the provided owner.
    ///
    /// The `ControlledTreasury` has to be `share`d after the creation.
    public fun new<T>(
        treasury_cap: TreasuryCap<T>,
        deny_cap: DenyCap<T>,
        owner: address,
        ctx: &mut TxContext
    ): ControlledTreasury<T> {
        let treasury = ControlledTreasury {
            id: object::new(ctx),
            treasury_cap,
            deny_cap,
            admin_count: 1,
            own_capabilities: bag::new(ctx),
        };
        add_cap(&mut treasury, owner, AdminCap {});
        treasury
    }

    #[lint_allow(share_owned)]
    /// Make ControlledTreasury a shared object.
    public fun share<T>(treasury: ControlledTreasury<T>) {
        transfer::share_object(treasury);
    }

    /// Unpack the `ControlledTreasury` and return the treasury cap, deny cap
    /// and the Bag. The Bag must be cleared by the admin to be unpacked
    public fun deconstruct<T>(
        treasury: ControlledTreasury<T>, ctx: &mut TxContext
    ): (TreasuryCap<T>, DenyCap<T>, Bag) {
        assert!(has_cap<T, AdminCap>(&treasury, sender(ctx)), ENoAuthRecord);

        // Deconstruct the structure and return the parts
        let ControlledTreasury {
            id,
            admin_count,
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
    /// - the sender does not have AdminCap
    /// - the receiver already has a `C` cap
    public fun add_capability<T, C: store + drop>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        cap: C,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, AdminCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(!has_cap<T, C>(treasury, for), ERecordExists);

        // using a reflection trick to update admin count when adding a new admin
        if (type_name::get<C>() == type_name::get<AdminCap>()) {
            treasury.admin_count = treasury.admin_count + 1;
        };

        add_cap(treasury, for, cap);
    }

    /// Allow the admin to remove capabilities from the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    ///
    /// Aborts if:
    /// - the sender does not have `AdminCap`
    /// - the receiver does not have `C` cap
    public fun remove_capability<T, C: store + drop>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, AdminCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(has_cap<T, C>(treasury, for), ENoCapRecord);

        // using a reflection trick to update admin count when removing an admin
        // make sure there's at least one admin always
        if (type_name::get<C>() == type_name::get<AdminCap>()) {
            assert!(treasury.admin_count > 1, EAdminsCantBeZero);
            treasury.admin_count = treasury.admin_count - 1;
        };

        let _: C = remove_cap(treasury, for);
    }

    // === Whitelist operations ===

    /// Allow the owner of a whitelist capability to add a whitelist entry to the own_capabilities bag
    /// Authorization checks that a capability under the given name is owned by the caller.
    ///
    /// Aborts if:
    /// - the sender does not have a `WhitelistCap`
    /// - the address is already whitelisted
    public fun add_whitelist_entry<T>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(!has_cap<T, WhitelistCap>(treasury, for), EWhitelistRecordExists);

        add_cap(treasury, for, WhitelistEntry {});
    }

    /// Allow the owner of a whitelist capability to remove a whitelist entry from the own_capabilities bag
    /// Authorization checks that a capability under the given name is owned by the caller.
    ///
    /// Aborts if:
    /// - the sender does not have a WhitelistCap
    /// - the address is not whitelisted
    public fun remove_whitelist_entry<T>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(has_cap<T, WhitelistEntry>(treasury, for), ENoWhitelistRecord);

        let _: WhitelistEntry = remove_cap(treasury, for);
    }

    // === Deny list operations ===

    /// Adds an `entry` to the Denylist. Requires sender to have a `DenyMutCap`
    /// assigned to them.
    ///
    /// Aborts if:
    /// - sender does not have this capability
    /// - denylist already contains the record
    public fun add_deny_address<T>(
        treasury: &mut ControlledTreasury<T>,
        deny_list: &mut DenyList,
        entry: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, DenyMutCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(!coin::deny_list_contains<T>(deny_list, entry), EDenyEntryExists);

        coin::deny_list_add<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    /// Removes an `entry` from the Denylist. Requires sender to have a `DenyMutCap`
    /// assigned to them.
    ///
    /// Aborts if:
    /// - sender does not have this capability
    /// - denylist does not contain this record
    public fun remove_deny_address<T>(
        treasury: &mut ControlledTreasury<T>,
        deny_list: &mut DenyList,
        entry: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, DenyMutCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(coin::deny_list_contains<T>(deny_list, entry), ENoDenyEntry);

        coin::deny_list_remove<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    // Allow an authorized multi-sig to mint and transfer coins to a whitelisted address
    ///
    /// Aborts if:
    /// - sender does not have MintCap assigned to them
    /// - the amount is higher than the defined limit on MintCap
    /// - the receiver is not Whitelisted
    ///
    /// Emits: MintEvent
    public fun mint_and_transfer<T>(
        treasury: &mut ControlledTreasury<T>,
        amount: u64,
        to: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, MintCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(has_cap<T, WhitelistEntry>(treasury, to), ENoWhitelistRecord);

        // get the MintCap and check the limit; if a new epoch - reset it
        let MintCap { limit, epoch, left } = get_cap_mut(treasury, sender(ctx));

        // reset the limit if a new epoch
        if (epoch(ctx) > *epoch) {
            left = limit;
            *epoch = epoch(ctx);
        };

        // Check that the amount is within the mint limit; update the limit
        assert!(amount <= *left, ELimitExceeded);
        *left = *left - amount;

        // Emit the event and mint + transfer the coins
        event::emit(MintEvent<T> { amount, to });
        let new_coin = coin::mint(&mut treasury.treasury_cap, amount, ctx);
        transfer::public_transfer(new_coin, to);
    }

    // Allow any external address on the whitelist to burn coins
    // This assumes that any whitelisted addres has gone through KYC and banking info is available to send back USD
    ///
    /// Aborts if:
    /// - sender is not on the whitelist
    ///
    /// Emits: BurnEvent
    public fun burn<T>(
        treasury: &mut ControlledTreasury<T>,
        coin: Coin<T>,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistEntry>(treasury, sender(ctx)), ENoAuthRecord);

        event::emit(BurnEvent<T> {
            amount: coin::value(&coin),
            from: sender(ctx)
        });

        coin::burn(&mut treasury.treasury_cap, coin);
    }

    // === Utilities ===

    /// Check if a capability `Cap` is assigned to the `owner`. Publicly available for tests
    /// and interoperability with other packages / modules.
    public fun has_cap<T, Cap: store>(treasury: &ControlledTreasury<T>, owner: address): bool {
        bag::contains_with_type<RoleKey<Cap>, Cap>(&treasury.own_capabilities, RoleKey<Cap> { owner })
    }

    // === Private Utilities ===

    #[allow(unused_function)]
    /// Get a capability for the `owner`.
    fun get_cap<T, Cap: store + drop>(treasury: &ControlledTreasury<T>, owner: address): &Cap {
        bag::borrow(&treasury.own_capabilities, RoleKey<Cap> { owner })
    }

    /// Get a mutable ref to the capability for the `owner`.
    fun get_cap_mut<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, owner: address): &mut Cap {
        bag::borrow_mut(&mut treasury.own_capabilities, RoleKey<Cap> { owner })
    }

    /// Adds a capability `cap` for `owner`.
    fun add_cap<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, owner: address, cap: Cap) {
        bag::add(&mut treasury.own_capabilities, RoleKey<Cap> { owner }, cap);
    }

    /// Remove a `Cap` from the `owner`.
    fun remove_cap<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, owner: address): Cap {
        bag::remove(&mut treasury.own_capabilities, RoleKey<Cap> { owner })
    }
}
