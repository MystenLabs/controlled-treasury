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

    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{sender, TxContext};
    use sui::bag::{Bag, Self};
    use sui::event;

    // Import moduled for Coin to get TreasuryCap
    use sui::coin::{Self, Coin, DenyCap, TreasuryCap};
    use sui::deny_list::DenyList;

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

    // A structure that wrapps the treasury cap of a coin and adds capabilities to so
    // that operations are controlled by a more granular and flexible policy. Can wrap
    // the capavilities after calling the constructor of a controlled coin.
    // Note: Upgrade cap can also be added to allow for upgrades
    struct ControlledTreasury<phantom T> has key {
        id: UID,
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

    /// Define a mint capability that may mint coins, with a limit
    struct MintCap has store, drop { limit: u64 }

    /// Define a capability to modify the deny list
    struct DenyMutCap has store, drop { }

    // Define a few events for auditing
    // === Events ===

    struct MintEvent has copy, drop {
        amount: u64,
        to: address,
    }

    struct BurnEvent has copy, drop {
        amount: u64,
        from: address,
    }

    // === DF Keys ===

    /// Namespace for dynamic fields: one for each of the Cap's.
    struct RoleKey<phantom T> has copy, store, drop { owner: address }

    // Note all "address" can represent multi-signature addresses and be authorized at any threshold

    // Constructor functions for capabilities
    public fun new_admin_cap(): AdminCap {
        AdminCap {}
    }

    public fun new_whitelist_cap(): WhitelistCap {
        WhitelistCap {}
    }

    public fun new_whitelist_entry(): WhitelistEntry {
        WhitelistEntry {}
    }

    public fun new_mint_cap(limit: u64): MintCap {
        MintCap { limit }
    }

    public fun new_deny_mut_cap(): DenyMutCap {
        DenyMutCap {}
    }

    /// Create a new controlled treasury by wrapping the treasury cap of a coin
    /// Th treasure becomes a public object with an initial Admin capbility assigned to
    /// the owner of the treasury as provided.
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
            own_capabilities: bag::new(ctx),
        };
        add_cap(&mut treasury, owner, AdminCap {});
        treasury
    }

    #[lint_allow(share_owned)]
    /// Make the treasury a shared object.
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
        let ControlledTreasury { id, treasury_cap, deny_cap, own_capabilities } = treasury;
        object::delete(id);

        (treasury_cap, deny_cap, own_capabilities)
    }

    /// Allow the admin to add capabilities to the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun add_capability<T, C: store + drop>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        cap: C,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, AdminCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(!has_cap<T, C>(treasury, for), ERecordExists);

        // Add the capability to the treasury
        add_cap(treasury, for, cap);
    }

    /// Allow the admin to remove capabilities from the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun remove_capability<T, C: store + drop>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, AdminCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(has_cap<T, C>(treasury, for), ENoCapRecord);

        // Remove the capability from the treasury
        let _: C = remove_cap(treasury, for);
    }

    /// Allow the owner of a whitelist capability to add a whitelist entry to the own_capabilities bag
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun add_whitelist_entry<T>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(!has_cap<T, WhitelistCap>(treasury, for), EWhitelistRecordExists);

        // Add the entry to the treasury; key already contains the address
        add_cap(treasury, for, WhitelistEntry {});
    }

    /// Allow the owner of a whitelist capability to remove a whitelist entry from the own_capabilities bag
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun remove_whitelist_entry<T>(
        treasury: &mut ControlledTreasury<T>,
        for: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(has_cap<T, WhitelistEntry>(treasury, for), ENoWhitelistRecord);

        // Now lets remove it.
        let _: WhitelistEntry = remove_cap(treasury, for);
    }

    // Deny list operations

    public fun add_deny_address<T>(
        treasury: &mut ControlledTreasury<T>,
        deny_list: &mut DenyList,
        entry: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, DenyMutCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(!coin::deny_list_contains<T>(deny_list, entry), EDenyEntryExists);

        // Add to deny list
        coin::deny_list_add<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    public fun remove_deny_address<T>(
        treasury: &mut ControlledTreasury<T>,
        deny_list: &mut DenyList,
        entry: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, DenyMutCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(coin::deny_list_contains<T>(deny_list, entry), ENoDenyEntry);

        // Add to deny list
        coin::deny_list_remove<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    // Allow an authorized multi-sig to mint and transfer coins to a whitelisted address
    public fun mint_and_transfer<T>(
        treasury: &mut ControlledTreasury<T>,
        to: address,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, MintCap>(treasury, sender(ctx)), ENoAuthRecord);
        assert!(has_cap<T, WhitelistEntry>(treasury, to), ENoWhitelistRecord);

        // Authorize sender has a mint cap
        let MintCap { limit } = get_cap(treasury, sender(ctx));

        // Check that the amount is within the mint limit
        // NOTE: Here we can have daily limits by updating the capability within
        //       the bag to "remember" totals for the day, for example.
        assert!(amount <= *limit, ELimitExceeded);

        // Mint and transfer the coins atomically, no holding account of coins
        event::emit(MintEvent { amount, to });

        let new_coin = coin::mint(&mut treasury.treasury_cap, amount, ctx);
        transfer::public_transfer(new_coin, to);
    }

    // Allow any external address on the whitelist to burn coins
    // This assumes that any whitelisted addres has gone through KYC and banking info is available to send back USD
    public fun burn<T>(
        treasury: &mut ControlledTreasury<T>,
        coin: Coin<T>,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistEntry>(treasury, sender(ctx)), ENoAuthRecord);

        // Burn the coins atomically, no holding of coins
        event::emit(BurnEvent {
            amount: coin::value(&coin),
            from: sender(ctx)
        });

        coin::burn(&mut treasury.treasury_cap, coin);
    }

    // === Utilities ===

    // Check if the treasury has a capability with the given key.
    fun has_cap<T, Cap: store>(treasury: &ControlledTreasury<T>, owner: address): bool {
        bag::contains_with_type<RoleKey<Cap>, Cap>(&treasury.own_capabilities, RoleKey<Cap> { owner })
    }

    /// Get a capability from the treasury.
    fun get_cap<T, Cap: store + drop>(treasury: &ControlledTreasury<T>, owner: address): &Cap {
        bag::borrow(&treasury.own_capabilities, RoleKey<Cap> { owner })
    }

    /// Adds a capability to the treasury.
    fun add_cap<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, owner: address, cap: Cap) {
        bag::add(&mut treasury.own_capabilities, RoleKey<Cap> { owner }, cap);
    }

    /// Removes a capability from the treasury.
    fun remove_cap<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, owner: address): Cap {
        bag::remove(&mut treasury.own_capabilities, RoleKey<Cap> { owner })
    }
}
