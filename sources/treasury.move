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
    use sui::tx_context::{Self, TxContext};
    use sui::bag::{Bag, Self};
    use sui::event;

    // Import moduled for Coin to get TreasuryCap
    use sui::coin::{Self, Coin, DenyCap, TreasuryCap};
    use sui::deny_list::DenyList;

    /// The Capability record does not exist.
    const ENoAuthRecord: u64 = 0;
    /// The sender is not authorized to perform the action.
    const ENotAuthorized: u64 = 1;
    /// The limit for minting has been exceeded.
    const ELimitExceeded: u64 = 2;
    /// The capability record does not exist.
    const ENoCapRecord: u64 = 3;
    /// Trying to add a capability that already exists.
    const ERecordExists: u64 = 4;
    /// Trying to add an address that is already on denylist.
    const EDenyEntryExists: u64 = 5;
    /// Trying to remove an address that is not on denylist.
    const ENoDenyEntry: u64 = 6;
    /// Trying to add a whitelist entry that already exists.
    const EWhitelistRecordExists: u64 = 7;
    /// Trying to remove a whitelist entry that does not exist.
    const ENoWhitelistRecord: u64 = 8;



    // A structure that wrapps the treasury cap of a coin and adds capabilities to so
    // that operations are controlled by a more granular and flexible policy. Can wrap
    // the capavilities after calling the constructor of a controlled coin.
    // Note: Upgrade cap can also be added to allow for upgrades
    struct ControlledTreasury<phantom T> has key, store {
        id: UID,
        /// The treasury cap of the Coin.
        treasury_cap: TreasuryCap<T>,
        deny_cap: DenyCap<T>,
        own_capabilities: Bag,
    }

    /// An administrator capability that may manage permissions
    struct AdminCap has store, drop {
        owner: address,
    }

    /// A risk manager capability that managed KYC addresses
    struct WhitelistCap has store, drop {
        owner: address,
    }

    /// A whitelist entry signifies that the address is authorized to burn, and safe to mint to
    struct WhitelistEntry has store, drop {
        remote_address: address,
    }

    /// Define a mint capability that may mint coins, with a limit
    struct MintCap has store, drop {
        owner: address,
        limit: u64,
    }

    /// Define a capability to modify the deny list
    struct DenyMutCap has store, drop {
        owner: address,
    }

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
    struct TypedKey<phantom T> has copy, store, drop { key: vector<u8> }

    // Note all "address" can represent multi-signature addresses and be authorized at any threshold

    // Constructor functions for capabilities
    public fun new_admin_cap(owner: address): AdminCap {
        AdminCap { owner }
    }

    public fun new_whitelist_cap(owner: address): WhitelistCap {
        WhitelistCap { owner }
    }

    public fun new_whitelist_entry(remote_address: address): WhitelistEntry {
        WhitelistEntry { remote_address }
    }

    public fun new_mint_cap(owner: address, limit: u64): MintCap {
        MintCap { owner, limit }
    }

    public fun new_deny_mut_cap(owner: address): DenyMutCap {
        DenyMutCap { owner }
    }

    /// Create a new controlled treasury by wrapping the treasury cap of a coin
    /// Th treasure becomes a public object with an initial Admin capbility assigned to
    /// the owner of the treasury as provided.
    public fun new<T>(
        treasury_cap: TreasuryCap<T>,
        deny_cap: DenyCap<T>,
        owner: address,
        ctx: &mut TxContext
    ) {
        let treasury = ControlledTreasury {
            id: object::new(ctx),
            treasury_cap,
            deny_cap,
            own_capabilities: bag::new(ctx),
        };
        add_cap(&mut treasury, b"admin", AdminCap { owner });
        transfer::share_object(treasury);
    }

    public fun deconstruct<T>(
        treasury: ControlledTreasury<T>, auth: vector<u8>, ctx: &mut TxContext
    ): (TreasuryCap<T>, DenyCap<T>, Bag) {
        assert!(has_cap<T, AdminCap>(&treasury, auth), ENoAuthRecord);

        // Authorize sender has an admin cap
        let AdminCap { owner } = get_cap(&treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Deconstruct the structure and return the parts
        let ControlledTreasury { id, treasury_cap, deny_cap, own_capabilities } = treasury;
        object::delete(id);

        (treasury_cap, deny_cap, own_capabilities)
    }

    /// Allow the admin to add capabilities to the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun add_capability<T, C: store + drop>(
        treasury: &mut ControlledTreasury<T>,
        auth: vector<u8>,
        name: vector<u8>,
        cap: C,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, AdminCap>(treasury, auth), ENoAuthRecord);
        assert!(!has_cap<T, C>(treasury, name), ERecordExists);

        // Authorize sender has an admin cap
        let AdminCap { owner } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Add the capability to the treasury
        add_cap(treasury, name, cap);
    }

    /// Allow the admin to remove capabilities from the treasury
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun remove_capability<T, C: store + drop>(
        treasury: &mut ControlledTreasury<T>,
        auth: vector<u8>,
        name: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, AdminCap>(treasury, auth), ENoAuthRecord);
        assert!(has_cap<T, C>(treasury, name), ENoCapRecord);

        // Authorize sender has an admin cap
        let AdminCap { owner } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Remove the capability from the treasury
        let _: C = remove_cap(treasury, name);
    }

    /// Allow the owner of a whitelist capability to add a whitelist entry to the own_capabilities bag
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun add_whitelist_entry<T>(
        treasury: &mut ControlledTreasury<T>,
        auth: vector<u8>,
        name: vector<u8>,
        entry: WhitelistEntry,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistCap>(treasury, auth), ENoAuthRecord);
        assert!(!has_cap<T, WhitelistCap>(treasury, name), EWhitelistRecordExists);

        // Authorize sender has a whitelist cap
        let WhitelistCap { owner } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Add the entry to the treasury
        add_cap(treasury, name, entry);
    }

    /// Allow the owner of a whitelist capability to remove a whitelist entry from the own_capabilities bag
    /// Authorization checks that a capability under the given name is owned by the caller.
    public fun remove_whitelist_entry<T>(
        treasury: &mut ControlledTreasury<T>,
        auth: vector<u8>,
        name: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistCap>(treasury, auth), ENoAuthRecord);
        assert!(has_cap<T, WhitelistEntry>(treasury, name), ENoWhitelistRecord);

        // Authorize sender has a whitelist cap
        let WhitelistCap { owner } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Now lets remove it.
        let _: WhitelistEntry = remove_cap(treasury, name);
    }

    // Deny list operations

    public fun add_deny_address<T>(
        treasury: &mut ControlledTreasury<T>,
        deny_list: &mut DenyList,
        auth: vector<u8>,
        entry: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, DenyMutCap>(treasury, auth), ENoAuthRecord);
        assert!(!coin::deny_list_contains<T>(deny_list, entry), EDenyEntryExists);

        // Authorize sender has a whitelist cap
        let DenyMutCap { owner } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Add to deny list
        coin::deny_list_add<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    public fun remove_deny_address<T>(
        treasury: &mut ControlledTreasury<T>,
        deny_list: &mut DenyList,
        auth: vector<u8>,
        entry: address,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, DenyMutCap>(treasury, auth), ENoAuthRecord);
        assert!(coin::deny_list_contains<T>(deny_list, entry), ENoDenyEntry);

        // Authorize sender has a whitelist cap
        let DenyMutCap { owner } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Add to deny list
        coin::deny_list_remove<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    // Allow an authorized multi-sig to mint and transfer coins to a whitelisted address
    public fun mint_and_transfer<T>(
        treasury: &mut ControlledTreasury<T>,
        auth: vector<u8>,
        to: vector<u8>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, MintCap>(treasury, auth), ENoAuthRecord);
        assert!(has_cap<T, WhitelistEntry>(treasury, to), ENoWhitelistRecord);

        // Authorize sender has a mint cap
        let MintCap { owner, limit } = get_cap(treasury, auth);
        assert!(owner == &tx_context::sender(ctx), ENotAuthorized);

        // Check that the amount is within the mint limit
        // NOTE: Here we can have daily limits by updating the capability within
        //       the bag to "remember" totals for the day, for example.
        assert!(amount <= *limit, ELimitExceeded);

        // Get the remote address from the whitelist entry.
        let WhitelistEntry { remote_address } = get_cap(treasury, to);
        let to = *remote_address;

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
        auth: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert!(has_cap<T, WhitelistEntry>(treasury, auth), ENoAuthRecord);

        // Check that the sender is whitelisted, by loading it
        let WhitelistEntry { remote_address } = get_cap(treasury, auth);
        assert!(remote_address == &tx_context::sender(ctx), ENotAuthorized);

        // Burn the coins atomically, no holding of coins
        event::emit(BurnEvent { amount: coin::value<T>(&coin), from: *remote_address });
        coin::burn(&mut treasury.treasury_cap, coin);
    }

    // === Utilities ===

    // Check if the treasury has a capability with the given key.
    fun has_cap<T, Cap: store>(treasury: &ControlledTreasury<T>, key: vector<u8>): bool {
        bag::contains_with_type<TypedKey<Cap>, Cap>(&treasury.own_capabilities, TypedKey<Cap> { key })
    }

    /// Get a capability from the treasury.
    fun get_cap<T, Cap: store + drop>(treasury: &ControlledTreasury<T>, key: vector<u8>): &Cap {
        bag::borrow(&treasury.own_capabilities, TypedKey<Cap> { key })
    }

    /// Adds a capability to the treasury.
    fun add_cap<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, key: vector<u8>, cap: Cap) {
        bag::add(&mut treasury.own_capabilities, TypedKey<Cap> { key }, cap);
    }

    /// Removes a capability from the treasury.
    fun remove_cap<T, Cap: store + drop>(treasury: &mut ControlledTreasury<T>, key: vector<u8>): Cap {
        bag::remove(&mut treasury.own_capabilities, TypedKey<Cap> { key })
    }
}
