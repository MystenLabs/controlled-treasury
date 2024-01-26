module controlled_treasury::treasury {

    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::bag::{Bag, Self};
    use sui::event;

    // Import moduled for Coin to get TreasuryCap
    use sui::coin::{Self, Coin, DenyCap, TreasuryCap};
    use sui::deny_list::{Self, DenyList};

    // A structure that wrapps the treasury cap of a coin and adds capabilities to so
    // that operations are controlled by a more granular and flexible policy.
    // Note: Upgrade cap can also be added to allow for upgrades
    struct ControlledTreasury<phantom T : key> has key, store {
        id : UID,
        treasury_cap: TreasuryCap<T>,
        deny_cap: DenyCap<T>,
        own_capabilities : Bag,
    }

    // Define an administrator capability that may manage permissions
    struct AdminCap has store, drop {
        owner: address,
    }

    // Define a risk manager capability that managed KYT adresses
    struct WhitelistCap has store, drop {
        owner: address,
    }

    // A whitelist entry signifies that the address is authorized to burn, and safe to mint to
    struct WhitelistEntry has store, drop {
        remote_address: address,
    }

    // Define a mint capability that may mint coins, with a limit
    struct MintCap has store, drop {
        owner: address,
        limit: u64,
    }

    // Define a capability to modify the deny list
    struct DenyMutCap has store, drop {
        owner: address,
    }

    // Define a few events for auditing

    struct MintEvent has copy, drop {
        amount: u64,
        to: address,
    }

    struct BurnEvent has copy, drop {
        amount: u64,
        from: address,
    }

    // Note all "address" can represent multi-signature addresses and be authorized at any threshold

    // Constructor functions for capabilities
    public fun new_admin_cap(owner: address) : AdminCap {
        AdminCap { owner }
    }

    public fun new_whitelist_cap(owner: address) : WhitelistCap {
        WhitelistCap { owner }
    }

    public fun new_whitelist_entry(remote_address: address) : WhitelistEntry {
        WhitelistEntry { remote_address }
    }

    public fun new_mint_cap(owner: address, limit: u64) : MintCap {
        MintCap { owner, limit }
    }

    public fun new_deny_mut_cap(owner: address) : DenyMutCap {
        DenyMutCap { owner }
    }

    // Create a new controlled treasury by wrapping the treasury cap of a coin
    // Th treasure becomes a public object with an initial Admin capbility assigned to 
    // the owner of the treasury as provided.
    public fun new<T : key>(treasury_cap: TreasuryCap<T>, deny_cap: DenyCap<T>, owner: address, ctx: &mut TxContext) {
        let cap = ControlledTreasury {
            id: object::new(ctx),
            treasury_cap,
            deny_cap,
            own_capabilities: bag::new(ctx),
        };
        bag::add(&mut cap.own_capabilities, b"admin", AdminCap { owner });
        transfer::share_object(cap);
    }

    public fun deconstruct<T: key>(auth: vector<u8>, treasury : ControlledTreasury<T>, ctx: &mut TxContext) : (TreasuryCap<T>, DenyCap<T>, Bag) {

        // Authorize sender has an admin cap
        let admin_cap = bag::borrow<vector<u8>, AdminCap>(&treasury.own_capabilities, auth);
        let AdminCap { owner } = admin_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Deconstruct the structure and return the parts
        let ControlledTreasury { id, treasury_cap, deny_cap, own_capabilities } = treasury;
        object::delete(id);

        (treasury_cap, deny_cap, own_capabilities)
    }

    // Allow the admin to add capabilities to the treasury
    // Authorization checks that a capability under the given name is owned by the caller.
    public fun add_capability<T : key, C: store>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, name: vector<u8>, cap: C, ctx: &mut TxContext) {

        // Authorize sender has an admin cap
        let admin_cap = bag::borrow<vector<u8>, AdminCap>(&treasury.own_capabilities, auth);
        let AdminCap { owner } = admin_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Add the capability to the treasury
        bag::add(&mut treasury.own_capabilities, name, cap);
    }

    // Allow the admin to remove capabilities from the treasury
    // Authorization checks that a capability under the given name is owned by the caller.
    public fun remove_capability<T : key, C: store + drop>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, name: vector<u8>, ctx: &mut TxContext) {

        // Authorize sender has an admin cap
        let admin_cap = bag::borrow<vector<u8>, AdminCap>(&treasury.own_capabilities, auth);
        let AdminCap { owner } = admin_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Remove the capability from the treasury
        bag::remove<vector<u8>, C>(&mut treasury.own_capabilities, name);
    }

    // Allow the owner of a whitelist capability to add a whitelist entry to the own_capabilities bag
    // Authorization checks that a capability under the given name is owned by the caller.
    public fun add_whitelist_entry<T : key>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, name: vector<u8>, entry: WhitelistEntry, ctx: &mut TxContext) {

        // Authorize sender has a whitelist cap
        let whitelist_cap = bag::borrow<vector<u8>, WhitelistCap>(&treasury.own_capabilities, auth);
        let WhitelistCap { owner } = whitelist_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Add the entry to the treasury
        // Todo, restrict to namespace
        bag::add(&mut treasury.own_capabilities, name, entry);
    }

    // Allow the owner of a whitelist capability to remove a whitelist entry from the own_capabilities bag
    // Authorization checks that a capability under the given name is owned by the caller.
    public fun remove_whitelist_entry<T : key>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, name: vector<u8>, ctx: &mut TxContext) {

        // Authorize sender has a whitelist cap
        let whitelist_cap = bag::borrow<vector<u8>, WhitelistCap>(&treasury.own_capabilities, auth);
        let WhitelistCap { owner } = whitelist_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Remove the entry from the treasury

        // We load the capability to check that its the correct type.
        let whitelist_entry = bag::borrow<vector<u8>, WhitelistEntry>(&treasury.own_capabilities, name);
        let WhitelistEntry { remote_address: _ } = whitelist_entry;

        // Now lets remove it.
        bag::remove<vector<u8>, WhitelistEntry>(&mut treasury.own_capabilities, name);
    }

    // Deny list operations

    public fun add_deny_address<T : key>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, deny_list: &mut DenyList, entry: address, ctx: &mut TxContext) {

        // Authorize sender has a whitelist cap
        let deny_mut_cap = bag::borrow<vector<u8>, DenyMutCap>(&treasury.own_capabilities, auth);
        let DenyMutCap { owner } = deny_mut_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Add to deny list
        coin::deny_list_add<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    public fun remove_deny_address<T : key>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, deny_list: &mut DenyList, entry: address, ctx: &mut TxContext) {

        // Authorize sender has a whitelist cap
        let deny_mut_cap = bag::borrow<vector<u8>, DenyMutCap>(&treasury.own_capabilities, auth);
        let DenyMutCap { owner } = deny_mut_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Add to deny list
        coin::deny_list_remove<T>(deny_list, &mut treasury.deny_cap, entry, ctx);
    }

    // Allow an authorized multi-sig to mint and transfer coins to a whitelisted address
    public fun mint_and_transfer<T : key>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, to: vector<u8>, amount: u64, ctx: &mut TxContext) {

        // Authorize sender has a mint cap
        let mint_cap = bag::borrow<vector<u8>, MintCap>(&treasury.own_capabilities, auth);
        let MintCap { owner, limit } = mint_cap;
        assert!(owner == &tx_context::sender(ctx), 0);

        // Check that the amount is within the mint limit
        // NOTE: Here we can have daily limits by updating the capability within 
        //       the bag to "remember" totals for the day, for example.
        assert!(amount <= *limit, 0);

        // Check that the to address is whitelisted, by loading it
        let whitelist_entry = bag::borrow<vector<u8>, WhitelistEntry>(&treasury.own_capabilities, to);
        let WhitelistEntry { remote_address } = whitelist_entry;

        // Mint and transfer the coins atomically, no holding account of coins
        event::emit(MintEvent { amount, to: *remote_address });
        let new_coin = coin::mint(&mut treasury.treasury_cap, amount, ctx);
        transfer::public_transfer(new_coin, *remote_address);
    }

    // Allow any external address on the whitelist to burn coins
    // This assumes that any whitelisted addres has gone through KYC and banking info is available to send back USD
    public fun burn<T : key>(auth: vector<u8>, treasury: &mut ControlledTreasury<T>, amount: Coin<T>, ctx: &mut TxContext) {

        // Check that the sender is whitelisted, by loading it
        let whitelist_entry = bag::borrow<vector<u8>, WhitelistEntry>(&treasury.own_capabilities, auth);
        let WhitelistEntry { remote_address } = whitelist_entry;
        assert!(remote_address == &tx_context::sender(ctx), 0);

        // Burn the coins atomically, no holding of coins
        event::emit(BurnEvent { amount: coin::value<T>(&amount), from: *remote_address });
        coin::burn(&mut treasury.treasury_cap, amount);
    }



}