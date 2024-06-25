module controlled_treasury::deny_add {

    use controlled_treasury::treasury::{AdminCap, ControlledTreasury};

    use sui::coin;
    use sui::deny_list::DenyList;

    /// DenyAddCap is a capability for adding addresses to DenyList.
    public struct DenyAddCap has key {
        id: UID
    }

    /// Witness for enabling DenyAddCap to edit DenyList.
    public struct DenyAddAuth has store, drop {}

    /// Owner of `treasury::AdminCap` can create new `DenyAddCap`s.
    public fun add_deny_add_auth<T>(
        admin_cap: &AdminCap<T>,
        treasury: &mut ControlledTreasury<T>,
        ctx: &mut TxContext
    ): DenyAddCap {
        let deny_add_cap = DenyAddCap { id: object::new(ctx) };
        admin_cap.add_authorization(treasury, &deny_add_cap, DenyAddAuth {});
        deny_add_cap
    }

    /// Owner of `DenyAddCap` can add an address to `DenyList`.
    public fun add_deny_address<T>(
        deny_add_cap: &DenyAddCap,
        deny_list: &mut DenyList,
        treasury: &mut ControlledTreasury<T>,
        addr: address,
        ctx: &mut TxContext
    ) {
        coin::deny_list_add<T>(
            deny_list,
            treasury.borrow_deny_cap_mut(deny_add_cap, DenyAddAuth {}),
            addr,
            ctx
        );
    }

    // ============================= Demo functions =============================
    // The below functions can be called via ptb directly

    /// Admin can remove `DenyAddAuth`, to disable a `DenyAddCap`.
    public fun remove_deny_add_auth<T>(admin_cap: &AdminCap<T>, treasury: &mut ControlledTreasury<T>, deny_cap_add_id: ID) {
        admin_cap.remove_authorization<T, DenyAddAuth>(treasury, deny_cap_add_id);
    }
}
