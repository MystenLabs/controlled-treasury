module controlled_treasury::deny_revoke {

    use controlled_treasury::treasury::{AdminCap, ControlledTreasury};

    use sui::coin;
    use sui::deny_list::DenyList;

    /// DenyRevokeCap is a capability for revoking denylist addresses, thus reenable them to transfer coins.
    public struct DenyRevokeCap has key {
        id: UID
    }

    /// Witness for enabling DenyRevokeCap to remove from DenyList.
    public struct DenyRevokeAuth has store, drop {}

    /// Owner of `treasury::AdminCap` can create new `DenyRevokeCap`s.
    public fun add_deny_revoke_auth<T>(
        admin_cap: &AdminCap<T>,
        treasury: &mut ControlledTreasury<T>,
        ctx: &mut TxContext
    ): DenyRevokeCap {
        let deny_add_cap = DenyRevokeCap { id: object::new(ctx) };
        admin_cap.add_authorization(treasury, &deny_add_cap, DenyRevokeAuth {});
        deny_add_cap
    }

    /// Owner of `DenyRevokeCap` can remove addresses from the denylist.
    public fun revoke_deny_address<T>(
        deny_add_cap: &DenyRevokeCap,
        deny_list: &mut DenyList,
        treasury: &mut ControlledTreasury<T>,
        addr: address,
        ctx: &mut TxContext
    ) {
        coin::deny_list_remove<T>(
            deny_list,
            treasury.borrow_deny_cap_mut(deny_add_cap, DenyRevokeAuth {}),
            addr,
            ctx
        );
    }

    // ============================= Demo functions =============================
    // The below functions can be called via ptb directly

    /// Admin can remove `DenyRevokeAuth` to disable a `DenyRevokeCap`.
    public fun remove_deny_revoke_auth<T>(admin_cap: &AdminCap<T>, treasury: &mut ControlledTreasury<T>, deny_revoke_cap_id: ID) {
        admin_cap.remove_authorization<T, DenyRevokeAuth>(treasury, deny_revoke_cap_id);
    }
}
