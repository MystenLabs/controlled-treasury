module controlled_treasury::burn {

    use controlled_treasury::treasury::{ControlledTreasury, AdminCap};

    use sui::coin::Coin;

    /// BurnCap is a capability for burning coins.
    public struct BurnCap has key {
        id: UID
    }

    /// Witness for enabling BurnCap to burn coins.
    public struct BurnAuth has store, drop {}

    /// Owner of `treasury::AdminCap` can add new burners.
    public fun add_burn_auth<T>(admin_cap: &AdminCap<T>, treasury: &mut ControlledTreasury<T>, ctx: &mut TxContext): BurnCap {
        let mint_cap = BurnCap { id: object::new(ctx) };
        admin_cap.add_authorization(treasury, &mint_cap, BurnAuth {});
        mint_cap
    }

    /// Owner of `BurnCap` can burn coins.
    public fun burn<T>(mint_cap: &BurnCap, treasury: &mut ControlledTreasury<T>, coin: Coin<T>) {
        treasury.borrow_treasury_cap_mut(mint_cap, BurnAuth {}).burn(coin);
    }

    // ============================= Demo functions =============================
    // The below functions can be called via ptb directly

    /// Admin can remove a `BurnAuth` for a `BurnCap`.
    public fun remove_burn_auth<T>(admin_cap: &AdminCap<T>, treasury: &mut ControlledTreasury<T>, burn_cap_id: ID) {
        admin_cap.remove_authorization<T, BurnAuth>(treasury, burn_cap_id);
    }
}
