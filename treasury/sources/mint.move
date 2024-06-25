module controlled_treasury::mint {

    use controlled_treasury::treasury::{ControlledTreasury, AdminCap};

    use sui::coin::Coin;

    /// MintCap is a capability for minting coins.
    public struct MintCap has key {
        id: UID
    }

    /// Witness for enabling MintCap to mint coins.
    public struct MintAuth has store, drop {}

    /// Owner of `treasury::AdminCap` can add new minters.
    public fun add_mint_auth<T>(admin_cap: &AdminCap<T>, treasury: &mut ControlledTreasury<T>, ctx: &mut TxContext): MintCap {
        let mint_cap = MintCap { id: object::new(ctx) };
        admin_cap.add_authorization(treasury, &mint_cap, MintAuth {});
        mint_cap
    }

    /// Owner of `MintCap` can mint coins.
    public fun mint<T>(mint_cap: &MintCap, treasury: &mut ControlledTreasury<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
        treasury.borrow_treasury_cap_mut(mint_cap, MintAuth {}).mint(amount, ctx)
    }

    // ============================= Demo functions =============================
    // The below functions can be called via ptb directly

    /// Admin can remove `MintAuth` for a `MintCap`.
    public fun remove_mint_auth<T>(admin_cap: &AdminCap<T>, treasury: &mut ControlledTreasury<T>, mint_cap_id: ID) {
        admin_cap.remove_authorization<T, MintAuth>(treasury, mint_cap_id);
    }
}
