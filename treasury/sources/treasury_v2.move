// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module controlled_treasury::treasury_v2 {

    use quorum::quorum::{Quorum, Confirmed};

    // TreasuryCap ==--authorize--> AdminCap
    //

    struct Treasury<phantom T> {}

    // === Caps ===

    struct AdminCap<phantom T> {}
    struct DenylistCap<phantom T> {}
    struct WhitelistCap<phantom T> {}



    struct AddWhitelist    { addr: address }
    struct RemoveWhitelist { addr: address }

    /// Starting a new TreasuryCap would mean starting a new Quorum to
    /// manage AdminCap too.
    public fun new<T>() {}
    public fun wen<T>() {}

    public fun new_quorum<T, Cap>(
        cap: Cap,
    ) { /* quorum::new(Cap, voters) */ abort 0 }

    /// We can't accept: AddWhitelist,
    /// We can accept: Confirmed(AddWhitelist)
    public fun add_whitelist_entry<T>(
        _p: Quorum<WhitelistCap<T>>,
    ) { abort 0 }

    ///
    public fun remove_whitelist_entry<T>(
        _p: Quorum<WhitelistCap<T>>,
    ) { abort 0 }

    ///
    public fun add_denylist_entry<T>(
        _p: Quorum<DenylistCap<T>>
    ) { abort 0 }

    public fun remove_denylist_entry<T>(
        _p: Quorum<Denylistcap<T>>
    ) { abort 0 }
}
