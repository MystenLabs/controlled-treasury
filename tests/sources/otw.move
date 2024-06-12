// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module tests::otw {
    use sui::coin::{Self, DenyCap, TreasuryCap};
    use sui::test_utils;

    public struct OTW has drop {}

    public fun create_currency(ctx: &mut TxContext): (TreasuryCap<OTW>, DenyCap<OTW>) {
        let (treasury, denycap, metadata) = coin::create_regulated_currency(
            OTW {},
            6,                   // decimals
            b"REG",              // symbol
            b"Test Coin",        // name
            b"Test Description", // description
            option::none(),      // icon url
            ctx
        );

        test_utils::destroy(metadata);
        (treasury, denycap)
    }
}
