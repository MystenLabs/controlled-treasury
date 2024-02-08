// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// What we want to achieve:
// 1. Register voters
// 2. Voters vote to perform an action
// 3. Action is authorized once there's a quorum
//
// Works on "2f + 1" basis - 51% is enough to perform an action.


// `Proposal` struct is a candy that needs a wrapper

///
module quorum::quorum {
    use std::vector;
    use std::option;
    use std::type_name;
    use sui::tx_context::{Self, sender, TxContext};
    use sui::vec_set::{Self, VecSet};
    use sui::vec_map::{Self, VecMap};

    use sui::object::{Self, ID, UID};
    use sui::bag::{Self, Bag};
    use sui::address;
    use sui::hash;
    use sui::bcs;

    /// Trying to perform an action not being a part of the quorum.
    const ENotVoter: u64 = 0;
    /// Trying to act on a proposal that doesn't exist (never / already).
    const ENoProposal: u64 = 1;
    /// Function awaits implementation
    const ENotImplemented: u64 = 1337;

    // === Managing Quorum ===

    ///
    struct AddVoter has store, drop { voter: address }

    ///
    struct RemoveVoter has store, drop { voter: address }

    /// This is where things get spicy! Due to specifics of the application,
    /// we can only allow unwrapping the candy when a TreasuryCap is shown.
    ///
    /// To make sure E<P> matches the TCap, we need to make Quorum T-specific.
    /// And that makes the last piece of the Puzzle. To prevent Quorum from
    /// being randomly spawned, we can require the TCap upon creation, perhaps?
    ///
    /// Or we could lock a single cap in the Quorum so that there's one Q per T?
    /// Oh, man, can get very complex easy. Think! Think!
    ///
    /// > propose: Proposal -> Q(Cap)
    /// > voting:  Q(Cap).Proposal +vote
    /// > execute: Q(Cap) -> Confirmed<Proposal> + Cap
    ///
    /// Proposal doesn't make any sense unless it gives the Cap in the end.
    /// How do we ensure the execution was correct in the end? That's the part
    /// that bugs me.
    ///
    /// Perhaps, we shouldn't allow "any" party execute. It should be voters.
    /// Guess that is left for a "dream" implementation. Though if we don't go
    /// the all-in way, then everything makes more sense all of a sudden and we
    /// shouldn't worry that much about wrongful execution.
    ///
    /// Actually, if they fail to execute, the worst thing is repeating the steps.
    /// And I don't think it's that bad tbh. It's either correct execution or no
    /// execution.
    ///
    /// It's the type which you can unpack easily but no way you can pack except
    /// if you go through the voting. A reverse-request - all actions were already
    /// taken before it was issued.
    struct Confirmed<Proposal> {
        p: Proposal,
        q: address,
    }

    // What if `Quorum<AdminCap>` could manage the rest? Well, technically, other
    // caps need to be created using the AdminCap, right? And once they're

    // random: we have 5 people, 2 of them leave, 3 left are voting them out and
    //         continue normal operation of the Quorum until they add 2 more.
    //
    // so what's the goal of the Quorum app? act as the center or as a component
    // which enables the rest of the system?

    /// Always a top-level object.
    struct Quorum /* <Cap: store> */ has key {
        id: UID,

        /// The stored capability which voters can access through a successful
        /// vote. Wrapped into `Option` to allow temporary borrow during the
        /// execution stage.
        // cap: Option<Cap>,

        /// The set of voters participating in the quorum. Can be modified by
        /// voting to include or exclude participants.
        // voters: VecSet<address>,
        voters: VecSet<address>,

        /// Stores currently active votes in a map: proposal_id => votes
        /// Records are added in `propose`, modified in `vote` and removed in
        /// `execute`.
        votes: VecMap<address, VecSet<address>>,

        /// Stores the proposal structs. They will be wrapped into an Executable
        /// once taken out.
        proposals: Bag,
    }

    // === Voting mechanics ===

    /// Start a new vote for an operation
    ///
    /// Q: Should the proposing party also automatically vote for this?
    public fun propose<Proposal: store + drop>(
        q: &mut Quorum, p: Proposal, ctx: &mut TxContext
    ): address {
        let p_id = proposal_id(&p);
        let voter = sender(ctx);

        assert!(is_voter(q, &voter), 0);
        assert!(!has_proposal(q, &p_id), 1);

        vec_map::insert(&mut q.votes, *&p_id, vec_set::singleton(voter));
        bag::add(&mut q.proposals, *&p_id, p);
        p_id
    }

    /// Vote for an active proposal
    public fun vote<Proposal>(
        q: &mut Quorum, p_id: address, ctx: &mut TxContext
    ) {
        let voter = sender(ctx);

        assert!(is_voter(q, &voter), 0);
        assert!(has_proposal(q, &p_id), 1);

        vec_set::insert(
            vec_map::get_mut(&mut q.votes, &p_id),
            voter
        );
    }

    /// Be mindful.
    /// This could be your way out.
    /// Decrease complexity by a lot at once.
    public(friend) fun execute_() {}

    /// Voters can execute the proposal
    public fun execute<Proposal: store>(
        q: &mut Quorum,
        p_id: address,
        ctx: &mut TxContext,
    ): Proposal {
        assert!(is_voter(q, &sender(ctx)), 0);
        assert!(has_proposal(q, &p_id), 1);

        let (_, p) = vec_map::remove(&mut q.votes, &p_id); // voting
        let l = (vec_set::size(&q.voters) / 2) + 1;   // expected votes

        // todo: filter out votes that no longer count (eg voter was removed)

        assert!(vec_set::size(&p) >= l, 2);

        bag::remove(&mut q.proposals, p_id)
    }

    /// Revoke the Proposal. Remove the vote of `sender` from the voting.
    ///
    /// Proposal is removed completely if:
    /// - there are no votes in the end
    /// - there are votes but none of them are in the voters set (were removed)
    public fun revoke<Proposal>(_q: &mut Quorum, _p_id: address) {
        abort ENotImplemented
    }

    // === Internal Functions ===

    /// Proposal ID is generated from the "type signature + bytes".
    ///
    /// It is not expected that proposals would be big, mostly simple
    /// operations of kind:
    /// - MintTo { address, amount }
    /// - DenylistAdd { address }
    /// - AddWhitelist { address }
    fun proposal_id<Proposal>(p: &Proposal): address {
        let src = bcs::to_bytes(&type_name::get<Proposal>());
        vector::append(&mut src, bcs::to_bytes(p));
        address::from_bytes(hash::blake2b256(&src))
    }

    /// Check whether the address is allowed to participate in the Quorum.
    fun is_voter(q: &Quorum, voter: &address): bool {
        vec_set::contains(&q.voters, voter)
    }

    /// Check whether Quorum has an actively running proposal
    fun has_proposal(q: &Quorum, proposal_id: &address): bool {
        vec_map::contains(&q.votes, proposal_id)
    }

    // === Testing ===

    #[test] fun test_quorum() {
        let ctx = &mut next_tx(@alice, 0);
        let voters = vec_set::singleton(@alice);
        vec_set::insert(&mut voters, @bob);

        let q = Quorum {
            voters,
            // cap: option::none<u8>(),
            id: object::new(ctx),
            votes: vec_map::empty(),
            proposals: bag::new(ctx),
        };

        // alice proposes to add Carl to the set
        let proposal = AddVoter { voter: @carl };
        let p_id = Self::propose(&mut q, proposal, &mut next_tx(@alice, 1));

        // bob supports the vote and executes
        let ctx = &mut next_tx(@bob, 2);

        Self::vote<AddVoter>(&mut q, p_id, ctx);
        Self::execute<AddVoter>(&mut q, p_id, ctx);

        test_utils::destroy(q)
    }

    #[test_only] use sui::test_utils;
    #[test_only] fun next_tx(sender: address, hint: u64): TxContext {
        tx_context::new_from_hint(sender, hint, 1, 0, 0)
    }
}
//
