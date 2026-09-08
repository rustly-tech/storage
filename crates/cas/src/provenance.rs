//! Where an object came from, and how much that matters.
//!
//! # The short answer: much less than you would expect
//!
//! Every read is verified against its CID, so a source cannot serve *wrong*
//! bytes — only fail to serve. Provenance therefore is not a security control
//! for content integrity; it is recorded for two narrower purposes:
//!
//! * **Diagnostics.** When a peer serves corrupt bytes repeatedly, we want to
//!   know which peer.
//! * **Confidentiality.** Verification says nothing about who is *allowed* to
//!   hold an object. Hidden tests and private source must not be distributed
//!   broadly regardless of how well they hash.
//!
//! That second point is the one that actually constrains the design.

use serde::{Deserialize, Serialize};

/// Where an object was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Origin {
    /// Already on local disk.
    Local,
    /// A CDN or object-store seed operated by us.
    Seed {
        /// Which seed, for diagnostics.
        name: String,
    },
    /// Another participant in the network.
    Peer {
        /// Opaque peer identifier.
        id: String,
    },
    /// Produced here, by compiling or building.
    Built,
}

impl Origin {
    /// Whether this origin is operated by us.
    pub fn is_operator_controlled(&self) -> bool {
        matches!(self, Self::Local | Self::Seed { .. } | Self::Built)
    }
}

/// How far an object has got through verification.
///
/// This is about *artifacts we produced*, not about content integrity. A
/// compiled artifact from a volunteer hashes perfectly well and may still be
/// the output of a subverted compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    /// Produced by capacity we do not control. Held, but not usable for judging.
    Quarantined,
    /// Reproduced bit for bit by trusted capacity, or produced by it.
    Verified,
    /// Verified and recently used. A cache hint, never a trust upgrade.
    Hot,
}

impl TrustState {
    /// Whether an object in this state may be used to decide a verdict.
    pub fn usable_for_judging(self) -> bool {
        matches!(self, Self::Verified | Self::Hot)
    }

    /// Promote after independent reproduction.
    ///
    /// There is deliberately no way to promote from `Quarantined` other than
    /// through this function, and its name says what the caller must have done.
    pub fn promote_after_reproduction(self) -> Self {
        match self {
            Self::Quarantined | Self::Verified => Self::Verified,
            Self::Hot => Self::Hot,
        }
    }

    /// Mark as recently used. Never changes whether an object is trusted.
    pub fn touch(self) -> Self {
        match self {
            Self::Quarantined => Self::Quarantined,
            Self::Verified | Self::Hot => Self::Hot,
        }
    }
}

/// How widely an object may be distributed.
///
/// Verification protects integrity; this protects confidentiality. They are
/// different problems and conflating them is how hidden tests escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Distribution {
    /// Public immutable data. May go anywhere: CDN, peers, browser caches.
    Public,
    /// Private, but safe to distribute once encrypted client-side.
    EncryptedAtRest,
    /// Trusted storage only. Never reaches a peer, a CDN, or a browser.
    ///
    /// Hidden tests live here. So does unencrypted private source.
    TrustedOnly,
}

impl Distribution {
    /// Whether an object may be served to an arbitrary peer.
    pub fn may_serve_to_peers(self) -> bool {
        matches!(self, Self::Public | Self::EncryptedAtRest)
    }

    /// Whether an object may be placed on a public CDN.
    pub fn may_place_on_cdn(self) -> bool {
        matches!(self, Self::Public | Self::EncryptedAtRest)
    }
}

/// Everything recorded about an object beyond its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Where it came from.
    pub origin: Origin,
    /// How far it has got through verification.
    pub trust: TrustState,
    /// How widely it may travel.
    pub distribution: Distribution,
}

impl Provenance {
    /// A public object built here.
    pub fn built_public() -> Self {
        Self {
            origin: Origin::Built,
            trust: TrustState::Verified,
            distribution: Distribution::Public,
        }
    }

    /// An artifact produced by a volunteer: held, quarantined, still public.
    pub fn from_volunteer(peer: impl Into<String>) -> Self {
        Self {
            origin: Origin::Peer { id: peer.into() },
            trust: TrustState::Quarantined,
            distribution: Distribution::Public,
        }
    }

    /// Material that must never leave trusted infrastructure.
    pub fn trusted_only() -> Self {
        Self {
            origin: Origin::Local,
            trust: TrustState::Verified,
            distribution: Distribution::TrustedOnly,
        }
    }

    /// Whether this object may be handed to `peer`.
    pub fn may_share_with_peer(&self) -> bool {
        self.distribution.may_serve_to_peers()
    }

    /// Whether this object may decide a verdict.
    pub fn may_decide_a_verdict(&self) -> bool {
        self.trust.usable_for_judging()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_only_material_never_reaches_a_peer_or_a_cdn() {
        let provenance = Provenance::trusted_only();
        assert!(!provenance.may_share_with_peer());
        assert!(!provenance.distribution.may_place_on_cdn());
    }

    #[test]
    fn public_and_encrypted_material_may_be_distributed() {
        for distribution in [Distribution::Public, Distribution::EncryptedAtRest] {
            assert!(distribution.may_serve_to_peers(), "{distribution:?}");
            assert!(distribution.may_place_on_cdn(), "{distribution:?}");
        }
    }

    #[test]
    fn a_volunteer_artifact_is_held_but_cannot_decide_a_verdict() {
        let provenance = Provenance::from_volunteer("peer-7");
        assert_eq!(provenance.trust, TrustState::Quarantined);
        assert!(!provenance.may_decide_a_verdict());
        // It is still public: quarantine is about our confidence in the build,
        // not about who may see the bytes.
        assert!(provenance.may_share_with_peer());
    }

    #[test]
    fn quarantine_lifts_only_through_reproduction() {
        let quarantined = TrustState::Quarantined;
        assert!(!quarantined.usable_for_judging());

        // Touching is a cache hint. It must not launder a quarantined artifact
        // into a trusted one.
        assert_eq!(quarantined.touch(), TrustState::Quarantined);
        assert!(!quarantined.touch().usable_for_judging());

        assert_eq!(
            quarantined.promote_after_reproduction(),
            TrustState::Verified
        );
        assert!(TrustState::Verified.usable_for_judging());
    }

    #[test]
    fn hot_is_a_cache_state_not_a_trust_level() {
        assert_eq!(TrustState::Verified.touch(), TrustState::Hot);
        assert!(TrustState::Hot.usable_for_judging());
        assert_eq!(
            TrustState::Hot.promote_after_reproduction(),
            TrustState::Hot
        );
    }

    #[test]
    fn trust_states_order_from_least_to_most_usable() {
        assert!(TrustState::Quarantined < TrustState::Verified);
        assert!(TrustState::Verified < TrustState::Hot);
    }

    #[test]
    fn peer_origins_are_not_operator_controlled() {
        assert!(!Origin::Peer { id: "p".into() }.is_operator_controlled());
        for origin in [
            Origin::Local,
            Origin::Built,
            Origin::Seed { name: "b2".into() },
        ] {
            assert!(origin.is_operator_controlled(), "{origin:?}");
        }
    }

    #[test]
    fn provenance_round_trips_through_json() {
        for provenance in [
            Provenance::built_public(),
            Provenance::from_volunteer("peer-1"),
            Provenance::trusted_only(),
        ] {
            let json = serde_json::to_string(&provenance).unwrap();
            assert_eq!(
                serde_json::from_str::<Provenance>(&json).unwrap(),
                provenance
            );
        }
    }
}
