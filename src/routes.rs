//! The advertised-route SET: Go `netutil.CalcAdvertiseRoutes` (`net/netutil/routes.go`).
//!
//! `--advertise-routes` and `--advertise-exit-node` are two inputs to ONE outcome — the set of
//! prefixes this node tells control it can route. Go has exactly one function that turns the two
//! into that set, and it is where three rules live that a per-route check cannot express:
//!
//! 1. **A default route needs its other-family counterpart.** `0.0.0.0/0` without `::/0` (or the
//!    reverse) is refused. That is the rule that stops a HALF exit node: a node advertising only the
//!    v4 default takes v4 traffic from its clients, while their v6 traffic leaves straight out their
//!    own link — a leak neither end can see, because both ends believe the exit node is working.
//! 2. **A 4via6 prefix is validated as one** ([`validate_via_prefix`], Go `ValidateViaPrefix`):
//!    inside the Tailscale via range, at least a `/96`, and an embedded site id of `0xffff` or less.
//!    Without it a malformed via prefix is advertised as an ordinary IPv6 route that decodes to
//!    nothing.
//! 3. **It is a SET**: de-duplicated and sorted, with the exit-node intent folded in as the two
//!    default routes. That is why the questions above are asked of the set and not of one argument's
//!    literal text.
//!
//! This fork keeps `--advertise-exit-node` as its own pref (`Prefs::advertise_exit_node`) rather
//! than folding it into `Prefs::advertise_routes` the way Go folds it into `AdvertiseRoutes` — the
//! engine takes the two separately, and `check_prefs`' advertise-and-use conflict is asked of the
//! bool. So [`calc_advertise_routes`] takes the bool as its second argument, exactly as Go's
//! `CalcAdvertiseRoutes` does, and composes the set itself: the rules are then evaluated against
//! what the node will actually advertise, not against the flag's argument.
//!
//! Every caller in the daemon asks this module — `up`, `set`, `check-prefs`
//! ([`crate::ipn::Backend`]) and the `--config` loader ([`crate::conffile`]) — so the declarative
//! and interactive paths refuse the same route sets with the same words.

/// The Tailscale 4via6 range, `fd7a:115c:a1e0:b1a::/64` (Go `tsaddr.TailscaleViaRange`; mnemonic:
/// "b1a" sounds like "via"), as its leading 8 bytes. A 4via6 route packs an IPv4 CIDR plus a 32-bit
/// site id behind this prefix so several subnet routers can advertise the *same* private IPv4 space
/// without colliding: `[0..8]` via range, `[8..12]` site id, `[12..16]` the IPv4 address.
pub const VIA_RANGE_PREFIX: [u8; 8] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x0b, 0x1a];

/// `0.0.0.0/0` (Go `tsaddr.AllIPv4`).
pub fn all_ipv4() -> ipnet::IpNet {
    ipnet::IpNet::V4(
        ipnet::Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
            .expect("0 is a valid v4 prefix len"),
    )
}

/// `::/0` (Go `tsaddr.AllIPv6`).
pub fn all_ipv6() -> ipnet::IpNet {
    ipnet::IpNet::V6(
        ipnet::Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 0)
            .expect("0 is a valid v6 prefix len"),
    )
}

/// Whether `p`'s address sits in the Tailscale via range (Go `tsaddr.IsViaPrefix`, which tests
/// `TailscaleViaRange().Contains(p.Addr())` — the ADDRESS, not the whole prefix, so a too-short
/// prefix whose base is in the range is still "a via prefix" and is then refused BY
/// [`validate_via_prefix`] rather than quietly treated as an ordinary route).
pub fn is_via_prefix(p: &ipnet::IpNet) -> bool {
    match p {
        ipnet::IpNet::V6(v6) => v6.addr().octets()[0..8] == VIA_RANGE_PREFIX,
        ipnet::IpNet::V4(_) => false,
    }
}

/// Go `netutil.ValidateViaPrefix`: a 4via6 prefix must be in the via range, be at least a `/96` (64
/// bits of via range + 32 bits of site id, leaving the low 32 for the IPv4 address), and embed a site
/// id of `0xffff` or less. Messages are Go's verbatim, because an operator who searches for one
/// should find the same answer for either implementation.
///
/// A shorter prefix than `/96` does not *contain* a site id at all, so it cannot be decoded back to
/// the `(site, IPv4 CIDR)` pair the feature is; a site id above `0xffff` is outside the documented
/// 16-bit site space (Go relaxed it from 8 to 16 bits in 2024 and no further).
pub fn validate_via_prefix(p: &ipnet::IpNet) -> Result<(), String> {
    if !is_via_prefix(p) {
        return Err(format!("{p} is not a 4-in-6 prefix"));
    }
    if p.prefix_len() < 96 {
        return Err(format!("{p} 4-in-6 prefix must be at least a /96"));
    }
    let octets = match p {
        ipnet::IpNet::V6(v6) => v6.addr().octets(),
        // Unreachable: `is_via_prefix` above is false for every v4 prefix.
        ipnet::IpNet::V4(_) => return Err(format!("{p} is not a 4-in-6 prefix")),
    };
    let site_id = u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]);
    if site_id > 0xffff {
        return Err(format!(
            "route {p} contains invalid site ID {site_id:08x}; must be 0xffff or less"
        ));
    }
    Ok(())
}

/// One reason a route set cannot be advertised. Carries the offending value rather than only a
/// string so a caller can tell the kinds apart (the `--config` loader prefixes its own messages);
/// [`Display`](std::fmt::Display) renders Go's wording, which is what every current caller wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// Not an IP prefix at all. Go gets this for free — its `AdvertiseRoutes` is a
    /// `[]netip.Prefix` — but this fork stores the operator's strings, so it is a rule here.
    Unparsable(String),
    /// A prefix with host bits set, e.g. `192.0.2.5/24`: accepted by the parser, and *not* what the
    /// operator meant. `masked` is the prefix they did mean.
    NonMasked {
        /// The route exactly as the operator wrote it.
        route: String,
        /// The same route with its host bits cleared — the value to use instead.
        masked: ipnet::IpNet,
    },
    /// A malformed 4via6 prefix ([`validate_via_prefix`]); the message is Go's, verbatim.
    Via(String),
    /// A default route advertised in one family only — the half-exit-node leak.
    LoneDefault {
        /// The default route that IS in the set.
        have: ipnet::IpNet,
        /// The other family's default route, which must be advertised with it.
        want: ipnet::IpNet,
    },
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Go: `fmt.Errorf("%q is not a valid IP address or CIDR prefix", s)`.
            Self::Unparsable(route) => {
                write!(f, "{route:?} is not a valid IP address or CIDR prefix")
            }
            // Go: `fmt.Errorf("%s has non-address bits set; expected %s", ipp, ipp.Masked())`. The
            // leading "route " is this fork's, kept from the check this replaces so the message an
            // operator already knows does not change under them.
            Self::NonMasked { route, masked } => {
                write!(
                    f,
                    "route {route} has non-address bits set; expected {masked}"
                )
            }
            Self::Via(msg) => f.write_str(msg),
            // Go: `fmt.Errorf("%s advertised without its IPv6 counterpart, please also advertise
            // %s", tsaddr.AllIPv4(), tsaddr.AllIPv6())`, and the mirror for the reverse.
            Self::LoneDefault { have, want } => {
                let family = if want.addr().is_ipv6() {
                    "IPv6"
                } else {
                    "IPv4"
                };
                write!(
                    f,
                    "{have} advertised without its {family} counterpart, please also advertise {want}"
                )
            }
        }
    }
}

/// Go `netutil.CalcAdvertiseRoutes`: turn the raw `--advertise-routes` strings plus the
/// `--advertise-exit-node` intent into the de-duplicated, sorted set of prefixes this node will
/// advertise — or EVERY reason it cannot.
///
/// Go returns on the first bad route. This returns all of them, because the daemon's callers report
/// to a headless operator: a `--config` boot or a `check-prefs` dry run should learn about every bad
/// route in one answer instead of one per restart. Within a single route the checks are still Go's,
/// in Go's order and one-per-route — a non-masked prefix reports the masking error only, exactly as
/// Go's early return does, so nobody gets told about a site id in a prefix they wrote wrong.
///
/// The pairing rule (rule 1) is asked of the COMPOSED set, i.e. after `advertise_exit_node` has
/// contributed its two default routes. Go asks it of the flag's argument *before* folding the
/// exit-node flag in, and so refuses `--advertise-routes=0.0.0.0/0 --advertise-exit-node`; here that
/// combination advertises both defaults, which is what the operator asked for, so the question is
/// asked of the outcome. Every lone default route is still refused, in Go's words.
///
/// Sorting is Go's comparator (prefix length, then address), so the set this returns is ordered the
/// way Go orders what it sends to control.
pub fn calc_advertise_routes(
    advertise_routes: &[String],
    advertise_exit_node: bool,
) -> Result<Vec<ipnet::IpNet>, Vec<RouteError>> {
    let mut errors: Vec<RouteError> = Vec::new();
    let mut set: Vec<ipnet::IpNet> = Vec::new();
    let (mut default4, mut default6) = (false, false);

    for s in advertise_routes {
        let Ok(net) = s.parse::<ipnet::IpNet>() else {
            errors.push(RouteError::Unparsable(s.clone()));
            continue;
        };
        let masked = net.trunc();
        if masked != net {
            errors.push(RouteError::NonMasked {
                route: s.clone(),
                masked,
            });
            continue;
        }
        // Go asks `IsViaPrefix` first and only then `ValidateViaPrefix`, so a prefix outside the via
        // range is never told it "is not a 4-in-6 prefix" — it simply is not one.
        if is_via_prefix(&net)
            && let Err(msg) = validate_via_prefix(&net)
        {
            errors.push(RouteError::Via(msg));
            continue;
        }
        if net == all_ipv4() {
            default4 = true;
        } else if net == all_ipv6() {
            default6 = true;
        }
        set.push(net);
    }

    // `--advertise-exit-node` IS the two default routes (Go folds it in as exactly that), so it
    // satisfies the pairing rule rather than being exempt from it.
    if advertise_exit_node {
        default4 = true;
        default6 = true;
        set.push(all_ipv4());
        set.push(all_ipv6());
    }

    if default4 != default6 {
        let (have, want) = if default4 {
            (all_ipv4(), all_ipv6())
        } else {
            (all_ipv6(), all_ipv4())
        };
        errors.push(RouteError::LoneDefault { have, want });
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // A SET: de-duplicate (Go uses a map keyed by prefix), then sort by prefix length and then by
    // address — Go's `sort.Slice` comparator in `CalcAdvertiseRoutes`. `IpNet`'s own `Ord` compares
    // the network address first and the prefix length only to break a tie, which is a different
    // order; this is spelled out so the set matches what Go sends.
    set.sort_by(|a, b| {
        a.prefix_len()
            .cmp(&b.prefix_len())
            .then_with(|| a.addr().cmp(&b.addr()))
    });
    set.dedup();
    Ok(set)
}

/// [`calc_advertise_routes`] with its errors rendered as the one message a caller returns: Go's
/// wording, one reason per line (the daemon's convention for a multi-rule refusal, as in
/// `Backend::check_prefs`). `Ok` discards the set — the callers that only need the verdict.
pub fn validate_advertise_routes(
    advertise_routes: &[String],
    advertise_exit_node: bool,
) -> anyhow::Result<()> {
    calc_advertise_routes(advertise_routes, advertise_exit_node)
        .map(|_| ())
        .map_err(|errs| {
            anyhow::anyhow!(
                errs.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// The rule the bead is about: a lone v4 default is a half exit node, and is refused with Go's
    /// message naming the counterpart to add.
    #[test]
    fn lone_v4_default_is_refused() {
        let err = validate_advertise_routes(&routes(&["0.0.0.0/0"]), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0"
        );
    }

    /// The mirror: a lone v6 default asks for the v4 one.
    #[test]
    fn lone_v6_default_is_refused() {
        let err = validate_advertise_routes(&routes(&["::/0"]), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "::/0 advertised without its IPv4 counterpart, please also advertise 0.0.0.0/0"
        );
    }

    /// Both defaults together are an exit node spelled the long way: accepted, and the set is the
    /// two of them in Go's order (equal prefix length → v4 address sorts first).
    #[test]
    fn both_defaults_together_are_accepted() {
        let set = calc_advertise_routes(&routes(&["::/0", "0.0.0.0/0"]), false).unwrap();
        assert_eq!(set, vec![all_ipv4(), all_ipv6()]);
    }

    /// `--advertise-exit-node` IS both defaults, so it satisfies the pairing rule on its own and
    /// also satisfies it for a route list that named only the v4 default.
    #[test]
    fn advertise_exit_node_supplies_both_defaults() {
        assert_eq!(
            calc_advertise_routes(&[], true).unwrap(),
            vec![all_ipv4(), all_ipv6()]
        );
        let set = calc_advertise_routes(&routes(&["0.0.0.0/0", "192.0.2.0/24"]), true).unwrap();
        assert_eq!(
            set,
            vec![
                all_ipv4(),
                all_ipv6(),
                "192.0.2.0/24".parse::<ipnet::IpNet>().unwrap()
            ],
            "the duplicated v4 default collapses; the set is sorted by prefix length"
        );
    }

    /// Turning the exit-node pref OFF while the route list still names one default is the same leak,
    /// and is refused the same way — the rule is a property of the composed set, not of one flag.
    #[test]
    fn exit_node_off_leaves_a_lone_default_refused() {
        let err = validate_advertise_routes(&routes(&["0.0.0.0/0"]), false).unwrap_err();
        assert!(err.to_string().contains("please also advertise ::/0"));
        assert!(
            validate_advertise_routes(&routes(&["0.0.0.0/0"]), true).is_ok(),
            "with the exit-node pref on, both defaults are advertised"
        );
    }

    /// Ordinary subnet routes do not involve the rule at all.
    #[test]
    fn subnet_routes_are_unaffected() {
        let set = calc_advertise_routes(
            &routes(&["192.0.2.0/24", "198.51.100.0/25", "10.0.0.0/8"]),
            false,
        )
        .unwrap();
        assert_eq!(
            set,
            vec![
                "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
                "192.0.2.0/24".parse::<ipnet::IpNet>().unwrap(),
                "198.51.100.0/25".parse::<ipnet::IpNet>().unwrap(),
            ],
            "sorted by prefix length, then address"
        );
    }

    /// A duplicate is not a second route (Go keys a map by prefix).
    #[test]
    fn duplicates_collapse() {
        let set = calc_advertise_routes(&routes(&["192.0.2.0/24", "192.0.2.0/24"]), false).unwrap();
        assert_eq!(set, vec!["192.0.2.0/24".parse::<ipnet::IpNet>().unwrap()]);
    }

    /// The masking rule, now asked by this one function for every caller.
    #[test]
    fn non_masked_route_is_refused() {
        let err = validate_advertise_routes(&routes(&["192.0.2.5/24"]), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "route 192.0.2.5/24 has non-address bits set; expected 192.0.2.0/24"
        );
    }

    /// An unparsable entry names itself, in Go's words.
    #[test]
    fn unparsable_route_is_refused() {
        let err = validate_advertise_routes(&routes(&["not-a-cidr"]), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "\"not-a-cidr\" is not a valid IP address or CIDR prefix"
        );
    }

    /// Every reason is reported in one answer — a headless boot should not need one restart per bad
    /// route — and each route reports ONE reason: the non-masked via prefix reports the masking
    /// error only, as Go's early return does.
    #[test]
    fn every_reason_is_reported_once_each() {
        let err = validate_advertise_routes(
            &routes(&[
                "nope",
                "192.0.2.5/24",
                "fd7a:115c:a1e0:b1a::1/48",
                "0.0.0.0/0",
            ]),
            false,
        )
        .unwrap_err();
        let reported = err.to_string();
        let lines: Vec<&str> = reported.lines().collect();
        assert_eq!(
            lines,
            vec![
                "\"nope\" is not a valid IP address or CIDR prefix",
                "route 192.0.2.5/24 has non-address bits set; expected 192.0.2.0/24",
                "route fd7a:115c:a1e0:b1a::1/48 has non-address bits set; expected fd7a:115c:a1e0::/48",
                "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0",
            ]
        );
    }

    /// A 4via6 prefix too short to carry a site id is refused as a via prefix, not accepted as an
    /// ordinary IPv6 route (Go `ValidateViaPrefix`, verbatim message).
    #[test]
    fn via_prefix_shorter_than_96_is_refused() {
        let err =
            validate_advertise_routes(&routes(&["fd7a:115c:a1e0:b1a::/64"]), false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fd7a:115c:a1e0:b1a::/64 4-in-6 prefix must be at least a /96"
        );
    }

    /// A site id above 0xffff is outside the documented 16-bit site space.
    #[test]
    fn via_prefix_with_oversized_site_id_is_refused() {
        // site id 0x00010000 lives in bytes 8..12: `…:b1a:1:0:…`.
        let err =
            validate_advertise_routes(&routes(&["fd7a:115c:a1e0:b1a:1:0:c000:200/128"]), false)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route fd7a:115c:a1e0:b1a:1:0:c000:200/128 contains invalid site ID 00010000; must be \
             0xffff or less"
        );
    }

    /// A well-formed 4via6 route — site 7, `192.0.2.0/24` — is accepted.
    #[test]
    fn well_formed_via_route_is_accepted() {
        let set = calc_advertise_routes(&routes(&["fd7a:115c:a1e0:b1a:0:7:c000:200/120"]), false)
            .unwrap();
        assert_eq!(
            set,
            vec![
                "fd7a:115c:a1e0:b1a:0:7:c000:200/120"
                    .parse::<ipnet::IpNet>()
                    .unwrap()
            ]
        );
    }

    /// [`validate_via_prefix`] called directly on a non-via prefix gives Go's first message; this is
    /// the one branch `calc_advertise_routes` never reaches (it asks `is_via_prefix` first).
    #[test]
    fn validate_via_prefix_rejects_a_non_via_prefix() {
        let p: ipnet::IpNet = "2001:db8::/96".parse().unwrap();
        assert_eq!(
            validate_via_prefix(&p).unwrap_err(),
            "2001:db8::/96 is not a 4-in-6 prefix"
        );
        assert!(!is_via_prefix(&p));
        assert!(!is_via_prefix(
            &"192.0.2.0/24".parse::<ipnet::IpNet>().unwrap()
        ));
    }

    /// No routes and no exit node is the empty set, not an error.
    #[test]
    fn empty_input_is_the_empty_set() {
        assert!(calc_advertise_routes(&[], false).unwrap().is_empty());
    }
}
