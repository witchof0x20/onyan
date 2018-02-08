use std::io::BufRead;
use std::str::from_str;
use nom::alphanumeric;
/// Spec defined at https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt
/// Votes and consensuses are more strictly formatted than other documents
/// in this specification, since different authorities must be able to
/// generate exactly the same consensus given the same set of votes.
/// The procedure for deciding when to generate vote and consensus status
/// documents are described in section 1.4 on the voting timeline.
/// Status documents contain a preamble, an authority section, a list of
/// router status entries, and one or more footer signature, in that order.
/// Unlike other formats described above, a SP in these documents must be a
/// single space character (hex 20).
/// Some items appear only in votes, and some items appear only in
/// consensuses.  Unless specified, items occur in both.
/// The preamble contains the following items.  They SHOULD occur in the
/// order given here:
struct ConsensusDocument {
    /// A document format version.  For this specification, the version is "3".
    /// [At start, exactly once.]
    network_status_version: i32,
    /// The status MUST be "vote" or "consensus", depending on the type of the document.
    /// [Exactly once.]
    vote_status: String,
    /// A space-separated list of supported methods for generating
    /// consensuses from votes.  See section 3.8.1 for details.  Absence of
    /// the line means that only method "1" is supported.
    /// [At most once for votes; does not occur in consensuses.]
    consensus_methods: Option<Vec<i32>>,
    /// See section 3.8.1 for details.
    /// (Only included when the vote is generated with consensus-method 2 or later.)
    /// [At most once for consensuses; does not occur in votes.]
    /// [No extra arguments]
    consensus_method: Option<i32>,
    /// The publication time for this status document (if a vote).
    /// [Exactly once for votes; does not occur in consensuses.]
    /// YYYY-MM-DD SP HH:MM:SS
    published: String,
    /// The start of the Interval for this vote.  Before this time, the
    /// consensus document produced from this vote should not be used.
    /// See section 1.4 for voting timeline information.
    /// [Exactly once.]
    /// YYYY-MM-DD SP HH:MM:SS
    valid_after: String,
    /// The time at which the next consensus should be produced; before this
    /// time, there is no point in downloading another consensus, since there
    /// won't be a new one.  See section 1.4 for voting timeline information.
    /// [Exactly once.]
    /// YYYY-MM-DD SP HH:MM:SS
    fresh_until: String,
    /// The end of the Interval for this vote.  After this time, the
    /// consensus produced by this vote should not be used.  See section 1.4
    /// for voting timeline information.
    /// [Exactly once.]
    /// YYYY-MM-DD SP HH:MM:SS
    valid_until: String,
    /// VoteSeconds is the number of seconds that we will allow to collect
    /// votes from all authorities
    /// See section 1.4 for voting timeline information.
    /// [Exactly once.]
    /// Part of the voting-delay field
    /// VoteSeconds DistSeconds
    vote_seconds: i32,
    /// DistSeconds is the number of seconds
    /// we'll allow to collect signatures from all authorities.
    /// [Exactly once.]
    /// Part of the voting-delay field
    dist_seconds: i32,
    /// A comma-separated list of recommended Tor versions for client
    /// usage, in ascending order. The versions are given as defined by
    /// version-spec.txt. If absent, no opinion is held about client
    /// versions.
    /// [At most once.]
    client_versions: Option<Vec<String>>,
    /// A comma-separated list of recommended Tor versions for relay
    /// usage, in ascending order. The versions are given as defined by
    /// version-spec.txt. If absent, no opinion is held about server
    /// versions.
    /// [At most once.]
    server_versions: Option<Vec<String>>,
    /// Indicates that a package called "package" of version VERSION may be
    /// found at URL, and its digest as computed with DIGESTTYPE is equal to
    /// DIGESTVAL.  In consensuses, these lines are sorted lexically by
    /// "PACKAGENAME VERSION" pairs, and DIGESTTYPES must appear in ascending
    /// order.  A consensus must not contain the same "PACKAGENAME VERSION"
    /// more than once.  If a vote contains the same "PACKAGENAME VERSION"
    /// more than once, all but the last is ignored.
    /// For this element:
    /// PACKAGENAME = NONSPACE
    /// VERSION = NONSPACE
    /// URL = NONSPACE
    /// DIGESTS = DIGEST | DIGESTS SP DIGEST
    /// DIGEST = DIGESTTYPE "=" DIGESTVAL
    /// NONSPACE = one or more non-space printing characters
    /// DIGESTVAL = DIGESTTYPE = one or more non-space printing characters
    /// other than "=".
    /// Included in consensuses only for method 19 and later.
    /// [Any number of times.]
    package: Vec<Digest>,
    /// A space-separated list of all of the flags that this document
    /// might contain.  A flag is "known" either because the authority
    /// knows about them and might set them (if in a vote), or because
    /// enough votes were counted for the consensus for an authoritative
    /// opinion to have been formed about their status.
    /// [Exactly once.]
    known_flags: Vec<String>,
    /// A space-separated list of the internal performance thresholds
    /// that the directory authority had at the moment it was forming
    /// a vote.
    /// [At most once for votes; does not occur in consensuses.]
    ///
    /// The metaformat is:
    ///    Thresholds = Threshold | Threshold SP Thresholds
    ///    Threshold = ThresholdKey '=' ThresholdVal
    ///    ThresholdKey = (KeywordChar | "_") +
    ///    ThresholdVal = [0-9]+("."[0-9]+)? "%"?
    ///
    /// Commonly used Thresholds at this point include:
    ///
    /// "stable-uptime" -- Uptime (in seconds) required for a relay
    ///                    to be marked as stable.
    ///
    /// "stable-mtbf" -- MTBF (in seconds) required for a relay to be
    ///                  marked as stable.
    ///
    /// "enough-mtbf" -- Whether we have measured enough MTBF to look
    ///                  at stable-mtbf instead of stable-uptime.
    ///
    /// "fast-speed" -- Bandwidth (in bytes per second) required for
    ///                 a relay to be marked as fast.
    ///
    /// "guard-wfu" -- WFU (in seconds) required for a relay to be
    ///                marked as guard.
    ///
    /// "guard-tk" -- Weighted Time Known (in seconds) required for a
    ///               relay to be marked as guard.
    ///
    /// "guard-bw-inc-exits" -- If exits can be guards, then all guards
    ///                         must have a bandwidth this high.
    ///
    /// "guard-bw-exc-exits" -- If exits can't be guards, then all guards
    ///                         must have a bandwidth this high.
    ///
    /// "ignoring-advertised-bws" -- 1 if we have enough measured bandwidths
    ///                         that we'll ignore the advertised bandwidth
    ///                         claims of routers without measured bandwidth.
    flag_thresholds: Vec<Threshold>,
    /// The "proto" element as specified in section 2.1.1.
    ///
    /// To vote on these entries, a protocol/version combination is included
    /// only if it is listed by a majority of the voters.
    ///
    /// These lines should be voted on.  A majority of votes is sufficient to
    /// make a protocol un-supported. and should require a supermajority of
    /// authorities (2/3) to make a protocol required.  The required protocols
    /// should not be torrc-configurable, but rather should be hardwired in
    /// the Tor code.
    ///
    /// The tor-spec.txt section 9 details how a relay and a client should
    /// behave when they encounter these lines in the consensus.
    /// [At most once for each.]
    recommended_client_protocols: Vec<Entry>,
    recommended_relay_protocols: Vec<Entry>,
    required_client_protocols: Vec<Entry>,
    required_relay_protocols: Vec<Entry>,

    /// The parameters list, if present, contains a space-separated list of
    /// case-sensitive key-value pairs, sorted in lexical order by their
    /// keyword (as ASCII byte strings). Each parameter has its own meaning.

    /// [At most once]
    /// (Only included when the vote is generated with consensus-method 7 or
    /// later.)

    /// Commonly used "param" arguments at this point include:

    /// "circwindow" -- the default package window that circuits should
    /// be established with. It started out at 1000 cells, but some
    /// research indicates that a lower value would mean fewer cells in
    /// transit in the network at any given time.
    /// Min: 100, Max: 1000
    /// First-appeared: Tor 0.2.1.20

    /// "CircuitPriorityHalflifeMsec" -- the halflife parameter used when
    /// weighting which circuit will send the next cell. Obeyed by Tor
    /// 0.2.2.10-alpha and later.  (Versions of Tor between 0.2.2.7-alpha
    /// and 0.2.2.10-alpha recognized a "CircPriorityHalflifeMsec" parameter,
    /// but mishandled it badly.)
    /// Min: -1, Max: 2147483647 (INT32_MAX)
    /// First-appeared: Tor 0.2.2.11-alpha

    /// "perconnbwrate" and "perconnbwburst" -- if set, each relay sets
    /// up a separate token bucket for every client OR connection,
    /// and rate limits that connection indepedently. Typically left
    /// unset, except when used for performance experiments around trac
    /// entry 1750. Only honored by relays running Tor 0.2.2.16-alpha
    /// and later. (Note that relays running 0.2.2.7-alpha through
    /// 0.2.2.14-alpha looked for bwconnrate and bwconnburst, but then
    /// did the wrong thing with them; see bug 1830 for details.)
    /// Min: 1, Max: 2147483647 (INT32_MAX)
    /// First-appeared: 0.2.2.7-alpha
    /// Removed-in: 0.2.2.16-alpha

    /// "refuseunknownexits" -- if set to one, exit relays look at
    /// the previous hop of circuits that ask to open an exit stream,
    /// and refuse to exit if they don't recognize it as a relay. The
    /// goal is to make it harder for people to use them as one-hop
    /// proxies. See trac entry 1751 for details.
    /// Min: 0, Max: 1
    /// First-appeared: 0.2.2.17-alpha

    /// "bwweightscale" -- Value that bandwidth-weights are divided by. If not
    /// present then this defaults to 10000.
    /// Min: 1
    /// First-appeared: 0.2.2.10-alpha

    /// "cbtdisabled", "cbtnummodes", "cbtrecentcount", "cbtmaxtimeouts",
    /// "cbtmincircs", "cbtquantile", "cbtclosequantile", "cbttestfreq",
    /// "cbtmintimeout", and "cbtinitialtimeout" -- see "2.4.5. Consensus
    /// parameters governing behavior" in path-spec.txt for a series of
    /// circuit build time related consensus params.

    /// "UseOptimisticData" -- If set to zero, clients by default
    /// shouldn't try to send optimistic data to servers until they have
    /// received a RELAY_CONNECTED cell.
    /// Min: 0, Max: 1, Default: 1
    /// First-appeared: 0.2.3.3-alpha
    /// Default was 0 before: 0.2.9.1-alpha

    /// "maxunmeasuredbw" -- Used by authorities during voting with
    /// method 17 or later. The maximum value to give for any Bandwidth=
    /// entry for a router that isn't based on at least three
    /// measurements.
    /// First-appeared: 0.2.4.11-alpha

    /// "Support022HiddenServices" -- Used to implement a mass switch-over
    /// from sending timestamps to hidden services by default to sending
    /// no timestamps at all.  If this option is absent, or is set to 1,
    /// clients with the default configuration send timestamps; otherwise,
    /// they do not.
    /// Min: 0, Max: 1. Default: 1.
    /// First-appeared: 0.2.4.18-rc

    /// "usecreatefast" -- Used to control whether clients use the
    /// CREATE_FAST handshake on the first hop of their circuits.
    /// Min: 0, Max: 1. Default: 1.
    /// First-appeared: 0.2.4.23, 0.2.5.2-alpha

    /// "pb_mincircs", "pb_noticepct", "pb_warnpct", "pb_extremepct",
    /// "pb_dropguards", "pb_scalecircs", "pb_scalefactor",
    /// "pb_multfactor", "pb_minuse", "pb_noticeusepct",
    /// "pb_extremeusepct", "pb_scaleuse" -- DOCDOC

    /// "UseNTorHandshake" -- If true, then versions of Tor that support
    ///   NTor will prefer to use it by default.
    /// Min: 0,  Max: 1. Default: 1.
    /// First-appeared: 0.2.4.8-alpha

    /// "FastFlagMinThreshold", "FastFlagMaxThreshold" -- lowest and
    /// highest allowable values for the cutoff for routers that should get
    /// the Fast flag.  This is used during voting to prevent the threshold
    /// for getting the Fast flag from being too low or too high.
    /// FastFlagMinThreshold: Min: 4. Max: INT32_MAX: Default: 4.
    /// FastFlagMaxThreshold: Min: -. Max: INT32_MAX: Default: INT32_MAX
    /// First-appeared: 0.2.3.11-alpha

    /// "NumDirectoryGuards", "NumEntryGuards" -- Number of guard nodes
    /// clients should use by default.  If NumDirectoryGuards is 0,
    /// we default to NumEntryGuards.
    /// NumDirectoryGuards: Min: 0. Max: 10. Default: 0
    /// NumEntryGuards:     Min: 1. Max: 10. Default: 3
    /// First-appeared: 0.2.4.23, 0.2.5.6-alpha

    /// "GuardLifetime" -- Duration for which clients should choose guard
    /// nodes, in seconds.
    /// Min: 30 days.  Max: 1826 days.  Default: 60 days.
    /// First-appeared: 0.2.4.12-alpha

    /// "min_paths_for_circs_pct" -- DOCDOC

    /// "NumNTorsPerTAP" -- When balancing ntor and TAP cells at relays,
    /// how many ntor handshakes should we perform for each TAP handshake?
    /// Min: 1. Max: 100000. Default: 10.
    /// First-appeared: 0.2.4.17-rc

    /// "AllowNonearlyExtend" -- If true, permit EXTEND cells that are not
    /// inside RELAY_EARLY cells.
    /// Min: 0. Max: 1. Default: 0.
    /// First-appeared: 0.2.3.11-alpha

    /// "AuthDirNumSRVAgreements" -- Minimum number of agreeing directory
    /// authority votes required for a fresh shared random value to be written
    /// in the consensus (this rule only applies on the first commit round of
    /// the shared randomness protocol).
    /// Min: 1. Max: INT32_MAX. Default: 2/3 of the total number of
    /// dirauth.

    /// "max-consensuses-age-to-cache-for-diff" -- Determines how
    /// much consensus history (in hours) relays should try to cache
    /// in order to serve diffs.  (min 0, max 8192, default 72)

    /// "try-diff-for-consensus-newer-than" -- This parameter
    /// determines how old a consensus can be (in hours) before a
    /// client should no longer try to find a diff for it.  (min 0,
    /// max 8192, default 72)

    /// onion key lifetime parameters:
    ///     "onion-key-rotation-days" -- (min 1, max 90, default 28)
    ///     "onion-key-grace-period-days" -- (min 1, max
    ///                          onion-key-rotation-days, default 7)
    /// Every relay should list each onion key it generates for
    /// onion-key-rotation-days days after generating it, and then
    /// replace it.  Relays should continue to accept their most recent
    /// previous onion key for an additional onion-key-grace-period-days
    /// days after it is replaced.  (Introduced in 0.3.1.1-alpha;
    /// prior versions of tor hardcoded both of these values to 7 days.)

    /// Hidden service v3 parameters:
    ///  "hs_intro_min_introduce2"
    ///  "hs_intro_max_introduce2" -- Minimum/maximum amount of INTRODUCE2 cells
    ///                               allowed per circuits before rotation (actual
    ///                               amount picked at random between these two values).
    ///  "hs_intro_min_lifetime"
    ///  "hs_intro_max_lifetime"   -- Minimum/maximum lifetime in seconds that a service
    ///                               should keep an intro point for (actual lifetime picked at
    ///                               random between these two values).
    ///  "hs_intro_num_extra"      -- Number of extra intro points a service is allowed to open.
    ///                               This concept comes from proposal #155.
    ///  "hsdir_interval"          -- The length of a time period. See rend-spec-v3.txt
    ///                               section [TIME-PERIODS].
    ///  "hsdir_n_replicas"        -- Number of HS descriptor replicas.
    ///  "hsdir_spread_fetch"      -- Total number of HSDirs per replica a tor client
    ///                               should select to try to fetch a descriptor.
    ///  "hsdir_spread_store"      -- Total number of HSDirs per replica a service
    ///                               will upload its descriptor to.
    ///  "HSV3MaxDescriptorSize"   -- Maximum descriptor size (in bytes).

    /// "hs_service_max_rdv_failures" -- This parameter determines the maximum
    /// number of rendezvous attempt an HS service can make per introduction.
    /// Min 1. Max 10. Default 2.
    /// First-appeared: 0.3.3.0-alpha.
    params: Vec<Param>,
    /// The shared random value that was generated during the second-to-last
    /// shared randomness protocol run. For example, if this document was
    /// created on the 5th of November, this field carries the shared random
    /// value generated during the protocol run of the 3rd of November.
    ///
    /// [At most once]
    /// NumReveals ::= An integer greater or equal to 0.
    /// Value ::= Base64-encoded-data
    /// See section [SRCALC] of srv-spec.txt for instructions on how to compute
    /// this value, and see section [CONS] for why we include old shared random
    /// values in votes and consensus.
    /// Value is the actual shared random value encoded in base64. NumReveals
    /// is the number of commits used to generate this SRV.
    shared_rand_previous_value: (i32, Vec<u8>),
    /// The shared random value that was generated during the latest shared
    /// randomness protocol run. For example, if this document was created on
    /// the 5th of November, this field carries the shared random value
    /// generated during the protocol run of the 4th of November
    ///
    /// [At most once]
    /// NumReveals ::= An integer greater or equal to 0.
    /// Value ::= Base64-encoded-data
    /// See section [SRCALC] of srv-spec.txt for instructions on how to compute
    /// this value given the active commits.
    /// Value is the actual shared random value encoded in base64. NumReveals
    /// is the number of commits used to generate this SRV.
    shared_rand_current_value: (i32, Vec<u8>),
    /// The authority section of a vote contains the following items, followed
    /// in turn by the authority's current key certificate:
    /// "dir-source" SP nickname SP identity SP address SP IP SP dirport SP
    ///    orport NL
    ///     [Exactly once, at start]

    ///     Describes this authority.  The nickname is a convenient identifier
    ///     for the authority.  The identity is an uppercase hex fingerprint of
    ///     the authority's current (v3 authority) identity key.  The address is
    ///     the server's hostname.  The IP is the server's current IP address,
    ///     and dirport is its current directory port.  The orport is the
    ///     port at that address where the authority listens for OR
    ///     connections.
    /// "contact" SP string NL
    ///     [Exactly once]
    ///     An arbitrary string describing how to contact the directory
    ///     server's administrator.  Administrators should include at least an
    ///     email address and a PGP fingerprint.
    /// "legacy-dir-key" SP FINGERPRINT NL
    ///     [At most once]
    ///     Lists a fingerprint for an obsolete _identity_ key still used
    ///     by this authority to keep older clients working.  This option
    ///     is used to keep key around for a little while in case the
    ///     authorities need to migrate many identity keys at once.
    ///     (Generally, this would only happen because of a security
    ///     vulnerability that affected multiple authorities, like the
    ///     Debian OpenSSL RNG bug of May 2008.)
    /// "shared-rand-participate" NL
    ///     [At most once]
    ///     Denotes that the directory authority supports and can participate in the
    ///     shared random protocol.
    /// "shared-rand-commit" SP Version SP AlgName SP Identity SP Commit [SP Reveal] NL
    ///     [Any number of times]
    ///     Version ::= An integer greater or equal to 0.
    ///     AlgName ::= 1*(ALPHA / DIGIT / "_" / "-")
    ///     Identity ::= 40 * HEXDIG
    ///     Commit ::= Base64-encoded-data
    ///     Reveal ::= Base64-encoded-data
    ///     Denotes a directory authority commit for the shared randomness
    ///     protocol, containing the commitment value and potentially also the
    ///     reveal value. See sections [COMMITREVEAL] and [VALIDATEVALUES] of
    ///     srv-spec.txt on how to generate and validate these values.
    ///     Version is the current shared randomness protocol version. AlgName is
    ///     the hash algorithm that is used (e.g. "sha3-256") and Identity is the
    ///     authority's SHA1 v3 identity fingerprint. Commit is the encoded
    ///     commitment value in base64. Reveal is optional and if it's set, it
    ///     contains the reveal value in base64.
    ///     If a vote contains multiple commits from the same authority, the
    ///     receiver MUST only consider the first commit listed.
    /// "shared-rand-previous-value" SP NumReveals SP Value NL
    ///     [At most once]
    ///     See shared-rand-previous-value description above.
    /// "shared-rand-current-value" SP NumReveals SP Value NL
    ///     [At most once]
    ///     See shared-rand-current-value decription above.
    /// The authority section of a consensus contains groups the following items,
    /// in the order given, with one group for each authority that contributed to
    /// the consensus, with groups sorted by authority identity digest:
    /// "dir-source" SP nickname SP identity SP address SP IP SP dirport SP
    ///    orport NL
    ///     [Exactly once, at start]
    ///     As in the authority section of a vote.
    /// "contact" SP string NL
    ///     [Exactly once.]
    ///     As in the authority section of a vote.
    /// "vote-digest" SP digest NL
    ///     [Exactly once.]
    ///     A digest of the vote from the authority that contributed to this
    ///     consensus, as signed (that is, not including the signature).
    ///     (Hex, upper-case.)
    ///
    /// For each "legacy-dir-key" in the vote, there is an additional "dir-source"
    /// line containing that legacy key's fingerprint, the authority's nickname
    /// with "-legacy" appended, and all other fields as in the main "dir-source"
    /// line for that authority.  These "dir-source" lines do not have
    /// corresponding "contact" or "vote-digest" entries.
    authorities: Vec<Authority>,
    ///    Each router status entry contains the following items.  Router status
    ///    entries are sorted in ascending order by identity digest.
    ///
    ///     "r" SP nickname SP identity SP digest SP publication SP IP SP ORPort
    ///         SP DirPort NL
    ///
    ///         [At start, exactly once.]
    ///
    ///         "Nickname" is the OR's nickname.  "Identity" is a hash of its
    ///         identity key, encoded in base64, with trailing equals sign(s)
    ///         removed.  "Digest" is a hash of its most recent descriptor as
    ///         signed (that is, not including the signature), encoded in base64.
    ///
    ///         "Publication" is the publication time of its most recent descriptor,
    ///         in the form YYYY-MM-DD HH:MM:SS, in UTC.  Implementations MAY base
    ///         decisions on publication times in the past, but MUST NOT reject
    ///         publication times in the future.
    ///
    ///         "IP" is its current IP address; ORPort is its current OR port,
    ///         "DirPort" is its current directory port, or "0" for "none".
    ///
    ///     "a" SP address ":" port NL
    ///
    ///         [Any number]
    ///
    ///         The first advertised IPv6 address for the OR, if it is reachable.
    ///
    ///         Present only if the OR advertises at least one IPv6 address, and the
    ///         authority believes that the first advertised address is reachable.
    ///         Any other IPv4 or IPv6 addresses should be ignored.
    ///
    ///         Address and port are as for "or-address" as specified in
    ///         section 2.1.1.
    ///
    ///         (Only included when the vote or consensus is generated with
    ///         consensus-method 14 or later.)
    ///
    ///     "s" SP Flags NL
    ///
    ///         [Exactly once.]
    ///
    ///         A series of space-separated status flags, in lexical order (as ASCII
    ///         byte strings).  Currently documented flags are:
    ///
    ///           "Authority" if the router is a directory authority.
    ///           "BadExit" if the router is believed to be useless as an exit node
    ///              (because its ISP censors it, because it is behind a restrictive
    ///              proxy, or for some similar reason).
    ///           "Exit" if the router is more useful for building
    ///              general-purpose exit circuits than for relay circuits.  The
    ///              path building algorithm uses this flag; see path-spec.txt.
    ///           "Fast" if the router is suitable for high-bandwidth circuits.
    ///           "Guard" if the router is suitable for use as an entry guard.
    ///           "HSDir" if the router is considered a v2 hidden service directory.
    ///           "NoEdConsensus" if any Ed25519 key in the router's descriptor or
    ///              microdesriptor does not reflect authority consensus.
    ///           "Stable" if the router is suitable for long-lived circuits.
    ///           "Running" if the router is currently usable over all its published
    ///              ORPorts. (Authorities ignore IPv6 ORPorts unless configured to
    ///              check IPv6 reachability.) Relays without this flag are omitted
    ///              from the consensus, and current clients (since 0.2.9.4-alpha)
    ///              assume that every listed relay has this flag.
    ///           "Valid" if the router has been 'validated'. Clients before
    ///              0.2.9.4-alpha would not use routers without this flag by
    ///              default. Currently, relays without this flag are omitted
    ///              fromthe consensus, and current (post-0.2.9.4-alpha) clients
    ///              assume that every listed relay has this flag.
    ///           "V2Dir" if the router implements the v2 directory protocol or
    ///              higher.
    ///
    ///     "v" SP version NL
    ///
    ///         [At most once.]
    ///
    ///         The version of the Tor protocol that this relay is running.  If
    ///         the value begins with "Tor" SP, the rest of the string is a Tor
    ///         version number, and the protocol is "The Tor protocol as supported
    ///         by the given version of Tor."  Otherwise, if the value begins with
    ///         some other string, Tor has upgraded to a more sophisticated
    ///         protocol versioning system, and the protocol is "a version of the
    ///         Tor protocol more recent than any we recognize."
    ///
    ///         Directory authorities SHOULD omit version strings they receive from
    ///         descriptors if they would cause "v" lines to be over 128 characters
    ///         long.
    ///
    ///     "pr" SP Entries NL
    ///
    ///         [At most once.]
    ///
    ///         The "proto" family element as specified in section 2.1.1.
    ///
    ///         During voting, authorities copy these lines immediately below the "v"
    ///         lines. When a descriptor does not contain a "proto" entry, the
    ///         authorities should reconstruct it using the approach described below
    ///         in section D. They are included in the consensus using the same rules
    ///         as currently used for "v" lines, if a sufficiently late consensus
    ///         method is in use.
    ///
    ///     "w" SP "Bandwidth=" INT [SP "Measured=" INT] [SP "Unmeasured=1"] NL
    ///
    ///         [At most once.]
    ///
    ///         An estimate of the bandwidth of this relay, in an arbitrary
    ///         unit (currently kilobytes per second).  Used to weight router
    ///         selection. See section 3.4.2 for details on how the value of
    ///         Bandwidth is determined in a consensus.
    ///
    ///         Additionally, the Measured= keyword is present in votes by
    ///         participating bandwidth measurement authorities to indicate
    ///         a measured bandwidth currently produced by measuring stream
    ///         capacities. It does not occur in consensuses.
    ///
    ///         The "Unmeasured=1" value is included in consensuses generated
    ///         with method 17 or later when the 'Bandwidth=' value is not
    ///         based on a threshold of 3 or more measurements for this relay.
    ///
    ///         Other weighting keywords may be added later.
    ///         Clients MUST ignore keywords they do not recognize.
    ///
    ///     "p" SP ("accept" / "reject") SP PortList NL
    ///
    ///         [At most once.]
    ///
    ///         PortList = PortOrRange
    ///         PortList = PortList "," PortOrRange
    ///         PortOrRange = INT "-" INT / INT
    ///
    ///         A list of those ports that this router supports (if 'accept')
    ///         or does not support (if 'reject') for exit to "most
    ///         addresses".
    ///
    ///      "m" SP methods 1*(SP algorithm "=" digest) NL
    ///
    ///         [Any number, only in votes.]
    ///
    ///         Microdescriptor hashes for all consensus methods that an authority
    ///         supports and that use the same microdescriptor format.  "methods"
    ///         is a comma-separated list of the consensus methods that the
    ///         authority believes will produce "digest".  "algorithm" is the name
    ///         of the hash algorithm producing "digest", which can be "sha256" or
    ///         something else, depending on the consensus "methods" supporting
    ///         this algorithm.  "digest" is the base64 encoding of the hash of
    ///         the router's microdescriptor with trailing =s omitted.
    ///
    ///      "id" SP "ed25519" SP ed25519-identity NL
    ///      "id" SP "ed25519" SP "none" NL
    ///         [vote only, at most once]
    routers: Vec<Router>,
    /// The footer section is delineated in all votes and consensuses supporting
    /// consensus method 9 and above with the following:
    ///
    ///     "directory-footer" NL
    ///     [No extra arguments]
    ///
    ///    It contains two subsections, a bandwidths-weights line and a
    ///    directory-signature. (Prior to conensus method 9, footers only contained
    ///    directory-signatures without a 'directory-footer' line or
    ///    bandwidth-weights.)
    ///
    ///    The bandwidths-weights line appears At Most Once for a consensus. It does
    ///    not appear in votes.
    ///
    ///     "bandwidth-weights" [SP Weights] NL
    ///
    ///        Weight ::= Keyword '=' Int32
    ///        Int32 ::= A decimal integer between -2147483648 and 2147483647.
    ///        Weights ::= Weight | Weights SP Weight
    ///
    ///        List of optional weights to apply to router bandwidths during path
    ///        selection. They are sorted in lexical order (as ASCII byte strings) and
    ///        values are divided by the consensus' "bwweightscale" param. Definition
    ///        of our known entries are...
    ///
    ///          Wgg - Weight for Guard-flagged nodes in the guard position
    ///          Wgm - Weight for non-flagged nodes in the guard Position
    ///          Wgd - Weight for Guard+Exit-flagged nodes in the guard Position
    ///
    ///          Wmg - Weight for Guard-flagged nodes in the middle Position
    ///          Wmm - Weight for non-flagged nodes in the middle Position
    ///          Wme - Weight for Exit-flagged nodes in the middle Position
    ///          Wmd - Weight for Guard+Exit flagged nodes in the middle Position
    ///
    ///          Weg - Weight for Guard flagged nodes in the exit Position
    ///          Wem - Weight for non-flagged nodes in the exit Position
    ///          Wee - Weight for Exit-flagged nodes in the exit Position
    ///          Wed - Weight for Guard+Exit-flagged nodes in the exit Position
    ///
    ///          Wgb - Weight for BEGIN_DIR-supporting Guard-flagged nodes
    ///          Wmb - Weight for BEGIN_DIR-supporting non-flagged nodes
    ///          Web - Weight for BEGIN_DIR-supporting Exit-flagged nodes
    ///          Wdb - Weight for BEGIN_DIR-supporting Guard+Exit-flagged nodes
    ///
    ///          Wbg - Weight for Guard flagged nodes for BEGIN_DIR requests
    ///          Wbm - Weight for non-flagged nodes for BEGIN_DIR requests
    ///          Wbe - Weight for Exit-flagged nodes for BEGIN_DIR requests
    ///          Wbd - Weight for Guard+Exit-flagged nodes for BEGIN_DIR requests
    ///
    ///        These values are calculated as specified in section 3.8.3.
    ///
    ///    The signature contains the following item, which appears Exactly Once
    ///    for a vote, and At Least Once for a consensus.
    ///
    ///     "directory-signature" [SP Algorithm] SP identity SP signing-key-digest
    ///         NL Signature
    ///
    ///         This is a signature of the status document, with the initial item
    ///         "network-status-version", and the signature item
    ///         "directory-signature", using the signing key.  (In this case, we take
    ///         the hash through the _space_ after directory-signature, not the
    ///         newline: this ensures that all authorities sign the same thing.)
    ///         "identity" is the hex-encoded digest of the authority identity key of
    ///         the signing authority, and "signing-key-digest" is the hex-encoded
    ///         digest of the current authority signing key of the signing authority.
    ///
    ///         The Algorithm is one of "sha1" or "sha256" if it is present;
    ///         implementations MUST ignore directory-signature entries with an
    ///         unrecognized Algorithm.  "sha1" is the default, if no Algorithm is
    ///         given.  The algorithm describes how to compute the hash of the
    ///         document before signing it.
    ///
    ///         "ns"-flavored consensus documents must contain only sha1 signatures.
    ///         Votes and microdescriptor documents may contain other signature
    ///         types. Note that only one signature from each authority should be
    ///         "counted" as meaning that the authority has signed the consensus.
    ///
    ///         (Tor clients before 0.2.3.x did not understand the 'algorithm'
    ///         field.)*/
    _void: (),
}

/// For this element:
/// PACKAGENAME = NONSPACE
/// VERSION = NONSPACE
/// URL = NONSPACE
/// DIGESTS = DIGEST | DIGESTS SP DIGEST
/// DIGEST = DIGESTTYPE "=" DIGESTVAL
/// NONSPACE = one or more non-space printing characters
/// DIGESTVAL = DIGESTTYPE = one or more non-space printing characters
/// other than "=".
/// Included in consensuses only for method 19 and later.
struct Package {
    package_name: String,
    version:      String,
    url:          String,
    digests:      Vec<Digest>,
}

struct Digest {
    digest_name: String,
    digest_type: String,
}
struct Entry {}
struct Router {}
struct Threshold {}
struct Param {}
struct Authority {}

/// Document ::= (Item | NL)+
named!(document<Vec<&[u8]>>, many1!(alt!(item | newline)));
/// Item ::= KeywordLine Object*
named!(
    item<&[u8]>,
    do_parse!(a: keyword_line >> b: many0!(object) >> (a))
);
/// KeywordLine ::= Keyword NL | Keyword WS ArgumentChar+ NL
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    keyword_line<&[u8]>,
    alt!(
        do_parse!(
            a: keyword >>
            b: newline >>
            (b)
        ) |
        do_parse!(
            c: keyword >>
            d: whitespace >>
            e: many1!(tag!("TODO: argumentchar")) >>
            f: newline >>
            (d)
        )
    )
);

/// Keyword = KeywordChar+
/// KeywordChar ::= 'A' ... 'Z' | 'a' ... 'z' | '0' ... '9' | '-'
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    keyword<String>,
    many1!(
        alt!(
            upper_alphabet |
            lower_alphabet |
            number |
            char!('-')
        )
    )
);
/// Lowercase alphabet
named!(lower_alphabet<char>, one_of!("abcdefghijklmnopqrstuvwxyz"));
/// Uppercase alphabet
named!(upper_alphabet<char>, one_of!("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
/// Numbers
named!(number<char>, one_of!("0123456789"));

/// ArgumentChar ::= any printing ASCII character except NL.


/// Object ::= BeginLine Base64-encoded-data EndLine
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    object<&[u8]>,
    do_parse!(
        begin_line: begin_line >>
        data: tag!("TODO: base64 data") >>
        end_line: end_line >>
        (data)
    )
);
/// BeginLine ::= "-----BEGIN " Keyword "-----" NL
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    begin_line<Vec<&[u8]>>,
    do_parse!(
        _i: tag!("-----BEGIN ") >>
        keyword: keyword >>
        _i: tag!("-----") >>
        _i: newline >>
        (keyword)
    )
);
/// EndLine ::= "-----END " Keyword "-----" NL
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    end_line<Vec<&[u8]>>,
    do_parse!(
        _i: tag!("-----END ") >>
        keyword: keyword >>
        _i: tag!("-----") >>
        _i: newline >>
        (keyword)
    )
);
/// NL = The ascii LF character (hex value 0x0a).
named!(newline, tag!("\n"));
/// WS = (SP | TAB)+
#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    whitespace<()>,
    do_parse!(
        _whitespace: many1!(one_of!(" \t")) >>
        ()
    )
);
