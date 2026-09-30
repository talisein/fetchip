#pragma once

// How far a vote can be trusted, weakest first: anything on the path could have sent it; the
// provider's authoritative nameserver sent it (AA set); or HTTPS proved who sent it.
enum class Trust {
    Unverified,
    Authoritative,
    Authenticated,
};
