# mrt
[![Build Status](https://travis-ci.org/Woutifier/mrt.svg?branch=master)](https://travis-ci.org/Woutifier/mrt) [![Docs](https://docs.rs/mrt/badge.svg)](https://docs.rs/mrt)

An MRT (RFC6396) file parser implemented in Rust, using Nom (v5).

## Key Features

* Implemented in Rust
* Fairly fast

## Supported messages

* PEER_INDEX_TABLE
* RIB_IPV4_UNICAST
* RIB_IPV6_UNICAST
* BGP4MP_MESSAGE_AS4
    * Only the content of the UPDATE message is parsed.

## Supported attributes
* ORIGIN
* AS_PATH
* NEXT_HOP
* MULTI_EXIT_DISC
* LOCAL_PREF
* ATOMIC_AGGREGATE
* COMMUNITY

## Contribute

Pull requests are welcome!

