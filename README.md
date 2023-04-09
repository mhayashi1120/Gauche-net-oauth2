Gauche-net-oauth2
===================

[![CI](https://github.com/mhayashi1120/Gauche-net-oauth2/actions/workflows/build.yml/badge.svg)](https://github.com/mhayashi1120/Gauche-net-oauth2/actions/workflows/build.yml)

Not like Oauth 1.0, Oauth2 is a simple protocol.
This package desired to provide convenience (utility) procedure to handle Major Oauth2 provider's (Github, Facebook, Google ...) API.

Followings are *maybe* working well.

- rfc6749 (Oauth2)
- rfc6750 (Bearer token)
- rfc7636 (PKCE: Proof Key for Code Exchange) at `net.oauth2.code-verifier` module
- rfc8252 (Native-app) at `net.oauth2.native-app` module

## Install

    ./configure
    make check
    sudo make install

## Confirmed OAuth2 Providers

- Google (2022-12)
- Twitter (2022-12)
- Github
- Facebook
- LINE

## Procedures

**Now preparing**

