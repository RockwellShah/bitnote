# bitnote
Protect Your Secrets Forever. Ultra-secure notes powered by blockchain.

web files:
- index.html:	                landing page of the app, contains all app html/css/js that run within the main thread.
- ww.js:		                web worker (runs in its own thread)
- sw.js:		                service worker (runs in its own thread)

contracts:
- mod_contract.sol:				main contract for the app, used as the main point of auth for the other contracts. Link: https://snowtrace.io/address/0x225AFdEb639E4cB7A128e348898A02e4730F2F2A
- better_notes_contract.sol:	stores user notes better than the old contract did. Link: https://snowtrace.io/address/0x3B0f15DAB71e3C609EcbB4c99e3AD7EA6532c8c9
- sec_keys.sol:					stores user security keys. Link: https://snowtrace.io/address/0x78D35C5341f9625f6eC7C497Ed875E0dEE0Ef3Ac
- authed_contract.sol:			contract inherited by notes, sec_keys, and potentially others, used to facilitate the mod_contract's auth over the rest, as well as pull necessary variables
