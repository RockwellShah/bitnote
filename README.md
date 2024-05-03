# bitnote
Protect Your Secrets Forever. Ultra-secure notes powered by blockchain.

web files:
- index.html:	                landing page of the app, contains all app html/css/js that run within the main thread.
- ww.js:		                web worker (runs in its own thread)
- sw.js:		                service worker (runs in its own thread)

contracts:
- mod_contract.sol:				main contract for the app, used as the main point of auth for the other contracts.
- better_notes_contract.sol:	stores user notes better than the old contract did.
- sec_keys.sol:					stores user security keys.
- authed_contract.sol:			contract inherited by notes, sec_keys, and potentially others, used to facilitate the mod_contract's auth over the rest, as well as pull necessary variables
