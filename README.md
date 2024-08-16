# bitnote
Protect Your Secrets Forever. Ultra-secure notes powered by blockchain. https://bitnote.xyz

Web Files:
- index.html:	                landing page of the app, contains all app html/css/js that run within the main thread.
- ww.js:		                web worker (runs in its own thread).
- sw.js:		                service worker (runs in its own thread).

Contracts:
- mod_contract.sol:				main contract for the app, used as auth for the other contracts. Link: https://snowtrace.io/address/0x225AFdEb639E4cB7A128e348898A02e4730F2F2A
- better_notes_contract.sol:	stores user notes. Link: https://snowtrace.io/address/0x3B0f15DAB71e3C609EcbB4c99e3AD7EA6532c8c9
- sec_keys.sol:					stores user security keys. Link: https://snowtrace.io/address/0x78D35C5341f9625f6eC7C497Ed875E0dEE0Ef3Ac
- authed_contract.sol:			contract inherited by notes, sec_keys, and potentially others, used to facilitate the mod_contract's auth over the rest, as well as pull necessary variables.

Why BitNote?

We created BitNote because we ran into an annoying problem: where do you store secret information?
‍
The traditional advice is to use a fireproof safe that is bolted to the ground in a hidden place in your house. That’s great advice if you’re Batman. Unfortunately, for the rest of us that kind of physical security is not really feasible.

Many people turn to centralized password managers like 1Password or Lastpass. Not only can these have pricey subscriptions and the threat of going out of business, they can also have a lot of security issues. And because they are not open source, you never really know what’s going on with your data.

Even open source alternatives like Bitwarden can have frustrating flaws, like the ability to permanently delete your vault if someone gets access to your email or having access blocked because you use a VPN. 

We’ve seen people store sensitive information in their Apple, Google, or Microsoft accounts (only sometimes encrypted), only to find their accounts banned or their access locked out. Or perhaps even worse, if someone steals a device and pin and gains access to everything.

We've seen people roll their own solutions, only to find they made a critical mistake that leads to data loss. 

We searched for something that could store our secrets safely that would solve these issues. Decentralized, censorship resistant, permissionless, open source, private, permanent storage that is highly secure but easily usable and accessible. And we didn’t find it. So we built BitNote.

BitNote is built with simple, time tested technology: HTML, CSS, and Javascript. No frameworks. The entire app comes in well under 1MB in total size and is very fast. It’s designed to have no centralized dependencies and be resilient for many years to come––a "forever machine."

What's next? On the roadmap we're excited to solve the next big problem: how do you automatically pass down your important information if something happens to you? Decentralized succession will unlock a number of new, important use cases.
