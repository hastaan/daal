# Distribution-Failure Rig

Scenarios where individual distribution channels fail independently. Used to verify that no single channel is load-bearing.

Channels covered:

- Telegram
- GitHub
- Project primary domain
- App stores
- Subscription URL
- Bootstrap-directory mirrors
- IPFS gateways

Each scenario file declares what is unreachable; later phases assert the client can still operate via remaining channels.
