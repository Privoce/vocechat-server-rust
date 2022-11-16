
# Re-decentralized the Internet through personal cloud computing.
## VoceChat is a ```15 MB``` chat server prioritizes private hosting!

# Grand Goal

The grand goal of Voce is to provide a space owned by "you" on the Internet, just as the name "voce" means in portguese. As cloud computing is getting matured, there will be a time in the foreseeable future that netizens like you and me can enjoy the benefit of having a personal cloud space on the Internet.

Why do we need a private cloud space? The short answer is that information will become our private property and means of communication will be under the control of every netizen.

Digital technologies including Internet and the Web make information duplicable and transferable, yet platforms are controlling the ownership and means of production and transmission of most information (content) on the Internet. We are building Voce as an open-sourced tool (not a platform) to empower smaller groups and individuals to become a platform themselves. When various servers get connected to each other, all the information shared among the servers will be duplicated and become the server owner's private data under private storages.

# Why Rust

Rust written server is only 15MB and runs with great efficiency, which means hosting a private social media server can become an individual thing, no matter where it is hosted--on your public cloud server, personal NAS or Raspberry Pi, etc. Just like cars v. public transportation, or single family home v. hotels, private social media is more personalized and all data is owned by the owner, so that there could be a new paradigm of private social media along with today's central social media platforms--if Facebook is a hotel, then Voce is like a house. However, private social media is not free--just like lands and houses are not free.

# How to get interconnected (work in progress, we welcome your contribution!)

Private social media cannot always stay private if people want new information to be transferred among different servers. The word "social" in social media means multiple nodes communicate with multiple nodes in a synced space (mass to mass). A channel (private or public) should serve the end of this mass to mass data sharing and syncing space. Each channel should function like a "shared ledger" where members who joined should have the right to use their server to distributely store the same chat data--this functions like Bitcoin, yet in the chat channel scenario, efficiency should be more prioritiezed and trust does not necessarily come evenly from every node (admin of the channel could have the right to assign "power" to members)--compared with blockchain, git is a more proper example. Matrix.org has provided a standard exactly solving this multi-server data storage needs. Hence a support for matrix is desirable in the next steps.

Or if you have a proposal on how multiple servers could get interconnected, feel free to share and discuss it with us here or through our chat at  https://voce.chat.

# VoceChat Intro

`Vocechat` is a secure community chat social media that supports independent deployment.
The data is completely controlled by the user.
The community version is open-sourced, for better supports and advanced features like personalized encryption and transmission or burned immediately after reading, please purchase our [entreprise version](https://voce.chat/).
The function is inspired by products and specifications such as `Slack`, `Discord`, `RocketChat`, `Matrix` and `Solid`.
The Vocechat server is the smallest, stablest and most efficient independent chat server on today's market.

We believe that the way to live up to the true meaning of the decentralization ideal of Web 3.0 is through de-platformization.
Through personalized computing and personalized storage, individuals and organizations can have their own platforms on their own cloud server.
Therefore, Vocechat is created and positioned as a social collaboration program that can be easily deployed on the private cloud by any parties.

The team is internationalized and cooperates remotely.
The contributors come from North America, South America, Asia and Africa.
Vocechat is an open-source product with a free community version and only charges for business usages. You are welcome to star, raise issues, and contribute in any form.

### Project composition:

| Name       | Tech                                | Project                                                   | License | Comment                                             |
| ---------- | ----------------------------------- | --------------------------------------------------------- | ------- | --------------------------------------------------- |
| Server     | Rust                                | [vocechat-server](https://github.com/privoce/voce-server) | GPLv3   | Server Supports platforms: Linux, Windows, Arm32/64 |
| APP Client | Flutter                             | [vocechat-client](https://github.com/privoce/voce-client) | ---     | Client supports Android and IOS platforms           |
| Web Client | React                               | [vocechat-web](https://github.com/privoce/vocechat-web)   | ---     | Web App, integrated management                      |
| Document   | [docusaurus](https://docusaurus.io) | [vocechat-doc](https://github.com/privoce/vocechat-doc)   | ---     | Vocechat document website                           |

### Feature List & Roadmap

- [x] DM & Group Chating / 2021-Q4
- [x] Reply, @ to mention a person / 2021-Q4
- [x] Images and large files transmission / 2021-Q4
- [x] Pin / 2022-Q1
- [x] Forward / 2022-Q1
- [x] Favorate / 2022-Q1
- [x] Burn after reading / 2022-Q2
- [x] Voice (now support agora) / 2022-Q4
- [x] Video (now support agora)/ 2022-Q4
- [ ] Matrix Bridge/ Undecided
- [ ] Role based permission control/ Undecided

### Quickly run

```bash
docker run -d --restart=always \
  -p 3000:3000 \
  --name vocechat-server \
  Privoce/vocechat-server:latest
```

view: http://localhost:3000/

### Contact Us

Doc: [https://doc.voce.chat](https://doc.voce.chat)  
Chat with us: [https://voce.chat](https://voce.chat)  
Email: [han@privoce.com](han@privoce.com)
