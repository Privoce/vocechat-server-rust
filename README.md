
# Re-decentralized the Internet through personal cloud computing.
## VoceChat is the `lightest` chat server prioritizes private hosting! Easy integratation to your app with our open API!
### Quick run

```bash
docker run -d --restart=always \
  -p 3009:3000 \
  --name vocechat-server \
  Privoce/vocechat-server:latest
```

On browser visit: http://localhost:3009/


### Contact us

Doc: [https://doc.voce.chat](https://doc.voce.chat)  
Chat with us: [https://voce.chat](https://voce.chat)  
Email: [han@privoce.com](han@privoce.com)
### Welcome your help of any form--code, issues, blog articles, social media shares.

# Goal

The goal of Voce is to provide a space owned by "you" on the Internet, just as the name "voce" means in portguese. As cloud computing getting matured, there will be a time in the foreseeable future that netizens like you and me can enjoy the benefit of having a personal cloud space on the Internet--like iCloud, while not only will you have storage, but also a personalized computing layer.

Why do we need a private cloud space? The short answer is that information will become our private property and means of communication will be under the control of every netizen.

Digital technologies including Internet and the Web make information duplicable and transferable, yet platforms are controlling the ownership and means of production and transmission of most information (content) on the Internet. We are building Voce as an open-sourced tool (not a platform) to empower smaller groups and individuals to become a platform themselves. When various servers get connected to each other, all the information shared among the servers will be duplicated and become the server owner's private data under private storages.

# Personal cloud

We need a "home" as our private property on the Internet, and this home should have features more than just storage. No matter you choose NAS, AWS, Raspberry Pi or your local PC to run VoceChat, it is your own private property--yes, public cloud services like AWS purchased by you is commercially your own property and the data in your cloud is protected from accessing by the public cloud service providers. Features including but not limited to instant messaging, activity posts, private video calls, notes, whiteboard are all desiring and useful on your personal cloud server. Personal cloud is the new PC, and there will be a new software layer with some shared traits--distributed by URL(web app), good API, interoperable profiles. Privoce is currently working on this software layer of personal cloud.

# Why Rust

Personal cloud needs efficent solutions. This Rust written server is less than 20MB and runs with great efficiency. Hosting a 20MB private social media server is much more accessible than a 300MB one. Just like cars v. bus, or single family home v. hotels, if Facebook is a grand hotel, VoceChat is like a house. If Matrix and Mastodon are buses, VoceChat is like a car. The next paradigm of the internet is serverless functions + personal storage. Making VoceChat serverless is also a next step.

# Webhook, bot, and ways to get interconnected (work in progress)

Social media cannot always stay private if people want new information to be transferred among different servers. The word "social" in social media means multiple nodes communicate with multiple nodes in a synced space (mass to mass). A channel (private or public) should serve the end of this mass to mass data sharing and syncing space. Channel should function as a shared good where members who joined should have the right to store the same chat data (use their server)--this may one day functions like Bitcoin, yet currently, efficiency should be more prioritiezed and admin of the channel could have the right to assign different "power" to members. We have implemented both inbound and outbound webhooks so that it's possible to sync messages from a VoceChat channel to another channel (slack, discord, or VoceChat) though you will need to write your own server side code to personalize this process (this could be troublesome, and again, serverless could be a good solution). 

We also found bot super interesting and personal bot services may replace platforms--e.g., we are training some bots based on GPT api that can be added to VoceChat.

If you have a proposal on how multiple servers could get interconnected, e.g., should we support Matrix protocal, or other protocal, feel free to share your thougts in the discussions, or directly discuss it with at our chat at  https://voce.chat.

# Free for personal use, require license for non-personal use.

`VoceChat` is an open-source commercial software. The VoceChat server is the smallest, stablest and most efficient independent chat server on today's market, which is good for integration to your own app. VoceChat official image is free for personal use, which we define as equal or less than 20 registered users, if you want to integrate VoceChat to your own app/site for a larger user base, you have to purchase a license. The license is 49$/version.

Our team also provide customization service. We also provide resale license for NAS and cloud providers who want to collaborate with us.

### Project composition:

| Name       | Tech                                | Project                                                   | License | Comment                                             |
| ---------- | ----------------------------------- | --------------------------------------------------------- | ------- | --------------------------------------------------- |
| Server     | Rust                                | [vocechat-server](https://github.com/privoce/vocechat-server-rust) | Big Time Public License   | Server supports Linux, Windows, ARM32/64 |
| Server image | Docker, Shell                             | [vocechat-docker](https://hub.docker.com/r/privoce/vocechat-server/tags) | Creative Commons Attribution-NonCommercial 4.0 International     | Official image supports Linux, ARM64           |
| APP Client | Flutter                             | [vocechat-client](https://github.com/privoce/vocechat-client) | GPLv3     | Client supports Android and IOS platforms           |
| Web Client | React                               | [vocechat-web](https://github.com/privoce/vocechat-web)   | GPLv3     | Web App, integrated management                      |
| Documentation   | [docusaurus](https://docusaurus.io) | [vocechat-doc](https://github.com/privoce/vocechat-doc)   | GPLv3     | Vocechat document website                           |

### Feature list & roadmap

- [x] DM & Group Chating / 2021-Q4
- [x] Reply, @ to mention a person / 2021-Q4
- [x] Images and large files transmission / 2021-Q4
- [x] Pin / 2022-Q1
- [x] Forward / 2022-Q1
- [x] Favorate / 2022-Q1
- [x] Auto-delete my messages / 2022-Q2
- [x] Voice (now support agora) / 2022-Q4
- [x] Video (now support agora)/ 2022-Q4
- [x] Bot and Webhook (inbound and outbound)/ 2022-Q4
- [ ] Role based permission control/ Undecided
- [ ] Post, based on ActivityPub/ Undecided
- [ ] Matrix Bridge/ Undecided


Chat with us: https://voce.chat
Email: han@privoce.com
