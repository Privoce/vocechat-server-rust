# VoceChat Intro
`Vocechat` is a secure chat software that supports independent deployment.
The data is completely controlled by the user.
It supports the whole process of encrypted transmission and can be burned immediately after reading.
The function is inspired by products and specifications such as `Slack`, `Discord`, `RocketChat`, `Matrix` and `Solid`.
The Vocechat server is the smallest, stablest and most efficient independent chat server on today's market.

We believe that the way to live up to the true meaning of the decentralization ideal of Web 3.0 is through de-platformization.
Through personalized computing and personalized storage, individuals and organizations can have their own platforms on their own cloud server.
Therefore, Vocechat is created and positioned as a social collaboration program that can be easily deployed on the private cloud by any parties.

The team is internationalized and cooperates remotely.
The contributors come from North America, South America, Asia and Africa.
The core members include 'MIT' alumni, 'Stanford' entrepreneurial organization members, top developers and open-source veterans.
Vocechat is an open-source product with a free community version and only charges for business usages. You are welcome to star, raise issues, and contribute in any form.

### Project composition:
| Name     | Tech    | Project                                                         | License | Comment                                             |
|----------|---------|-----------------------------------------------------------------|---------|-----------------------------------------------------|
| Server:  | Rust    | [vocechat-server](https://github.com/privoce/voce-server)   | GPLv3     | Server Supports platforms: Linux, Windows, Arm32/64 |
| Client:  | Flutter | [vocechat-client](https://github.com/privoce/voce-client)   | ---     | Client supports Android and IOS platforms           |
| Web:     | React   | [vocechat-web](https://github.com/privoce/vocechat-web)         | ---     | Web App, integrated management                      |
| Web-SDK: | React   | [vocechat-web-sdk](https://github.com/privoce/vocechat-web-sdk) | ---     | JS-SDK Can be intergrated into other products.      |

### Feature List & Roadmap
- [x] DM & Group Chating / 2021-Q4
- [x] Reply, @ to mention a person / 2021-Q4
- [x] Images and large files transmission / 2021-Q4
- [x] Pin / 2022-Q1
- [x] Forward / 2022-Q1
- [x] Favorate / 2022-Q1
- [x] Burn after reading / 2022-Q2
- [ ] Voice / 2022-Q3
- [ ] Video / 2022-Q3

### Quickly run
```bash
docker run -d --restart=always \
  -p 3000:3000 \
  --name vocechat-server \
  Privoce/vocechat-server:latest
```
view: http://localhost:3000/

### Comparison of similar products
<table border="1">
    <tr>
        <th></th>
        <th colspan="4">Security & Privacy</th>
        <th colspan="6">Compatibility</th>
        <th colspan="8">Function</th>
        <th></th>
    </tr>
    <tr align="center">
        <td></td>
        <td>TLS</td>
        <td>Client open source</td>
        <td>Server open source</td>
        <td>Independent deployment</td>
        <td>Web</td>
        <td>Android</td>
        <td>iOS</td>
        <td>MacOS</td>
        <td>Win</td>
        <td>Linux</td>
        <td>Multiple devices</td>
        <td>Local message</td>
        <td>File Transfer</td>
        <td>Voice</td>
        <td>Video</td>
        <td>Mobile Unnecessary</td>
        <td>Burn after reading</td>
        <td>Technology stack</td>
        <td>Time</td>
    </tr>
    <tr align="center">
        <th align="left">Vocechat</th>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td align="left">Rust, Flutter, React</td>
        <td>2022</td>
    </tr>
    <tr align="center">
        <th align="left">Matrix</th>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td align="left">Protocal</td>
        <td>2014</td>
    </tr>
    <tr align="center">
        <th align="left">XMPP</th>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td align="left">Protocal</td>
        <td>1999</td>
    </tr>
    <tr align="center">
        <th align="left">RocketChat</th>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td align="left">NodeJS, Electron</td>
        <td>2015</td>
    </tr>
    <tr align="center">
        <th align="left">Mattermost</th>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td align="left">Nginx, PostgreSQL, Golang, RN</td>
        <td>2016</td>
    </tr>
    <tr align="center">
        <th align="left">Signal</th>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>✅</td>
        <td align="left">Java, Swift, PostgreSQL, Redis</td>
        <td>2014</td>
    </tr>
    <tr align="center">
        <th align="left">Telegram</th>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td align="left">Java, QT</td>
        <td>2013</td>
    </tr>
    <tr align="center">
        <th align="left">Discord</th>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td align="left">Elixir, Python, Rust, C++</td>
        <td>2015</td>
    </tr>
    <tr align="center">
        <th align="left">Whatsapp</th>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td align="left">Erlang, Mnesia, Lighttpd, XMPP</td>
        <td>2009</td>
    </tr>
    <tr align="center">
        <th align="left">Line</th>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td align="left">Unknown</td>
        <td>2011</td>
    </tr>
    <tr align="center">
        <th align="left">Slack</th>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td align="left">Java, LAMP, JQuery, MacGap, Object-C</td>
        <td>2013</td>
    </tr>
    <tr align="center">
        <th align="left">WeChat</th>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td align="left">C++, Java, Object-C/Swift</td>
        <td>2011</td>
    </tr>
    <tr align="center">
        <th align="left">MSN</th>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>❌</td>
        <td>❌</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>✅</td>
        <td>❌</td>
        <td align="left">VC++.NET</td>
        <td>Unknown</td>
    </tr>
</table>


### Contact Us
Github: [https://github.com/privoce/vocechat-server](https://github.com/privoce/vocechat-server)  
Email: [han@privoce.com](han@privoce.com)


https://github.com/Privoce/vocechat-web/releases/download/v0.3.0/web.vocechat.md5
https://github.com/Privoce/vocechat-web/releases/v0.3.0/download/web.vocechat.md5
