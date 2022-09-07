## Iframe Embed

If the 80/443 port is occupied by nginx, please refer to [Nginx Reverse proxy](https://doc.voce.chat/en-us/install-by-docker-nginx.html)

All you need is iframe, change src to your VoceChat domain，e.g., `privoce.voce.chat` is our embedded space on our official website: [https://voce.chat](https://voce.chat), and the exmaple `code` is here:


```
{
      <iframe src="//privoce.voce.chat" width="1200" height="800px" frameborder="0"/>
      <!-- width and height can be changed by you，but we recommend using CSS to control it -->
}
```
