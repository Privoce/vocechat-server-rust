# Open Graph Protocal Parser

`pvc-opengraph` is based on `opengraph-0.2.4`, added some extra information: `Title`, `Description`, `Favicon`, and solved some problem:

1. Support three-level attribute name.
```html
<meta property="og:image:height" content="1000" />
```

2. Support extracting `favicon`.
```html
<link rel="apple-touch-icon" sizes="57x57" href="https://domain.com/img/favicon/icon.png"/>
```

3. Support extracting `Title`.
```html
<title>First Title</title>
<meta property="og:title" content="High priority Title" />
```

4. Relative path is automatically converted to absolute path:
if request `https://domain.com/path1/path2` get the following:
```html
<meta property="og:image" content="rock.jpg" />
```
The absolute path is obtained after parsing:
```
https://domain.com/path1/rock.jpg
```

5. `reqwest` updated to the latest version. The `edition` adopts 2021, and `rustls` is enabled by default, which supports better cross platform compilation.


6. add feature `poem-openapi`.


7. `unzip` decoding of non-standard servers is supported. few servers ignore the client `Accept-Encoding` and always return `gz` format data.


9. The code passed the `cargo test` and `cargo clip`.