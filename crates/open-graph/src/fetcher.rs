use std::borrow::Borrow;

use html5ever::{
    parse_document,
    rcdom::{
        Handle,
        NodeData::{Comment, Doctype, Document, Element, ProcessingInstruction, Text},
        RcDom,
    },
    tendril::{fmt::Slice, TendrilSink},
    Attribute,
};
use http::HeaderMap;
use reqwest;

// use std::io::Read;
use crate::{error::Error, Audio, Image, Object, Video};

fn gz_decode(data: &[u8]) -> Result<String, Error> {
    use std::io::prelude::*;

    use flate2::read::GzDecoder;
    let mut d = GzDecoder::new(data);
    let mut s = String::new();
    d.read_to_string(&mut s)?;
    Ok(s)
}

use regex::Regex;
fn fetch_url_from_meta(text: &str) -> Option<String> {
    let re = Regex::new(r#"<meta .*?content=".*?url=(.*?)""#).unwrap();
    if let Some(cap) = re.captures(text) {
        return cap.get(1).map(|v| v.as_str().to_string());
    }
    None
}

#[test]
fn test_fetch_url_from_meta() {
    let text = r#"<meta http-equiv="refresh" content="0;url=http://www.baidu.com/">"#;
    let a = fetch_url_from_meta(text);
    assert_eq!(Some("http://www.baidu.com/".to_string()), a);
}

use async_recursion::async_recursion;
#[async_recursion]
pub async fn fetch(url: &str, header_map: Option<HeaderMap>, deep: u8) -> Result<Object, Error> {
    // let body = reqwest::get(url).await?.text().await?;
    let mut client = reqwest::Client::new().get(url);
    if let Some(header_map2) = header_map.clone() {
        client = client.headers(header_map2);
        client = client.header(http::header::ACCEPT_ENCODING, "none");
    }
    let body = client.send().await?.bytes().await?;
    // gz magic number: 1f 8b
    if body.len() < 2 {
        return Err(Error::Unexpected);
    }
    let body = if body[0] == 0x1f && body[1] == 0x8b {
        gz_decode(body.as_bytes())
            .unwrap_or_default()
            .to_lowercase()
    } else {
        String::from_utf8(body.to_vec()).unwrap_or_default()
    };

    if body.contains("<meta") {
        if let Some(url) = fetch_url_from_meta(body.as_str()) {
            if deep > 10 {
                return Err(Error::Other("too many redirect!".into()));
            }
            return fetch(&url, header_map, deep + 1).await;
        }
    }
    // let body = client.send().await?.text().await?;
    let dom = parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut body.as_bytes())
        .unwrap();
    walk(dom.document, url)
}

fn attr_value(attr_name: &str, attrs: &[Attribute]) -> Option<String> {
    for attr in attrs.iter() {
        if attr.name.local.as_ref() == attr_name {
            return Some(attr.value.to_string());
        }
    }
    None
}

fn inner_text(handle: Handle) -> Option<String> {
    if handle.children.borrow().len() > 0 {
        let text1 = handle.children.borrow();
        let inner = text1.get(0);
        if let Some(handle) = inner {
            if let Text { contents } = handle.data.borrow() {
                return Some(contents.borrow().to_string());
            }
        }
    }
    None
}

// use std::any::Any;
fn walk(handle: Handle, url: &str) -> Result<Object, Error> {
    let mut key_key_values = vec![];
    do_walk(handle, &mut key_key_values, url)?;
    let mut obj = Object::default();
    for (key0, key1, value) in key_key_values {
        match key0.as_ref() {
            "title" => {
                if !value.is_empty() {
                    obj.title = value;
                }
            }
            "type" => {
                obj.r#type = value;
            }
            "url" => {
                obj.url = value;
            }
            "favicon_url" => {
                obj.favicon_url = Some(value);
            }
            "description" => {
                if !value.is_empty() {
                    obj.description = Some(value);
                }
            }
            "locale" => {
                obj.locale = Some(value);
            }
            "locale_alternate" => {
                // obj.locale_alternate.as_mut().map(|v|v.push(value)); // cargo clippy warning!
                if let Some(v) = obj.locale_alternate.as_mut() {
                    v.push(value);
                }
            }
            "site_name" => {
                obj.site_name = Some(value);
            }
            "image" => {
                if key1.is_empty() {
                    obj.images.push(Image::new(value));
                } else {
                    if obj.images.is_empty() {
                        obj.images.push(Image::new(value.clone()));
                    }
                    let mut v = obj.images.last_mut().unwrap();
                    match key1.as_ref() {
                        "width" => v.width = value.parse::<i32>().ok(),
                        "height" => v.height = value.parse::<i32>().ok(),
                        "secure_url" => v.secure_url = Some(value),
                        "alt" => v.alt = Some(value),
                        "type" => v.r#type = Some(value),
                        _ => {}
                    }
                }
            }
            "audio" => {
                if key1.is_empty() {
                    obj.audios.push(Audio::new(value));
                } else {
                    if obj.audios.is_empty() {
                        obj.audios.push(Audio::new(value.clone()));
                    }
                    let mut v = obj.audios.last_mut().unwrap();
                    match key1.as_ref() {
                        "secure_url" => v.secure_url = Some(value),
                        "type" => v.r#type = Some(value),
                        _ => {}
                    }
                }
            }
            "video" => {
                if key1.is_empty() {
                    obj.videos.push(Video::new(value));
                } else {
                    if obj.videos.is_empty() {
                        obj.videos.push(Video::new(value.clone()));
                    }
                    let mut v = obj.videos.last_mut().unwrap();
                    match key1.as_ref() {
                        "height" => v.height = value.parse::<i32>().ok(),
                        "width" => v.width = value.parse::<i32>().ok(),
                        "secure_url" => v.secure_url = Some(value),
                        "type" => v.r#type = Some(value),
                        _ => {}
                    }
                }
            }
            _ => {}
        };
    }
    Ok(obj)
}
fn do_walk(
    handle: Handle,
    key_key_values: &mut Vec<(String, String, String)>,
    url: &str,
) -> Result<(), Error> {
    let abs_path = url::Url::parse(url)?;
    match handle.data {
        Document => (),
        Doctype { .. } => (),
        Text { .. } => (),
        Comment { .. } => (),
        Element {
            ref name,
            ref attrs,
            ..
        } => {
            let tag_name = name.local.as_ref();
            match tag_name {
                "meta" => {
                    if let Some(v) = attr_value("name", &attrs.borrow()) {
                        if v == "description" {
                            if let Some(vv) = attr_value("content", &attrs.borrow()) {
                                key_key_values.push((
                                    "description".to_string(),
                                    "".to_string(),
                                    vv,
                                ));
                            }
                        }
                    }
                    if let Some(v) = attr_value("property", &attrs.borrow()) {
                        if v.starts_with("og:") {
                            let end = v.chars().count();
                            let key = unsafe { v.get_unchecked(3..end) }.to_string();
                            let mut keys: Vec<_> = key.split(':').collect();
                            let key0 = keys.remove(0).to_string();
                            let key1 = if keys.is_empty() {
                                String::new()
                            } else {
                                keys.remove(0).to_string()
                            };
                            if let Some(mut vv) = attr_value("content", &attrs.borrow()) {
                                if (key0 == "image" || key0 == "video" || key0 == "audio")
                                    && key1.is_empty()
                                    && !vv.starts_with("http")
                                {
                                    vv = abs_path.join(vv.as_str())?.to_string();
                                }
                                key_key_values.push((key0, key1, vv));
                            }
                        }
                    }
                }
                "title" => {
                    let title = inner_text(handle.clone()).unwrap_or_default();
                    key_key_values.push(("title".to_string(), "".to_string(), title))
                }
                // <link rel="apple-touch-icon" sizes="57x57" href="https://www.redditstatic.com/desktop2x/img/favicon/apple-icon-57x57.png"/>
                // <link rel="apple-touch-icon" sizes="60x60" href="https://www.redditstatic.com/desktop2x/img/favicon/apple-icon-60x60.png"/>
                // <link rel="icon" type="image/png" href="http://example.com/myicon.png">
                // <link rel="icon" type="image/x-icon" href="/images/favicon.ico">
                "link" => {
                    if let Some(v) = attr_value("rel", &attrs.borrow()) {
                        if v.ends_with("icon") {
                            if let Some(vv) = attr_value("href", &attrs.borrow()) {
                                let vv = url::Url::parse(url)?.join(&vv)?;
                                key_key_values.push((
                                    "favicon_url".to_string(),
                                    "".to_string(),
                                    vv.to_string(),
                                ));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
        ProcessingInstruction { .. } => unreachable!(),
    }
    for child in handle.children.borrow().iter() {
        do_walk(child.clone(), key_key_values, url)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_open_graph_object() {
        let x = r#"
            <html prefix="og: http://ogp.me/ns#">
                <head>
                    <title>The Rock 123</title>
                    <meta name="description" content="Some Description" />
                    <meta property="og:title" content="The Rock" />
                    <meta property="og:type" content="video.movie" />
                    <meta property="og:url" content="http://www.imdb.com/title/tt0117500/" />
                    <meta property="og:image" content="http://ia.media-imdb.com/images/rock.jpg" />
                    <meta property="og:image:type" content="image/jpeg" />
                    <meta property="og:image" content="https://example.com/rock.jpg" />
                    <meta property="og:image:width" content="400" />
                    <meta property="og:image:height" content="300" />
                    <meta property="og:image" content="https://example.com/rock2.jpg" />
                    <meta property="og:image" content="https://example.com/rock3.jpg" />
                    <meta property="og:image:height" content="1000" />
                </head>
                <body>
                    <p>hello</p>
                    <h1>hello</h1>
                </body>
            </html>
            "#;
        let x = x.to_string();
        let dom = parse_document(RcDom::default(), Default::default())
            .from_utf8()
            .read_from(&mut x.as_bytes())
            .unwrap();
        let obj = walk(dom.document, "").unwrap();
        assert_eq!(obj.title, "The Rock".to_string());
        assert_eq!(obj.description, Some("Some Description".to_string()));
        assert_eq!(obj.r#type, "video.movie".to_string());
        assert_eq!(obj.url, "http://www.imdb.com/title/tt0117500/".to_string());
        assert_eq!(obj.images.len(), 4);
        assert_eq!(
            obj.images[1].url,
            "https://example.com/rock.jpg".to_string()
        );
        assert_eq!(obj.images[1].width, Some(400));
        assert_eq!(obj.images[1].height, Some(300));
        assert_eq!(obj.images[3].height, Some(1000));
    }

    #[tokio::test]
    async fn test_fetch() {
        // curl -H "accept-encoding: none" https://www.bilibili.com/video/BV1s3411J7Aj
        // let obj = fetch("https://www.bilibili.com/video/BV1s3411J7Aj", None).await.unwrap();
        // let obj = fetch("https://www.youtube.com/watch?v=BlI9PVQA8ZA", None).await.unwrap();
        // let obj = fetch("https://dapr.io/", None).await.unwrap();
        // dbg!(obj);
    }
}
