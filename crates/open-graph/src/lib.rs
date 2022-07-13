// https://ogp.me/
#[macro_use]
extern crate serde_derive;
extern crate html5ever;
extern crate reqwest;
extern crate serde;
extern crate serde_json;

mod audio;
mod image;
mod object;
mod video;

pub mod error;
pub mod fetcher;

pub use audio::Audio;
pub use error::Error;
pub use fetcher::fetch;
pub use image::Image;
pub use object::Object;
pub use video::Video;
