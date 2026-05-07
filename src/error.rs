pub type Result<T> = std::result::Result<T, Error>;
pub type Error = std::boxed::Box<dyn std::error::Error>;