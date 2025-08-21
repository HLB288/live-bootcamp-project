pub mod user;
pub mod error;
pub mod data_stores;
pub use error::*;
pub use user::*;
pub use data_stores ::*;
pub struct Email(pub String);
pub struct Password(pub String);
