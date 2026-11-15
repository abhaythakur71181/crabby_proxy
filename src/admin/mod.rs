pub mod auth;
pub mod handlers;
pub mod server;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

pub use server::run_admin_server;
