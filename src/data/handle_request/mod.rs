pub mod add_friend_request;
pub mod delete_friend_request;
pub mod delete_request;
pub mod get_request;
pub mod put_request;
pub mod sign_in_request;
pub mod sign_up_request;

pub mod func_used_in_req;

pub use self::add_friend_request::handle_add_friend_request;
pub use self::delete_friend_request::handle_delete_friend_request;
pub use self::delete_request::handle_delete_request;
pub use self::get_request::handle_get_request;
pub use self::put_request::handle_put_request;
pub use self::sign_in_request::handle_sign_in_request;
pub use self::sign_up_request::handle_sign_up_request;
