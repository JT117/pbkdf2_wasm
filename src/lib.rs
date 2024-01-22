use pbkdf2::password_hash::{PasswordHasher, SaltString};
use pbkdf2::Pbkdf2;
use wasmbus_rpc::actor::prelude::*;
use wasmcloud_interface_httpserver::{HttpRequest, HttpResponse, HttpServer, HttpServerReceiver};

#[derive(Debug, Default, Actor, HealthResponder)]
#[services(Actor, HttpServer)]
struct HelloWorldActor {}

/// Implementation of the HttpServer capability contract
#[async_trait]
impl HttpServer for HelloWorldActor {
    // #[tracing::instrument]
    async fn handle_request(&self, _ctx: &Context, _req: &HttpRequest) -> RpcResult<HttpResponse> {
        let password = b"hunter42dfkjsdhfkhdfkhjjhsdfjhsdfhsdkjfhsdhjfksjdhfsdjhfkjshdfkjsdhfkjshdfkhsdfnqsknfezhfhsdkfksdjnfkjsdhfksjdhfjhsdfkhsdkfhksjsqjdqslkjdlqkjd";
        let salt = get_salt().await?;
        let password_hash = get_password_hash(password, &salt).await?;

        Ok(HttpResponse {
            status_code: 200,
            body: format!("Password hash: {}", password_hash).into_bytes(),
            ..Default::default()
        })
    }
}

async fn get_salt() -> Result<SaltString, MyError> {
    match SaltString::from_b64("aWF0aGlua3NvaWFt"){
        Ok(salt) => Ok(salt),
        Err(e) => {
            Err(MyError::SaltError)
        }
    }
}

async fn get_password_hash(password: &[u8], salt: &SaltString) -> Result<String, MyError> {
    match Pbkdf2.hash_password(password, salt) {
        Ok(hash) => Ok(hash.to_string()),
        Err(e) => {
            Err(MyError::PasswordError)
        }
    }
}

#[derive(Debug)]
pub enum MyError {
    SaltError,
    PasswordError
}

impl From<MyError> for RpcError {
    fn from(e: MyError) -> RpcError {
        RpcError::InvalidParameter(format!("{:?}", e))
    }
}