use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use taiyi_underwriter::api::{run, PreconfApiResult};

#[tokio::main]
async fn main() -> PreconfApiResult<()> {
    println!("hello");
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5656);
    run(addr).await?;
    Ok(())
}
