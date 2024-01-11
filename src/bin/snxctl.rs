use anyhow::anyhow;

use snx_rs::controller::{ServiceCommand, ServiceController};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() != 2 {
        return Err(anyhow!(
            "usage: {} {{status|connect|disconnect|reconnect|info}}",
            args[0]
        ));
    }

    let controller = ServiceController::new()?;
    let command: ServiceCommand = args.get(1).map(AsRef::as_ref).unwrap_or("status").parse()?;
    controller.command(command).await?;
    Ok(())
}
