use reth::primitives::Header;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::FullNodeComponents;
use reth_provider::Chain;
use tokio::sync::mpsc::Sender;

// TODO:
// handle preconf tx receipt
// check preconf tx indeed included

pub struct ChainInfoExEx<Node: FullNodeComponents> {
    ctx: ExExContext<Node>,
    sender: Sender<Header>,
}

impl<Node: FullNodeComponents> ChainInfoExEx<Node> {
    pub fn new(ctx: ExExContext<Node>, sender: Sender<Header>) -> Self {
        Self { ctx, sender }
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        while let Some(notification) = self.ctx.notifications.recv().await {
            if let Some(committed_chain) = notification.committed_chain() {
                self.process_new_chain(&committed_chain).await?;
                self.ctx
                    .events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().number))?;
            }
        }
        Ok(())
    }

    async fn process_new_chain(&self, chain: &Chain) -> eyre::Result<()> {
        let commited_header = chain.tip().block.header.clone().unseal();
        self.sender.send(commited_header).await?;

        Ok(())
    }
}

// #[cfg(test)]
// mod test {
//     use crate::chain_info_exex::ChainInfoExEx;
//     use crate::lookahead_fetcher::LookaheadFetcher;
//     use eyre::Result;
//     use reth_node_ethereum::EthereumNode;
//     use tokio::sync::mpsc;

//     async fn setup() -> Result<()> {
//         let (el_sender, _receiver) = mpsc::channel(100);
//         let (cl_sender, _receiver) = mpsc::channel(100);

//         let _ = reth::cli::Cli::parse_args().run(|builder, _| async move {
//             let handle = builder
//                 .node(EthereumNode::default())
//                 .install_exex("ChainInfoExEx", move |ctx| async {
//                     Ok(ChainInfoExEx::new(ctx, el_sender).run())
//                 })
//                 .launch()
//                 .await?;

//             handle.wait_for_node_exit().await
//         });

//         let fetcher =
//             LookaheadFetcher::new("https://docs-demo.quiknode.pro".to_string(), cl_sender);
//         fetcher.run().await?;
//         Ok(())
//     }
//     #[tokio::test]
//     async fn test_setup() -> Result<()> {
//         setup().await?;
//         Ok(())
//     }
// }
