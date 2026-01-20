use crate::proto;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use async_trait::async_trait;
use libp2p::request_response;

pub const PEER_EXCHANGE_CODEC: &str = "/vac/waku/peer-exchange/2.0.0-alpha1";

#[derive(Clone, Default)]
pub struct PeerExchangeCodec;

#[derive(Clone)]
pub struct PeerExchangeProtocol;

impl AsRef<str> for PeerExchangeProtocol {
    fn as_ref(&self) -> &str {
        PEER_EXCHANGE_CODEC
    }
}

#[async_trait]
impl request_response::Codec for PeerExchangeCodec {
    type Protocol = PeerExchangeProtocol;
    type Request = proto::peer_exchange::PeerExchangeRpc;
    type Response = proto::peer_exchange::PeerExchangeRpc;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::read_request(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::read_response(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::write_request(io, req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::write_response(io, resp).await
    }
}

#[must_use]
pub fn behaviour() -> request_response::Behaviour<PeerExchangeCodec> {
    request_response::Behaviour::new(
        [(
            PeerExchangeProtocol,
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}
