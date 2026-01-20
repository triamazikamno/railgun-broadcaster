use crate::proto;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use async_trait::async_trait;
use libp2p::request_response;

pub const LIGHTPUSH_V3_CODEC: &str = "/vac/waku/lightpush/3.0.0";

#[derive(Clone, Default)]
pub struct LightPushCodec;

#[derive(Clone)]
pub struct LightPushProtocol;

impl AsRef<str> for LightPushProtocol {
    fn as_ref(&self) -> &str {
        LIGHTPUSH_V3_CODEC
    }
}

#[async_trait]
impl request_response::Codec for LightPushCodec {
    type Protocol = LightPushProtocol;
    type Request = proto::light_push::LightPushRequestV3;
    type Response = proto::light_push::LightPushResponseV3;

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
pub fn behaviour() -> request_response::Behaviour<LightPushCodec> {
    request_response::Behaviour::new(
        [(LightPushProtocol, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}
