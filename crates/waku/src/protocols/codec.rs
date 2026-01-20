use futures::prelude::*;
use prost::Message;
use std::io;
use std::marker::PhantomData;

pub struct ProstLengthDelimitedCodec<Req, Resp> {
    _marker: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> Default for ProstLengthDelimitedCodec<Req, Resp> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<Req, Resp> Clone for ProstLengthDelimitedCodec<Req, Resp> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<Req, Resp> ProstLengthDelimitedCodec<Req, Resp>
where
    Req: Message + Default,
    Resp: Message + Default,
{
    async fn read_length_prefixed<T>(io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin,
    {
        let len = unsigned_varint::aio::read_usize(&mut *io)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn write_length_prefixed<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let mut len_buf = unsigned_varint::encode::usize_buffer();
        let len_bytes = unsigned_varint::encode::usize(bytes.len(), &mut len_buf);
        io.write_all(len_bytes).await?;
        io.write_all(bytes).await?;
        io.flush().await?;
        Ok(())
    }

    /// Read a length-delimited protobuf request.
    ///
    /// # Errors
    /// Returns an `io::Error` on EOF, framing errors, or protobuf decode errors.
    pub async fn read_request<T>(io: &mut T) -> io::Result<Req>
    where
        T: AsyncRead + Unpin,
    {
        let buf = Self::read_length_prefixed(io).await?;
        Req::decode(buf.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Read a length-delimited protobuf response.
    ///
    /// # Errors
    /// Returns an `io::Error` on EOF, framing errors, or protobuf decode errors.
    pub async fn read_response<T>(io: &mut T) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin,
    {
        let buf = Self::read_length_prefixed(io).await?;
        Resp::decode(buf.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write a length-delimited protobuf request.
    ///
    /// # Errors
    /// Returns an `io::Error` on write errors.
    pub async fn write_request<T>(io: &mut T, req: Req) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let bytes = req.encode_to_vec();
        Self::write_length_prefixed(io, &bytes).await
    }

    /// Write a length-delimited protobuf response.
    ///
    /// # Errors
    /// Returns an `io::Error` on write errors.
    pub async fn write_response<T>(io: &mut T, resp: Resp) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let bytes = resp.encode_to_vec();
        Self::write_length_prefixed(io, &bytes).await
    }
}
